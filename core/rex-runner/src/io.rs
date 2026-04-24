use crate::constants::{RexRunnerAlarm, RexRunnerMetric};
use crate::context::RunnerMonitoringContext;
use crate::model::{
    ErrorType, ExecutionError, ExecutionStatus, LogEntry as RunnerLogEntry, RexAlarm, RexMetric,
    RunnerExecutionOutput,
};
use crate::monitoring::build_alarm;
use crate::utils::elapsed_duration;
use anyhow::Result;
use rex_logger::{LogEntry, error, get_script_handle};
use rex_metrics_and_alarms::alarms::RexAlarmRegistry;
use rex_metrics_and_alarms::metrics::{
    RexMetricRegistry, build_rex_duration_metric, build_rex_failure_count_metric,
    build_rex_success_count_metric,
};
use rex_runner_registrar::error_utils::format_error_message;
use rhai::{Dynamic, EvalAltResult};
use serde_json::to_vec;
use std::collections::HashMap;
use std::io::{self, Write};
use std::process::exit;

/// Serializes and writes the execution output to stdout.
///
/// Exits the process with status code 1 if serialization or writing fails.
pub fn write_to_stdout(output: &RunnerExecutionOutput) {
    let output_bytes = match to_vec(output) {
        Ok(bytes) => bytes,

        Err(e) => {
            error!("Failed to serialize output: {e}");
            exit(1);
        }
    };

    if let Err(e) = io::stdout().write_all(&output_bytes) {
        error!("Failed to write output to stdout: {e}");
        exit(1);
    }

    if let Err(e) = io::stdout().flush() {
        error!("Failed to flush stdout: {e}");
        exit(1);
    }
}

/// Adds a truncation warning to the log iterator when the buffer was exceeded.
fn with_truncation_warning(
    logs: Vec<LogEntry>,
    was_truncated: bool,
) -> impl Iterator<Item = LogEntry> {
    let warning = if was_truncated {
        logs.first().map(|first_log| LogEntry {
            timestamp: first_log.timestamp,
            line_number: 0,
            level: "WARN".to_string(),
            message: "Warning: Log buffer capacity exceeded. Some earlier log entries were removed to fit new logs.".to_string(),
            rhai_api_name: None,
        })
    } else {
        None
    };

    warning.into_iter().chain(logs)
}

/// Converts script log entries into local [`RunnerLogEntry`] values.
fn convert_to_local_logs(logs: impl Iterator<Item = LogEntry>) -> Vec<RunnerLogEntry> {
    logs.map(|entry| {
        let mut attrs = HashMap::new();
        attrs.insert("timestamp".to_string(), entry.timestamp.to_string());
        attrs.insert("level".to_string(), entry.level.clone());
        attrs.insert("message".to_string(), entry.message.clone());
        attrs.insert("line_number".to_string(), entry.line_number.to_string());
        if let Some(api_name) = &entry.rhai_api_name {
            attrs.insert("rhai_api_name".to_string(), api_name.clone());
        }
        RunnerLogEntry {
            attributes: Some(attrs),
        }
    })
    .collect()
}

/// Collects alarms from the registry into a vec for the output payload.
pub(crate) fn get_local_alarms(registry: &RexAlarmRegistry) -> Option<Vec<RexAlarm>> {
    registry.get_alarms().map(|alarms| alarms.to_vec())
}

/// Collects metrics from the registry into a vec for the output payload.
pub(crate) fn get_local_metrics(registry: &RexMetricRegistry) -> Option<Vec<RexMetric>> {
    registry.get_metrics()
}

/// Converts the Rhai script execution result into a [`RunnerExecutionOutput`].
pub(crate) fn structure_engine_output(
    result: &Result<Dynamic, Box<EvalAltResult>>,
    runner_monitoring_context: &mut RunnerMonitoringContext,
) -> RunnerExecutionOutput {
    let (output_str, status, error_opt) = result.as_ref().map_or_else(
        |err| {
            let error_str = format_error_message(err);
            let (error_type, alarm_type, metric_name) =
                if error_str.to_lowercase().contains("permission denied") {
                    (
                        ErrorType::AccessDeniedException,
                        RexRunnerAlarm::RexRunnerPrivilegeEscalation,
                        RexRunnerMetric::RexRunnerPrivilegeEscalationCount,
                    )
                } else {
                    (
                        ErrorType::ScriptException,
                        RexRunnerAlarm::RexRunnerScriptExecutionFailure,
                        RexRunnerMetric::RexRunnerScriptExecutionFailureCount,
                    )
                };

            runner_monitoring_context
                .rex_alarm_registry
                .add_alarm(build_alarm(
                    alarm_type.to_string(),
                    Some(format!("Failed to execute script: {error_str}")),
                ));
            runner_monitoring_context
                .rex_metric_registry
                .add_metric(build_rex_failure_count_metric(metric_name.to_string()));

            (
                String::new(),
                ExecutionStatus::Error,
                Some(ExecutionError::new(error_type, &error_str)),
            )
        },
        |value| {
            runner_monitoring_context.rex_metric_registry.add_metric(
                build_rex_success_count_metric(
                    RexRunnerMetric::RexRunnerScriptExecutionSuccessCount.to_string(),
                ),
            );
            (value.to_string(), ExecutionStatus::Success, None)
        },
    );

    runner_monitoring_context
        .rex_metric_registry
        .add_metric(build_rex_duration_metric(
            RexRunnerMetric::RexRunnerTotalExecutionTime.to_string(),
            elapsed_duration(&runner_monitoring_context.runner_execution_start_time),
        ));

    let logs = get_script_handle().map(|script_handle| {
        convert_to_local_logs(with_truncation_warning(
            script_handle.get_logs(),
            script_handle.was_max_limit_applied(),
        ))
    });

    RunnerExecutionOutput {
        output: output_str,
        status,
        error: error_opt,
        alarms: get_local_alarms(&runner_monitoring_context.rex_alarm_registry),
        metrics: get_local_metrics(&runner_monitoring_context.rex_metric_registry),
        logs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::RunnerMonitoringContext;
    use assertables::assert_contains;
    use rex_logger::{LoggingOptionBuilder, init_logger};
    use rex_metrics_and_alarms::alarms::RexAlarmRegistryBuilder;
    use rex_metrics_and_alarms::metrics::RexMetricRegistryBuilder;
    use rex_runner_registrar::RhaiEngineBuilder;
    use sealed_test::prelude::{rusty_fork_test, sealed_test};
    use std::time::Instant;

    fn make_monitoring_context() -> RunnerMonitoringContext {
        RunnerMonitoringContext::new(
            Instant::now(),
            RexAlarmRegistryBuilder::default().build().unwrap(),
            RexMetricRegistryBuilder::default().build().unwrap(),
        )
    }

    /// Given: A successful execution result containing a string value
    /// When: The structure_engine_output function processes the result
    /// Then: The output contains the string value with Success status and no error
    #[test]
    fn test_structure_engine_output_with_string_success() {
        let test_string = "Hello World";
        let result: Result<Dynamic, Box<EvalAltResult>> = Ok(Dynamic::from(test_string));
        let mut ctx = make_monitoring_context();
        let output = structure_engine_output(&result, &mut ctx);

        assert_eq!(output.output, test_string);
        assert_eq!(output.status, ExecutionStatus::Success);
        assert!(output.error.is_none());
        assert!(output.alarms.is_none());
        assert!(output.metrics.is_some());
        assert!(
            output.metrics.unwrap().iter().any(|m| m.metric_name
                == RexRunnerMetric::RexRunnerScriptExecutionSuccessCount.to_string()),
        );
    }

    /// Given: A failed execution result with an error
    /// When: The structure_engine_output function processes the error
    /// Then: Error status with alarms and metrics
    #[test]
    fn test_structure_engine_output_with_error_result() {
        let result: Result<Dynamic, Box<EvalAltResult>> =
            Err(Box::<EvalAltResult>::from("Test error message".to_string()));
        let mut rex_alarm_registry = RexAlarmRegistryBuilder::default().build().unwrap();
        rex_alarm_registry.add_alarm(build_alarm(
            "TestAlarm".to_string(),
            Some("Test alarm details".to_string()),
        ));
        let mut ctx = RunnerMonitoringContext::new(
            Instant::now(),
            rex_alarm_registry,
            RexMetricRegistryBuilder::default().build().unwrap(),
        );
        let output = structure_engine_output(&result, &mut ctx);

        assert_eq!(output.output, "");
        assert_eq!(output.status, ExecutionStatus::Error);
        assert!(output.error.is_some());
        assert_eq!(output.error.unwrap().error_type, ErrorType::ScriptException);

        let alarms = output.alarms.unwrap();
        assert_eq!(alarms.len(), 2);
        assert!(
            output.metrics.unwrap().iter().any(|m| m.metric_name
                == RexRunnerMetric::RexRunnerScriptExecutionFailureCount.to_string())
        );
    }

    /// Given: A successful execution result containing an empty string
    /// When: The structure_engine_output function processes the result
    /// Then: Empty output with Success status
    #[test]
    fn test_structure_engine_output_with_empty_string_success() {
        let result: Result<Dynamic, Box<EvalAltResult>> = Ok(Dynamic::from(""));
        let mut ctx = make_monitoring_context();
        let output = structure_engine_output(&result, &mut ctx);

        assert_eq!(output.output, "");
        assert_eq!(output.status, ExecutionStatus::Success);
        assert!(output.error.is_none());
        assert!(output.alarms.is_none());
    }

    /// Given: A "permission denied" error
    /// When: The structure_engine_output function processes this error
    /// Then: AccessDeniedException with privilege escalation alarm and metric
    #[test]
    fn test_structure_engine_output_with_permission_denied_error() {
        let result: Result<Dynamic, Box<EvalAltResult>> = Err(Box::<EvalAltResult>::from(
            "Operation failed: permission denied for resource".to_string(),
        ));
        let mut ctx = make_monitoring_context();
        let output = structure_engine_output(&result, &mut ctx);

        assert_eq!(output.status, ExecutionStatus::Error);
        let error = output.error.unwrap();
        assert_eq!(error.error_type, ErrorType::AccessDeniedException);
        assert_contains!(error.message, "permission denied");

        let alarms = output.alarms.unwrap();
        assert_eq!(alarms.len(), 1);
        assert_eq!(
            alarms[0].alarm_type,
            RexRunnerAlarm::RexRunnerPrivilegeEscalation.to_string()
        );
        assert!(output.metrics.unwrap().iter().any(
            |m| m.metric_name == RexRunnerMetric::RexRunnerPrivilegeEscalationCount.to_string()
        ));
    }

    /// Given: A successful execution result and script logging enabled
    /// When: The structure_engine_output function processes both the result and script logs
    /// Then: Logs are captured with expected attributes
    #[sealed_test]
    fn test_structure_engine_output_with_logs() {
        init_logger(
            &LoggingOptionBuilder::default()
                .console(false)
                .syslog(false)
                .script_log(true)
                .build()
                .unwrap(),
        )
        .unwrap();

        let result: Result<Dynamic, Box<EvalAltResult>> = Ok(Dynamic::from("Hello World"));
        RhaiEngineBuilder::with_policy_content(String::new())
            .create()
            .unwrap()
            .engine()
            .eval::<()>(r#"info("Log message 1"); info("Log message 2");"#)
            .expect("Script execution failed");

        let mut ctx = make_monitoring_context();
        let output = structure_engine_output(&result, &mut ctx);

        assert_eq!(output.status, ExecutionStatus::Success);
        let logs = output.logs.unwrap();
        assert_eq!(logs.len(), 2);
        assert_eq!(
            logs[0].attributes.as_ref().unwrap().get("message").unwrap(),
            "Log message 1"
        );
        assert!(
            logs[0]
                .attributes
                .as_ref()
                .unwrap()
                .contains_key("timestamp")
        );
        assert_eq!(
            logs[1].attributes.as_ref().unwrap().get("message").unwrap(),
            "Log message 2"
        );
    }
}
