use crate::constants::RexRunnerMetric;
use crate::context::RunnerMonitoringContext;
use crate::io::{get_local_alarms, get_local_metrics};
use crate::model::{ErrorType, ExecutionError, ExecutionStatus, RunnerExecutionOutput};
use crate::utils::elapsed_duration;
use rex_logger::{debug, error};
use rex_metrics_and_alarms::alarms::RexAlarmRegistry;
use rex_metrics_and_alarms::metrics::{RexMetricRegistry, build_rex_duration_metric};
use std::time::Instant;

const MAX_MESSAGE_LENGTH: usize = 1024;

/// Macro to handle Result values or create direct error responses, writing to stdout and exiting the process.
#[macro_export]
macro_rules! handle_or_exit {
    ($result:expr, $context:expr, $error_type:expr, $runner_monitoring_context:expr) => {{
        match $result {
            Ok(value) => value,
            Err(e) => {
                let error_msg = format!("{}: {:#}", $context, e);
                let error = create_error_response_with_monitoring(
                    &error_msg,
                    $error_type,
                    $runner_monitoring_context,
                );
                write_to_stdout(&error);
                std::process::exit(1);
            }
        }
    }};

    ($message:expr, $error_type:expr, $runner_monitoring_context:expr) => {{
        let error = create_error_response_with_monitoring(
            $message,
            $error_type,
            $runner_monitoring_context,
        );
        write_to_stdout(&error);
        std::process::exit(1);
    }};

    ($result:expr, $context:expr, $error_type:expr, $rex_alarm_registry:expr, $alarm_type:expr, $rex_metric_registry:expr, $rex_metric:expr, $runner_execution_start_time:expr) => {{
        match $result {
            Ok(value) => value,
            Err(e) => {
                let error_msg = format!("{}: {:#}", $context, e);
                $rex_alarm_registry.add_alarm(build_alarm(
                    $alarm_type.to_string(),
                    Some(error_msg.clone()),
                ));
                $rex_metric_registry.add_metric($rex_metric);
                let error = create_error_response(
                    &error_msg,
                    $error_type,
                    Some($rex_alarm_registry),
                    Some($rex_metric_registry),
                    $runner_execution_start_time,
                );
                write_to_stdout(&error);
                std::process::exit(1);
            }
        }
    }};
}

/// Creates a standardized error response with monitoring context integration.
pub fn create_error_response_with_monitoring(
    message: &str,
    error_type: ErrorType,
    runner_monitoring_context: Option<&RunnerMonitoringContext>,
) -> RunnerExecutionOutput {
    if let Some(context) = runner_monitoring_context {
        let runner_execution_duration = elapsed_duration(&context.runner_execution_start_time);
        context
            .rex_metric_registry
            .add_metric(build_rex_duration_metric(
                RexRunnerMetric::RexRunnerTotalExecutionTime.to_string(),
                runner_execution_duration,
            ));
    }

    let alarms =
        runner_monitoring_context.and_then(|ctx| get_local_alarms(&ctx.rex_alarm_registry));
    let metrics =
        runner_monitoring_context.and_then(|ctx| get_local_metrics(&ctx.rex_metric_registry));

    RunnerExecutionOutput {
        output: String::new(),
        status: ExecutionStatus::Error,
        error: Some(create_execution_error(message, error_type)),
        alarms,
        metrics,
        logs: None,
    }
}

/// Creates a standardized error response with optional alarm and metric registries.
pub fn create_error_response(
    message: &str,
    error_type: ErrorType,
    rex_alarm_registry: Option<&RexAlarmRegistry>,
    rex_metric_registry: Option<&RexMetricRegistry>,
    runner_execution_start_time: Option<&Instant>,
) -> RunnerExecutionOutput {
    if let (Some(registry), Some(time)) = (rex_metric_registry, runner_execution_start_time) {
        registry.add_metric(build_rex_duration_metric(
            RexRunnerMetric::RexRunnerTotalExecutionTime.to_string(),
            elapsed_duration(time),
        ));
    }

    let alarms = rex_alarm_registry.and_then(get_local_alarms);
    let metrics = rex_metric_registry.and_then(get_local_metrics);

    RunnerExecutionOutput {
        output: String::new(),
        status: ExecutionStatus::Error,
        error: Some(create_execution_error(message, error_type)),
        alarms,
        metrics,
        logs: None,
    }
}

pub(crate) fn create_execution_error(message: &str, error_type: ErrorType) -> ExecutionError {
    let msg = if message.len() > MAX_MESSAGE_LENGTH {
        let mut truncated = message
            .chars()
            .take(MAX_MESSAGE_LENGTH - 3)
            .collect::<String>();
        truncated.push_str("...");
        debug!(
            "Message truncated from {} to {} characters",
            message.len(),
            truncated.len()
        );
        truncated
    } else if message.is_empty() {
        error!("Error message is empty, using fallback");
        "Error message could not be included into the result".to_string()
    } else {
        message.to_string()
    };

    ExecutionError {
        error_type,
        message: msg,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rex_metrics_and_alarms::alarms::RexAlarmRegistryBuilder;
    use rex_metrics_and_alarms::metrics::RexMetricRegistryBuilder;
    use rstest::rstest;

    /// Given: Messages of various lengths
    /// When: create_execution_error is called
    /// Then: Short messages unchanged, long messages truncated to 1024 chars
    #[rstest]
    #[case("This is a short message", false, "Short message should be unchanged")]
    #[case(&"x".repeat(1024), false, "Message at exact limit should be unchanged")]
    #[case(&"x".repeat(1500), true, "Long message should be truncated")]
    #[case(&"x".repeat(1025), true, "Message just over limit should be truncated")]
    fn test_create_execution_error_various_lengths(
        #[case] input_message: &str,
        #[case] should_truncate: bool,
        #[case] description: &str,
    ) {
        let error = create_execution_error(input_message, ErrorType::InternalException);

        match should_truncate {
            true => {
                assert_eq!(
                    error.message.len(),
                    1024,
                    "{} should be exactly 1024 characters",
                    description
                );
                assert!(
                    error.message.ends_with("..."),
                    "{} should end with '...'",
                    description
                );
            }
            false => {
                assert_eq!(
                    error.message, input_message,
                    "{} should be unchanged",
                    description
                );
            }
        }
    }

    /// Given: create_error_response with ValidationException
    /// When: Called with a message
    /// Then: RunnerExecutionOutput with Error status and ValidationException
    #[test]
    fn test_create_error_response_validation_exception() {
        let error_message = "Failed to serialize output: test error";
        let result = create_error_response(
            error_message,
            ErrorType::ValidationException,
            None,
            None,
            None,
        );

        assert_eq!(result.status, ExecutionStatus::Error);
        assert_eq!(result.output, "");
        let error = result.error.unwrap();
        assert_eq!(error.error_type, ErrorType::ValidationException);
        assert_eq!(error.message, error_message);
    }

    /// Given: create_error_response with InternalException
    /// When: Called with a message
    /// Then: RunnerExecutionOutput with Error status and InternalException
    #[test]
    fn test_create_error_response_internal_exception() {
        let error_message = "Failed to write output to stdout: test error";
        let result = create_error_response(
            error_message,
            ErrorType::InternalException,
            None,
            None,
            None,
        );

        assert_eq!(result.status, ExecutionStatus::Error);
        let error = result.error.unwrap();
        assert_eq!(error.error_type, ErrorType::InternalException);
        assert_eq!(error.message, error_message);
    }

    /// Given: create_error_response_with_monitoring with monitoring context
    /// When: Called with a message and error type
    /// Then: RunnerExecutionOutput with duration metric added
    #[test]
    fn test_create_error_response_with_context() {
        use std::time::Instant;
        let alarm_registry = RexAlarmRegistryBuilder::default().build().unwrap();
        let metric_registry = RexMetricRegistryBuilder::default().build().unwrap();
        let monitoring_context =
            RunnerMonitoringContext::new(Instant::now(), alarm_registry, metric_registry);

        let result = create_error_response_with_monitoring(
            "Test error with monitoring context",
            ErrorType::InternalException,
            Some(&monitoring_context),
        );

        assert_eq!(result.status, ExecutionStatus::Error);
        let error = result.error.unwrap();
        assert_eq!(error.error_type, ErrorType::InternalException);

        // Verify duration metric was added
        let metrics = monitoring_context.rex_metric_registry.get_metrics();
        assert!(metrics.is_some() && !metrics.unwrap().is_empty());
    }
}
