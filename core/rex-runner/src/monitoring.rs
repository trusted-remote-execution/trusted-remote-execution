use crate::constants::{RexRunnerAlarm, RexRunnerMetric};
use crate::context::RunnerMonitoringContext;
use crate::error_handling::create_error_response_with_monitoring;
use crate::handle_or_exit;
use crate::io::write_to_stdout;
use crate::model::ErrorType;
use anyhow::{Result, anyhow};
use rex_logger::{LoggingOptionBuilder, init_logger};
use rex_logger::{debug, error};
use rex_metrics_and_alarms::alarms::{
    RexAlarm, RexAlarmBuilder, RexAlarmRegistry, RexAlarmRegistryBuilder,
};
use rex_metrics_and_alarms::common::MetricUnitType;
use rex_metrics_and_alarms::metrics::{
    RexMetric, RexMetricRegistry, RexMetricRegistryBuilder, build_rex_metric,
};
use rex_runner_registrar::ProcessMonitor;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

/// Initializes the logging system for the runner.
///
/// # Example
/// ```no_run
/// # use rex_runner::monitoring::init_logging;
/// init_logging();
/// ```
pub fn init_logging() {
    let syslog_enable = std::env::var("SYSLOG_ENABLE").map_or(true, |val| val != "0");

    let logger_config = handle_or_exit!(
        LoggingOptionBuilder::default()
            .console(false)
            .syslog(syslog_enable)
            .script_log(true)
            .build(),
        "Failed to build logging configuration",
        ErrorType::InternalException,
        None
    );

    let logger = init_logger(&logger_config);

    handle_or_exit!(
        logger,
        "Failed to initialize logger",
        ErrorType::InternalException,
        None
    );
}

/// Initializes and returns Rex alarm and metric registries for monitoring.
///
/// # Example
/// ```no_run
/// # use rex_runner::monitoring::initialize_rex_alarm_and_metric_registries;
/// let (alarm_registry, metric_registry) = initialize_rex_alarm_and_metric_registries().unwrap();
/// ```
pub fn initialize_rex_alarm_and_metric_registries() -> Result<(RexAlarmRegistry, RexMetricRegistry)>
{
    let rex_alarm_registry = RexAlarmRegistryBuilder::default()
        .build()
        .map_err(|e| anyhow!("Failed to initialize alarm registry: {e}"))?;

    let rex_metric_registry = RexMetricRegistryBuilder::default()
        .build()
        .map_err(|e| anyhow!("Failed to initialize metric registry: {e}"))?;

    Ok((rex_alarm_registry, rex_metric_registry))
}

/// Creates and registers a new alarm with the specified type and optional details.
#[allow(clippy::unwrap_used)]
pub fn build_alarm(alarm_type: String, alarm_details: Option<String>) -> RexAlarm {
    RexAlarmBuilder::default()
        .alarm_type(alarm_type)
        .alarm_details(alarm_details)
        .build()
        .unwrap()
}

pub(crate) fn add_script_metrics_to_rex_metric_registry(
    script_metrics: Option<&Vec<RexMetric>>,
    runner_monitoring_context: &mut RunnerMonitoringContext,
) -> Result<(), String> {
    if let Some(metrics) = script_metrics {
        if let Some(invalid_script_metric) = metrics
            .iter()
            .find(|m| m.metric_name.to_lowercase().starts_with("rex"))
        {
            let error_msg = format!(
                "Invalid metric name '{}': Script metrics cannot start with Rex",
                invalid_script_metric.metric_name
            );
            runner_monitoring_context
                .rex_alarm_registry
                .add_alarm(build_alarm(
                    RexRunnerAlarm::RexRunnerScriptExecutionFailure.to_string(),
                    Some(error_msg.clone()),
                ));
            return Err(error_msg);
        }
        for metric in metrics {
            runner_monitoring_context
                .rex_metric_registry
                .add_metric(metric.clone());
        }
    }
    Ok(())
}

pub(crate) fn add_script_alarms_to_rex_alarm_registry(
    script_alarms: Option<&Vec<RexAlarm>>,
    rex_alarm_registry: &mut RexAlarmRegistry,
) -> Result<(), String> {
    if let Some(alarms) = script_alarms {
        if let Some(invalid_script_alarm) = alarms
            .iter()
            .find(|a| a.alarm_type.to_lowercase().starts_with("rex"))
        {
            let error_msg = format!(
                "Invalid alarm type '{}': Script alarms cannot start with Rex",
                invalid_script_alarm.alarm_type
            );
            rex_alarm_registry.add_alarm(build_alarm(
                RexRunnerAlarm::RexRunnerScriptExecutionFailure.to_string(),
                Some(error_msg.clone()),
            ));
            return Err(error_msg);
        }
        for alarm in alarms {
            rex_alarm_registry.add_alarm(alarm.clone());
        }
    }
    Ok(())
}

#[allow(clippy::cognitive_complexity)]
pub(crate) fn add_process_monitoring_metrics_to_registry(
    process_monitor: &Rc<RefCell<ProcessMonitor>>,
    rex_metric_registry: &RexMetricRegistry,
) {
    let mut dimensions = HashMap::new();
    dimensions.insert("MetricInfo".to_string(), "ProcessMonitoring".to_string());

    if let Ok(mut process_monitor_ref) = process_monitor.try_borrow_mut() {
        if let Some(cpu_usage) = process_monitor_ref.get_cpu_usage() {
            rex_metric_registry.add_metric(build_rex_metric(
                RexRunnerMetric::RexRunnerProcessCpuUsage.to_string(),
                f64::from(cpu_usage),
                MetricUnitType::PERCENT,
                dimensions.clone(),
            ));
            debug!(
                "Added process monitoring metrics - CPU usage: {:.2}%",
                cpu_usage
            );
        }

        if let Some(rss_memory_average_mb) = process_monitor_ref.get_rss_memory_average_mb() {
            rex_metric_registry.add_metric(build_rex_metric(
                RexRunnerMetric::RexRunnerProcessRssMemoryUsageAverage.to_string(),
                rss_memory_average_mb,
                MetricUnitType::MEGABYTES,
                dimensions.clone(),
            ));
            debug!(
                "Added process monitoring metrics - RSS Memory avg: {:.2}MB",
                rss_memory_average_mb
            );
        }

        if let Some(virtual_memory_average_mb) = process_monitor_ref.get_virtual_memory_average_mb()
        {
            rex_metric_registry.add_metric(build_rex_metric(
                RexRunnerMetric::RexRunnerProcessVirtualMemoryUsageAverage.to_string(),
                virtual_memory_average_mb,
                MetricUnitType::MEGABYTES,
                dimensions.clone(),
            ));
            debug!(
                "Added process monitoring metrics - Virtual Memory avg: {:.2}MB",
                virtual_memory_average_mb
            );
        }
    } else {
        error!("Failed to borrow process monitor for metrics");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{RunnerExecutionContext, RunnerMonitoringContext};
    use crate::execution::run_script_content;
    use crate::model::ScriptArgumentValue;
    use std::collections::HashMap;
    use std::time::Instant;

    fn create_test_execution_context(
        script_content: &str,
        policy_content: Option<&str>,
        script_arguments: Option<HashMap<String, ScriptArgumentValue>>,
    ) -> RunnerExecutionContext {
        let monitoring_context = RunnerMonitoringContext::new(
            Instant::now(),
            RexAlarmRegistryBuilder::default().build().unwrap(),
            RexMetricRegistryBuilder::default().build().unwrap(),
        );

        RunnerExecutionContext::new(
            script_content.to_string(),
            policy_content
                .unwrap_or("permit(principal, action, resource);")
                .to_string(),
            script_arguments,
            monitoring_context,
        )
    }

    /// Given: A script that emits metrics with REX prefix
    /// When: The script is executed and script metrics are processed
    /// Then: It should fail with appropriate error and alarm
    #[test]
    fn test_script_rex_prefix_metric_validation() {
        let script_content = r#"
        MetricBuilder()
            .name("RexTestMetric")
            .value(42.0)
            .unit(MetricUnitType::COUNT)
            .publish();
        "#;

        let mut execution_context = create_test_execution_context(script_content, None, None);
        let result = run_script_content(&mut execution_context);

        assert!(result.is_ok());
        let metrics_result = add_script_metrics_to_rex_metric_registry(
            execution_context.rhai_context.get_metrics().as_ref(),
            execution_context.monitoring_mut(),
        );

        assert!(metrics_result.is_err());
        assert!(
            metrics_result
                .unwrap_err()
                .contains("cannot start with Rex")
        );

        let rex_alarms = execution_context
            .monitoring()
            .rex_alarm_registry
            .get_alarms();
        assert!(rex_alarms.is_some());
        let rex_alarms = rex_alarms.unwrap();
        assert_eq!(rex_alarms.len(), 1);
        assert_eq!(
            rex_alarms[0].alarm_type,
            RexRunnerAlarm::RexRunnerScriptExecutionFailure.to_string()
        );
    }

    /// Given: A script that emits alarms with REX prefix
    /// When: The script is executed and script alarms are processed
    /// Then: It should fail with appropriate error and alarm
    #[test]
    fn test_script_rex_prefix_alarm_validation() {
        let script_content = r#"
        let rex_alarm = AlarmBuilder()
            .type("RexAlarm")
            .details("Test alarm details")
            .publish();
        "#;

        let mut execution_context = create_test_execution_context(script_content, None, None);
        let result = run_script_content(&mut execution_context);

        assert!(result.is_ok());
        let alarms_result = add_script_alarms_to_rex_alarm_registry(
            execution_context.rhai_context.get_alarms().as_ref(),
            &mut execution_context.monitoring_mut().rex_alarm_registry,
        );

        assert!(alarms_result.is_err());
        assert!(alarms_result.unwrap_err().contains("cannot start with Rex"));

        let rex_alarms = execution_context
            .monitoring()
            .rex_alarm_registry
            .get_alarms()
            .unwrap();
        assert_eq!(rex_alarms.len(), 1);
        assert_eq!(
            rex_alarms[0].alarm_type,
            RexRunnerAlarm::RexRunnerScriptExecutionFailure.to_string()
        );
    }

    /// Given: A ProcessMonitor with test data
    /// When: add_process_monitoring_metrics_to_registry is called
    /// Then: It should add CPU and memory metrics to the registry
    #[test]
    fn test_add_process_monitoring_metrics_to_registry() {
        let rex_metric_registry = RexMetricRegistryBuilder::default().build().unwrap();

        let monitor =
            ProcessMonitor::new(std::process::id(), 0, true).expect("Failed to create monitor");
        let monitor_rc = Rc::new(RefCell::new(monitor));

        {
            let callback = ProcessMonitor::create_progress_callback(monitor_rc.clone(), None);
            for i in 1..=3 {
                callback(i);
            }
        }

        add_process_monitoring_metrics_to_registry(&monitor_rc, &rex_metric_registry);

        let metrics = rex_metric_registry
            .get_metrics()
            .expect("Metrics should be present");
        assert_eq!(
            metrics.len(),
            3,
            "Expected 3 metrics: CPU, RSS memory, and virtual memory"
        );

        assert!(
            metrics
                .iter()
                .any(|m| m.metric_name == RexRunnerMetric::RexRunnerProcessCpuUsage.to_string())
        );
        assert!(
            metrics.iter().any(|m| m.metric_name
                == RexRunnerMetric::RexRunnerProcessRssMemoryUsageAverage.to_string())
        );
        assert!(metrics.iter().any(|m| m.metric_name
            == RexRunnerMetric::RexRunnerProcessVirtualMemoryUsageAverage.to_string()));

        for metric in metrics {
            assert_eq!(
                metric.metric_dimension.get("MetricInfo").unwrap(),
                "ProcessMonitoring"
            );
        }
    }
}
