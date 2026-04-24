use crate::error_handling::create_error_response_with_monitoring;
use crate::handle_or_exit;
use crate::io::write_to_stdout;
use crate::model::{ErrorType, ScriptArgumentValue};
use rex_metrics_and_alarms::alarms::RexAlarmRegistry;
use rex_metrics_and_alarms::metrics::RexMetricRegistry;
use rex_runner_registrar::RhaiContext;
use rex_runner_registrar::RhaiEngineBuilder;
use std::collections::HashMap;
use std::time::Instant;

/// Context for monitoring runner execution with alarms and metrics.
#[derive(Debug)]
pub struct RunnerMonitoringContext {
    pub runner_execution_start_time: Instant,
    pub rex_alarm_registry: RexAlarmRegistry,
    pub rex_metric_registry: RexMetricRegistry,
}

/// Context for runner script execution containing all necessary execution state.
#[derive(Debug)]
pub struct RunnerExecutionContext {
    pub script_content: String,
    pub policy_content: String,
    pub script_arguments: Option<HashMap<String, ScriptArgumentValue>>,
    pub rhai_context: RhaiContext,
    pub monitoring_context: RunnerMonitoringContext,
}

impl RunnerMonitoringContext {
    pub const fn new(
        runner_execution_start_time: Instant,
        rex_alarm_registry: RexAlarmRegistry,
        rex_metric_registry: RexMetricRegistry,
    ) -> Self {
        Self {
            runner_execution_start_time,
            rex_alarm_registry,
            rex_metric_registry,
        }
    }
}

impl RunnerExecutionContext {
    pub fn new(
        script_content: String,
        policy_content: String,
        script_arguments: Option<HashMap<String, ScriptArgumentValue>>,
        monitoring_context: RunnerMonitoringContext,
    ) -> Self {
        let builder = RhaiEngineBuilder::with_policy_content(policy_content.clone())
            .with_strict_variables(true)
            .with_enable_permissive_mode(false);

        let rhai_context = handle_or_exit!(
            builder.create(),
            "Failed to create Rhai engine",
            ErrorType::InternalException,
            Some(&monitoring_context)
        );

        Self {
            script_content,
            policy_content,
            script_arguments,
            rhai_context,
            monitoring_context,
        }
    }

    /// Gets an immutable reference to the monitoring context.
    pub const fn monitoring(&self) -> &RunnerMonitoringContext {
        &self.monitoring_context
    }

    /// Gets a mutable reference to the monitoring context.
    pub const fn monitoring_mut(&mut self) -> &mut RunnerMonitoringContext {
        &mut self.monitoring_context
    }
}
