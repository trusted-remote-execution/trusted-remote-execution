use crate::monitoring::{ProcessMonitor, ProcessMonitorHandle, register_process_monitor};
use crate::script_alarm_collector::ScriptAlarmCollector;
use crate::script_metric_collector::ScriptMetricCollector;
use anyhow::Result;
use derive_builder::Builder;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_logger::{RUNNER_TARGET_FOR_SCRIPT_LOGS, push_rhai_context_with_guard};
use rex_logger::{debug, error, info, trace, warn};
use rex_metrics_and_alarms::{alarms::RexAlarm, metrics::RexMetric};
use rex_policy_schema::{get_rex_entities, get_rex_policy_schema};
use rex_runner_registrar_utils::execution_context::ExecutionContext;
use rex_sdk_registry::register_sdk_functions;
use rhai::{Dynamic, Engine, NativeCallContext, Position};
use std::rc::Rc;

// Macro to register script logs
macro_rules! register_log_fn {
    ($engine:expr, $level:ident) => {
        $engine.register_fn(
            stringify!($level),
            move |context: NativeCallContext, message: &str| -> Dynamic {
                let _guard = Self::get_rhai_context_guard(&context);

                $level!(
                    target: RUNNER_TARGET_FOR_SCRIPT_LOGS,
                    "{}", message
                );
                Dynamic::UNIT
            },
        )
    };
}

/// A wrapper around the Rhai engine and its associated components
#[derive(Debug)]
pub struct RhaiContext {
    engine: Engine,
    cedar_auth: Rc<CedarAuth>,
    alarm_collector: ScriptAlarmCollector,
    metric_collector: ScriptMetricCollector,
    process_monitor: ProcessMonitorHandle,
}

impl RhaiContext {
    pub const fn engine(&self) -> &Engine {
        &self.engine
    }

    pub fn into_engine(self) -> Engine {
        self.engine
    }

    pub fn cedar_auth(&self) -> &Rc<CedarAuth> {
        &self.cedar_auth
    }

    pub fn get_process_monitor(&self) -> ProcessMonitorHandle {
        Rc::clone(&self.process_monitor)
    }

    pub fn get_alarms(&self) -> Option<Vec<RexAlarm>> {
        self.alarm_collector.get_alarms()
    }

    pub fn get_metrics(&self) -> Option<Vec<RexMetric>> {
        self.metric_collector.get_metrics()
    }
}

/// Builder for creating a Rhai engine with Cedar authorization and function registration
#[derive(Builder, Debug)]
#[builder(derive(Debug))]
pub struct RhaiEngineBuilder {
    /// Cedar policy used for authorization
    policy: String,
    /// Whether to enable strict variables (defaults to true unless script arguments are used)
    #[builder(default = "true")]
    strict_variables: bool,
    /// Whether to enable permissive mode for Cedar authorization (defaults to false)
    #[builder(default = "false")]
    enable_permissive_mode: bool,
}

impl RhaiEngineBuilder {
    /// Sets the policy directly from a string content read from stdin.
    ///
    /// # Arguments
    /// * `content` - Cedar policy content as a string
    ///
    /// # Returns
    /// * `Self` - The [`RhaiEngineBuilder`] with provided policy
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rex_runner_registrar::rhai_engine_builder::RhaiEngineBuilder;
    /// let policy = r#"
    ///     permit(
    ///         principal == User::"nobody",
    ///         action == file_system::Action::"read",
    ///         resource == file_system::File::"file.txt"
    ///     );
    /// "#.to_string();
    /// let engine = RhaiEngineBuilder::with_policy_content(policy).create();
    /// ```
    pub fn with_policy_content(content: String) -> Self {
        Self {
            policy: content,
            strict_variables: true,
            enable_permissive_mode: false,
        }
    }

    /// Sets whether to enable strict variables checking.
    ///
    /// When strict variables is enabled, all variables must be declared before use.
    /// This should be disabled when using script arguments that are injected at runtime.
    ///
    /// # Arguments
    /// * `strict` - Whether to enable strict variables checking
    ///
    /// # Returns
    /// * `Self` - The [`RhaiEngineBuilder`] with the strict variables setting
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rex_runner_registrar::rhai_engine_builder::RhaiEngineBuilder;
    /// let policy = r#"permit(principal, action, resource);"#.to_string();
    /// // Disable strict variables when using script arguments
    /// let engine = RhaiEngineBuilder::with_policy_content(policy)
    ///     .with_strict_variables(false)
    ///     .create();
    /// ```
    #[must_use]
    pub fn with_strict_variables(mut self, strict: bool) -> Self {
        self.strict_variables = strict;
        self
    }

    #[must_use]
    pub fn with_enable_permissive_mode(mut self, enabled: bool) -> Self {
        self.enable_permissive_mode = enabled;
        self
    }

    /// Creates the Rhai engine, sets up Cedar authorization, process monitoring, and registers functions for use in scripts.
    ///
    /// REX uses `set_strict_variables` to ensure that unused imports / undeclared variables are caught during compilation time.
    /// This can be disabled by calling `with_strict_variables(false)` when script arguments need to be injected at runtime.
    ///
    /// Process monitoring is automatically enabled with a sampling interval of 20 operations unless disabled
    /// via the `REX_RUNNER_DISABLE_MONITORING` environment variable.
    ///
    /// # Returns
    /// * `Result<RhaiContext, String>` - The configured `RhaiContext` on success, or error message on failure
    ///
    /// # Errors
    /// Returns an error if `ProcessMonitor` initialization fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rex_runner_registrar::rhai_engine_builder::RhaiEngineBuilder;
    /// let policy = r#"
    ///     permit(
    ///         principal == User::"nobody",
    ///         action == file_system::Action::"read",
    ///         resource == file_system::File::"file.txt"
    ///     );
    /// "#.to_string();
    /// let context = RhaiEngineBuilder::with_policy_content(policy).create().unwrap();
    /// assert_eq!(std::any::type_name_of_val(&context), "runner_registrar::rhai_engine_builder::RhaiContext");
    /// ```
    #[allow(clippy::expect_used)]
    pub fn create(self) -> Result<RhaiContext> {
        let mut engine = Engine::new();
        engine.set_strict_variables(self.strict_variables);

        let cedar_auth = self.build_cedar_auth()?;

        let alarm_collector = ScriptAlarmCollector::new();
        let metric_collector = ScriptMetricCollector::new();
        self.finalize_engine(
            engine,
            Rc::new(cedar_auth),
            alarm_collector,
            metric_collector,
        )
    }

    fn finalize_engine(
        self,
        mut engine: Engine,
        cedar_auth: Rc<CedarAuth>,
        alarm_collector: ScriptAlarmCollector,
        metric_collector: ScriptMetricCollector,
    ) -> Result<RhaiContext> {
        let execution_context = ExecutionContext::default();
        register_sdk_functions(&mut engine, &cedar_auth, Some(&execution_context));

        self.register_logging(&mut engine);
        engine.disable_symbol("eval");

        alarm_collector.register_script_alarm_functions(&mut engine);
        metric_collector.register_script_metric_functions(&mut engine);

        let process_monitor = register_process_monitor(&mut engine)?;
        let callback = ProcessMonitor::create_progress_callback(
            Rc::clone(&process_monitor),
            Some(Rc::new(execution_context)),
        );
        engine.on_progress(callback);

        Ok(RhaiContext {
            engine,
            cedar_auth,
            alarm_collector,
            metric_collector,
            process_monitor,
        })
    }

    /// Builds a new [`CedarAuth`] instance with the Rex policy configurations.
    ///
    /// # Returns
    /// A Result containing configured `CedarAuth` instance on success, or error on failure
    ///
    /// # Errors
    /// Returns an error if Cedar policy initialization fails
    #[allow(clippy::expect_used)]
    fn build_cedar_auth(&self) -> Result<CedarAuth> {
        let rex_schema = get_rex_policy_schema();
        let rex_entities = get_rex_entities();
        let (cedar_auth, _) = CedarAuth::new(&self.policy, rex_schema, rex_entities)?;
        Ok(cedar_auth.with_permissive_mode(self.enable_permissive_mode))
    }

    fn get_rhai_context_guard(context: &NativeCallContext) -> impl Drop {
        let line_number = context
            .call_position()
            .line()
            .map_or(0, |l| u32::try_from(l).unwrap_or(0));

        push_rhai_context_with_guard(None, line_number)
    }

    /// Registers logging functions with the Rhai engine for use in scripts and disables default print/debug output.
    /// This implementation assumes single-threaded execution.
    ///
    /// # Arguments
    /// * `engine` - The Rhai engine instance to register the logging functions
    #[allow(clippy::unused_self)]
    fn register_logging(&self, engine: &mut Engine) {
        register_log_fn!(engine, error);
        register_log_fn!(engine, warn);
        register_log_fn!(engine, info);
        register_log_fn!(engine, trace);

        engine.on_debug(move |message: &str, _source: Option<&str>, pos: Position| {
            let line_number = pos.line().map_or(0, |l| u32::try_from(l).unwrap_or(0));

            let _guard = push_rhai_context_with_guard(None, line_number);

            debug!(
                target: RUNNER_TARGET_FOR_SCRIPT_LOGS,
                "{}", message.trim_matches('"')
            );
        });

        engine.disable_symbol("print");
    }
}

#[cfg(test)]
mod tests {
    use crate::monitoring::ProcessMonitor;
    use crate::rhai_engine_builder::RhaiEngineBuilder;
    use rex_cedar_auth::cedar_auth::UserEntity;
    use rex_test_utils::assertions::assert_error_contains;
    use rex_test_utils::rhai::common::to_eval_error;
    use rhai::EvalAltResult;
    use std::rc::Rc;

    /// Given: A Rex policy content
    /// When: Creating a RhaiEngineBuilder with the policy content
    /// Then: The Rhai engine is configured properly with the policy content
    #[test]
    fn test_rhai_engine_builder_with_policy_content() -> Result<(), Box<EvalAltResult>> {
        let policy_content = r#"permit(
            principal == User::"test_user",
            action == file_system::Action::"safe_read_file",
            resource == file_system::File::"test.txt"
        );"#
        .to_string();

        let rhai_engine_builder = RhaiEngineBuilder::with_policy_content(policy_content.clone());

        assert_eq!(rhai_engine_builder.policy, policy_content);
        Ok(())
    }

    /// Given: A RhaiEngineBuilder with policy content
    /// When: with_strict_variables is called with false
    /// Then: The builder should be configured with strict variables disabled
    #[test]
    fn test_rhai_engine_builder_with_strict_variables() -> Result<(), Box<EvalAltResult>> {
        let policy_content = "permit(principal, action, resource);".to_string();

        let rhai_engine_builder = RhaiEngineBuilder::with_policy_content(policy_content.clone())
            .with_strict_variables(false);

        assert_eq!(rhai_engine_builder.policy, policy_content);
        assert_eq!(rhai_engine_builder.strict_variables, false);
        Ok(())
    }

    /// Given: A RhaiEngineBuilder with default settings
    /// When: Creating the engine without calling with_strict_variables
    /// Then: The engine should have strict variables enabled by default
    #[test]
    fn test_rhai_engine_builder_default_strict_variables_enabled() -> Result<(), Box<EvalAltResult>>
    {
        let policy_content = "permit(principal, action, resource);".to_string();
        let rhai_context = RhaiEngineBuilder::with_policy_content(policy_content)
            .create()
            .map_err(to_eval_error)?;

        let script_with_undefined_var = "let result = undefined_variable + 1;";
        let result = rhai_context.engine().compile(script_with_undefined_var);

        assert!(
            result.is_err(),
            "Script with undefined variable should fail compilation when strict variables is enabled"
        );

        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Variable not found") || error_msg.contains("undefined"),
            "Error should indicate undefined variable: {}",
            error_msg
        );

        Ok(())
    }

    /// Given: A RhaiEngineBuilder with strict variables disabled
    /// When: Creating the engine and testing script argument injection
    /// Then: The engine should allow runtime variable injection via scope
    #[test]
    fn test_rhai_engine_builder_strict_variables_disabled() -> Result<(), Box<EvalAltResult>> {
        let policy_content = "permit(principal, action, resource);".to_string();
        let rhai_context = RhaiEngineBuilder::with_policy_content(policy_content)
            .with_strict_variables(false)
            .create()
            .map_err(to_eval_error)?;

        let script_using_injected_var = "let result = injected_variable + 10; result";

        let mut scope = rhai::Scope::new();
        scope.push("injected_variable", 32_i64);

        let execution_result: i64 = rhai_context
            .engine()
            .eval_with_scope(&mut scope, script_using_injected_var)?;
        assert_eq!(
            execution_result, 42,
            "Script should successfully use runtime-injected variables when strict variables is disabled"
        );

        Ok(())
    }

    /// Given: A RhaiEngineBuilder with strict variables enabled
    /// When: Creating the engine and running a script with all variables properly defined
    /// Then: The script should execute successfully
    #[test]
    fn test_rhai_engine_builder_strict_variables_enabled_with_defined_vars()
    -> Result<(), Box<EvalAltResult>> {
        let policy_content = "permit(principal, action, resource);".to_string();
        let rhai_context = RhaiEngineBuilder::with_policy_content(policy_content)
            .with_strict_variables(true)
            .create()
            .map_err(to_eval_error)?;

        let script_with_defined_vars = r#"
            let defined_variable = 10;
            let result = defined_variable + 32;
            result
        "#;

        let result: i64 = rhai_context.engine().eval(script_with_defined_vars)?;
        assert_eq!(
            result, 42,
            "Script with properly defined variables should execute successfully"
        );

        Ok(())
    }

    /// Given: A RhaiContext created from RhaiEngineBuilder
    /// When: get_process_monitor is called
    /// Then: It should return an Rc<RefCell<ProcessMonitor>> that can be used to access the monitor
    #[test]
    fn test_get_process_monitor_returns_cloned_rc() -> Result<(), Box<EvalAltResult>> {
        let policy_content = "permit(principal, action, resource);".to_string();
        let context = RhaiEngineBuilder::with_policy_content(policy_content)
            .create()
            .map_err(to_eval_error)?;

        let process_monitor = context.get_process_monitor();

        let mut monitor_ref = process_monitor.try_borrow_mut().map_err(to_eval_error)?;

        let cpu_usage = monitor_ref.get_cpu_usage();
        assert!(
            cpu_usage.is_some(),
            "CPU usage should be available when monitoring is enabled"
        );
        assert!(
            cpu_usage.unwrap() >= 0.0,
            "CPU usage should be non-negative"
        );

        let memory_avg = monitor_ref.get_rss_memory_average_mb();
        // Memory average may be None if no samples were collected yet
        if let Some(avg) = memory_avg {
            assert!(avg >= 0.0, "Memory average should be non-negative");
        }

        // Verify we can create a callback using the returned monitor
        drop(monitor_ref); // Release the borrow before creating callback
        let callback = ProcessMonitor::create_progress_callback(process_monitor.clone(), None);

        // Use the callback to verify it works
        callback(1);

        Ok(())
    }

    /// Given: An invalid Cedar policy and valid script content
    /// When: Creating a RhaiEngineBuilder and calling create()
    /// Then: It should return an error due to invalid policy
    #[test]
    fn test_rhai_engine_builder_with_invalid_policy_fails() -> Result<(), Box<EvalAltResult>> {
        let invalid_policy_content = "this is not valid cedar policy syntax!@#$%^&*()";

        let result =
            RhaiEngineBuilder::with_policy_content(invalid_policy_content.to_string()).create();

        assert!(
            result.is_err(),
            "Expected RhaiEngineBuilder creation to fail with invalid policy"
        );

        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Failed to parse Cedar policy"),
            "Error message should indicate policy parsing failure: {}",
            error_msg
        );

        Ok(())
    }

    /// Given: A RhaiContext
    /// When: Executing a script that emits an alarm with the RhaiEngine
    /// Then: The script alarm is collected properly from the RhaiContext
    #[test]
    fn test_rhai_context_alarm_collector() -> Result<(), Box<EvalAltResult>> {
        let policy_content = r#"permit(
            principal == User::"test_user",
            action == file_system::Action::"read",
            resource == file_system::File::"test.txt"
        );"#
        .to_string();

        let rhai_context = RhaiEngineBuilder::with_policy_content(policy_content.clone())
            .create()
            .unwrap();
        let script = r#"
        AlarmBuilder()
            .type("TestAlarm")
            .details("Test alarm details")
            .publish();
        "#;

        rhai_context.engine().eval::<()>(script)?;
        let script_alarm = &rhai_context.get_alarms().unwrap()[0];
        assert!(
            script_alarm.alarm_type == "TestAlarm"
                && script_alarm.alarm_details.as_ref().unwrap() == "Test alarm details"
        );
        Ok(())
    }

    /// Given: A RhaiContext
    /// When: Executing a script that emits a metric with the RhaiEngine
    /// Then: The script metric is collected properly from the RhaiContext
    #[test]
    fn test_rhai_context_metric_collector() -> Result<(), Box<EvalAltResult>> {
        let policy_content = r#"permit(
            principal == User::"test_user",
            action == file_system::Action::"read",
            resource == file_system::File::"test.txt"
        );"#
        .to_string();

        let rhai_context = RhaiEngineBuilder::with_policy_content(policy_content.clone())
            .create()
            .unwrap();

        let script = r#"
        MetricBuilder()
            .name("TestMetric")
            .value(100.0)
            .unit(MetricUnitType::COUNT)
            .publish();
        "#;

        rhai_context.engine().eval::<()>(script)?;
        let script_metric = &rhai_context.get_metrics().unwrap()[0];
        assert!(script_metric.metric_name == "TestMetric" && script_metric.metric_value == 100.0);
        Ok(())
    }

    /// Given: A RhaiContext created from RhaiEngineBuilder
    /// When: cedar_auth() method is called
    /// Then: It should return a valid Rc<CedarAuth> that can be used for authorization checks
    #[test]
    fn test_rhai_context_cedar_auth_getter() -> Result<(), Box<EvalAltResult>> {
        let policy_content = r#"permit(
            principal == User::"test_user",
            action == file_system::Action::"read",
            resource
        );"#
        .to_string();

        let rhai_context = RhaiEngineBuilder::with_policy_content(policy_content.clone())
            .create()
            .map_err(to_eval_error)?;

        let cedar_auth = rhai_context.cedar_auth();

        let cloned_cedar_auth = cedar_auth.clone();
        assert!(
            Rc::ptr_eq(cedar_auth, &cloned_cedar_auth),
            "Cloned Rc should point to the same CedarAuth instance"
        );

        Ok(())
    }

    /// Given: A RhaiContext created from RhaiEngineBuilder
    /// When: Executing a script that attempts to use the disabled `eval` function
    /// Then: The script execution should fail with an error indicating eval is disabled/unknown
    #[test]
    fn test_eval_function_is_disabled() -> Result<(), Box<EvalAltResult>> {
        let policy_content = "permit(principal, action, resource);".to_string();
        let rhai_context = RhaiEngineBuilder::with_policy_content(policy_content)
            .create()
            .map_err(to_eval_error)?;

        let script_using_eval = r#"
            let code = "40 + 2";
            let result = eval(code);
            result
        "#;

        let result = rhai_context.engine().eval::<i64>(script_using_eval);
        assert_error_contains(
            result,
            "ImproperSymbol(\"eval\", \"reserved keyword 'eval' is disabled\")",
        );

        Ok(())
    }

    /// Given: A RhaiEngineBuilder with permissive mode enabled
    /// When: Creating a RhaiContext
    /// Then: The CedarAuth instance has permissive mode propagated from RhaiEngineBuilder
    #[test]
    fn test_rhai_engine_builder_with_enable_permissive_mode() -> Result<(), Box<EvalAltResult>> {
        let rhai_context = RhaiEngineBuilder::with_policy_content(
            "permit(principal, action, resource);".to_string(),
        )
        .with_enable_permissive_mode(true)
        .create()
        .map_err(to_eval_error)?;

        assert!(
            rhai_context.cedar_auth().is_permissive_mode_enabled(),
            "CedarAuth should have permissive mode propagated from RhaiEngineBuilder"
        );

        Ok(())
    }
}
