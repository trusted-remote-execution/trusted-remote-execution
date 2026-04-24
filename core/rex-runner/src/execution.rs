use crate::constants::{RexRunnerAlarm, RexRunnerMetric};
use crate::context::RunnerExecutionContext;
use crate::error_handling::create_error_response_with_monitoring;
use crate::handle_or_exit;
use crate::io::{structure_engine_output, write_to_stdout};
use crate::model::{ErrorType, RunnerExecutionOutput, ScriptArgumentValue};
use crate::monitoring::{
    add_process_monitoring_metrics_to_registry, add_script_alarms_to_rex_alarm_registry,
    add_script_metrics_to_rex_metric_registry, build_alarm,
};
use crate::utils::elapsed_duration;
use rex_logger::info;
use rex_metrics_and_alarms::metrics::{build_rex_duration_metric, build_rex_failure_count_metric};
use rhai::{Dynamic, EvalAltResult, Scope};
use std::time::Instant;

/// Compiles and executes script content within the runner execution context.
#[allow(clippy::implicit_hasher)]
#[allow(clippy::cognitive_complexity)]
pub(crate) fn run_script_content(
    runner_execution_context: &mut RunnerExecutionContext,
) -> Result<Dynamic, Box<EvalAltResult>> {
    info!("Compiling script content from stdin.");
    let mut scope = Scope::new();

    if let Some(args) = &runner_execution_context.script_arguments {
        for (key, value) in args {
            let rhai_dynamic = convert_script_argument_value_to_rhai_dynamic(value.clone());
            scope.push(key, rhai_dynamic);
        }
    } else {
        info!("No script arguments provided");
    }

    let ast = runner_execution_context
        .rhai_context
        .engine()
        .compile_with_scope(&scope, runner_execution_context.script_content.clone())
        .map_err(|e| {
            runner_execution_context
                .monitoring_mut()
                .rex_alarm_registry
                .add_alarm(build_alarm(
                    RexRunnerAlarm::RexRunnerScriptCompilationFailure.to_string(),
                    Some(format!("Failed to compile script: {e}")),
                ));
            runner_execution_context
                .monitoring_mut()
                .rex_metric_registry
                .add_metric(build_rex_failure_count_metric(
                    RexRunnerMetric::RexRunnerScriptCompilationFailureCount.to_string(),
                ));
            e
        })?;

    info!("Running script content from stdin.");
    let script_execution_start_time = Instant::now();

    let result = runner_execution_context
        .rhai_context
        .engine()
        .eval_ast_with_scope(&mut scope, &ast);

    runner_execution_context
        .monitoring_mut()
        .rex_metric_registry
        .add_metric(build_rex_duration_metric(
            RexRunnerMetric::RexRunnerScriptExecutionTime.to_string(),
            elapsed_duration(&script_execution_start_time),
        ));

    result
}

fn convert_script_argument_value_to_rhai_dynamic(value: ScriptArgumentValue) -> Dynamic {
    match value {
        ScriptArgumentValue::StringValue(s) => Dynamic::from(s),
        ScriptArgumentValue::IntegerValue(i) => Dynamic::from(i64::from(i)),
        ScriptArgumentValue::LongValue(l) => Dynamic::from(l),
        ScriptArgumentValue::DoubleValue(d) => Dynamic::from(d),
        ScriptArgumentValue::BooleanValue(b) => Dynamic::from(b),
        ScriptArgumentValue::ListValue(arr) => {
            let rhai_array: rhai::Array = arr
                .into_iter()
                .map(convert_script_argument_value_to_rhai_dynamic)
                .collect();
            Dynamic::from(rhai_array)
        }
        ScriptArgumentValue::MapValue(obj) => {
            let mut rhai_map = rhai::Map::new();
            for (k, v) in obj {
                rhai_map.insert(k.into(), convert_script_argument_value_to_rhai_dynamic(v));
            }
            Dynamic::from(rhai_map)
        }
    }
}

/// Executes a script within the provided runner execution context.
#[allow(clippy::implicit_hasher)]
pub fn execute_script(
    runner_execution_context: &mut RunnerExecutionContext,
) -> RunnerExecutionOutput {
    let result = run_script_content(runner_execution_context);
    add_process_monitoring_metrics_to_registry(
        &runner_execution_context.rhai_context.get_process_monitor(),
        &runner_execution_context.monitoring().rex_metric_registry,
    );

    handle_or_exit!(
        add_script_metrics_to_rex_metric_registry(
            runner_execution_context.rhai_context.get_metrics().as_ref(),
            runner_execution_context.monitoring_mut()
        ),
        "Script metric validation failed",
        ErrorType::ScriptException,
        Some(runner_execution_context.monitoring())
    );

    handle_or_exit!(
        add_script_alarms_to_rex_alarm_registry(
            runner_execution_context.rhai_context.get_alarms().as_ref(),
            &mut runner_execution_context.monitoring_mut().rex_alarm_registry
        ),
        "Script alarm validation failed",
        ErrorType::ScriptException,
        Some(runner_execution_context.monitoring())
    );

    structure_engine_output(&result, runner_execution_context.monitoring_mut())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::RexRunnerAlarm;
    use crate::context::RunnerMonitoringContext;
    use crate::model::ScriptArgumentValue;
    use rex_metrics_and_alarms::alarms::RexAlarmRegistryBuilder;
    use rex_metrics_and_alarms::metrics::RexMetricRegistryBuilder;
    use rstest::rstest;
    use std::collections::HashMap;

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

    /// Given: A RunnerExecutionContext with valid script content
    /// When: A script content is run
    /// Then: The script execution should succeed without errors
    #[test]
    fn test_run_script_body_success() {
        let mut ctx = create_test_execution_context(r#"info("Hello world");"#, None, None);
        let result = run_script_content(&mut ctx);
        assert!(
            result.is_ok(),
            "Script execution should succeed. Error: {:?}",
            result.unwrap_err()
        );
        assert!(ctx.monitoring().rex_alarm_registry.get_alarms().is_none());
        assert!(ctx
            .monitoring()
            .rex_metric_registry
            .get_metrics()
            .unwrap()
            .iter()
            .any(|m| m.metric_name == RexRunnerMetric::RexRunnerScriptExecutionTime.to_string()));
    }

    /// Given: Script arguments of all possible types
    /// When: The script is executed with provided arguments
    /// Then: The script correctly accesses all argument types
    #[test]
    fn test_run_script_content_with_arguments_success() {
        let script_content = r#"
            let message = greeting + " " + name + "!";
            info("Message: " + message);
            let total = positive_int + long_val;
            let is_ready = bool_true && !bool_false;
            let array_len = mixed_array.len();
            let user_name = user_info.name;
            "All argument types processed successfully"
        "#;

        let mut args = HashMap::new();
        args.insert(
            "name".to_string(),
            ScriptArgumentValue::StringValue("World".to_string()),
        );
        args.insert(
            "greeting".to_string(),
            ScriptArgumentValue::StringValue("Hello".to_string()),
        );
        args.insert(
            "positive_int".to_string(),
            ScriptArgumentValue::IntegerValue(42),
        );
        args.insert(
            "long_val".to_string(),
            ScriptArgumentValue::LongValue(1000000i64),
        );
        args.insert(
            "bool_true".to_string(),
            ScriptArgumentValue::BooleanValue(true),
        );
        args.insert(
            "bool_false".to_string(),
            ScriptArgumentValue::BooleanValue(false),
        );
        args.insert(
            "mixed_array".to_string(),
            ScriptArgumentValue::ListValue(vec![
                ScriptArgumentValue::StringValue("item1".to_string()),
                ScriptArgumentValue::LongValue(100),
            ]),
        );
        let mut user_info = HashMap::new();
        user_info.insert(
            "name".to_string(),
            ScriptArgumentValue::StringValue("Alice".to_string()),
        );
        args.insert(
            "user_info".to_string(),
            ScriptArgumentValue::MapValue(user_info),
        );

        let mut ctx = create_test_execution_context(script_content, None, Some(args));
        let result = run_script_content(&mut ctx);
        assert!(result.is_ok(), "Error: {:?}", result.unwrap_err());
        assert_eq!(
            result.unwrap().to_string(),
            "All argument types processed successfully"
        );
    }

    /// Given: A script with syntax error
    /// When: The script is compiled
    /// Then: Compilation fails and alarm is set
    #[test]
    fn test_run_script_body_compilation_failure() {
        let mut ctx =
            create_test_execution_context(r#"safe_println("missing semicolon"#, None, None);
        let result = run_script_content(&mut ctx);
        assert!(result.is_err());
        let alarms = ctx.monitoring().rex_alarm_registry.get_alarms().unwrap();
        assert!(
            alarms
                .iter()
                .any(|a| a.alarm_type
                    == RexRunnerAlarm::RexRunnerScriptCompilationFailure.to_string())
        );
    }

    /// Given: A ScriptArgumentValue::StringValue
    /// When: convert_script_argument_value_to_rhai_dynamic is called
    /// Then: Returns Dynamic string
    #[test]
    fn test_convert_string_value() {
        let result = convert_script_argument_value_to_rhai_dynamic(
            ScriptArgumentValue::StringValue("Hello".to_string()),
        );
        assert_eq!(result.type_name(), "string");
        assert_eq!(result.cast::<String>(), "Hello");
    }

    /// Given: Various numeric ScriptArgumentValues
    /// When: convert_script_argument_value_to_rhai_dynamic is called
    /// Then: Returns correct Dynamic numeric types
    #[rstest]
    #[case(ScriptArgumentValue::IntegerValue(42), 42i64)]
    #[case(ScriptArgumentValue::LongValue(i64::MAX), i64::MAX)]
    fn test_convert_numeric_values(#[case] input: ScriptArgumentValue, #[case] expected: i64) {
        let result = convert_script_argument_value_to_rhai_dynamic(input);
        assert_eq!(result.cast::<i64>(), expected);
    }

    /// Given: Boolean ScriptArgumentValues
    /// When: convert_script_argument_value_to_rhai_dynamic is called
    /// Then: Returns correct Dynamic boolean
    #[rstest]
    #[case(true)]
    #[case(false)]
    fn test_convert_boolean_value(#[case] val: bool) {
        let result =
            convert_script_argument_value_to_rhai_dynamic(ScriptArgumentValue::BooleanValue(val));
        assert_eq!(result.cast::<bool>(), val);
    }

    /// Given: A list ScriptArgumentValue
    /// When: convert_script_argument_value_to_rhai_dynamic is called
    /// Then: Returns Dynamic array with converted elements
    #[test]
    fn test_convert_list_value() {
        let result =
            convert_script_argument_value_to_rhai_dynamic(ScriptArgumentValue::ListValue(vec![
                ScriptArgumentValue::StringValue("a".to_string()),
                ScriptArgumentValue::LongValue(1),
            ]));
        assert_eq!(result.type_name(), "array");
        let arr = result.cast::<rhai::Array>();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0].clone().cast::<String>(), "a");
        assert_eq!(arr[1].clone().cast::<i64>(), 1);
    }

    /// Given: A map ScriptArgumentValue
    /// When: convert_script_argument_value_to_rhai_dynamic is called
    /// Then: Returns Dynamic map with converted values
    #[test]
    fn test_convert_map_value() {
        let mut map = HashMap::new();
        map.insert(
            "key".to_string(),
            ScriptArgumentValue::StringValue("value".to_string()),
        );
        let result =
            convert_script_argument_value_to_rhai_dynamic(ScriptArgumentValue::MapValue(map));
        assert_eq!(result.type_name(), "map");
        let rhai_map = result.cast::<rhai::Map>();
        assert_eq!(
            rhai_map.get("key").unwrap().clone().cast::<String>(),
            "value"
        );
    }

    /// Given: A double ScriptArgumentValue with NaN
    /// When: convert_script_argument_value_to_rhai_dynamic is called
    /// Then: Returns Dynamic NaN
    #[test]
    fn test_convert_nan_double() {
        let result = convert_script_argument_value_to_rhai_dynamic(
            ScriptArgumentValue::DoubleValue(f64::NAN),
        );
        assert!(result.cast::<f64>().is_nan());
    }
}
