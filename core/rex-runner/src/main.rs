use rex_logger::warn;
use rex_metrics_and_alarms::metrics::build_rex_failure_count_metric;
use rex_runner::constants::{RexRunnerAlarm, RexRunnerMetric};
use rex_runner::context::{RunnerExecutionContext, RunnerMonitoringContext};
use rex_runner::error_handling::{create_error_response, create_error_response_with_monitoring};
use rex_runner::execution::execute_script;
use rex_runner::handle_or_exit;
use rex_runner::io::write_to_stdout;
use rex_runner::model::{ErrorType, RunnerInput, ScriptArgumentValue};
use rex_runner::monitoring::{
    build_alarm, init_logging, initialize_rex_alarm_and_metric_registries,
};
use rex_runner::output_format::{OutputFormat, write_output};
use rex_runner::validation::validate_script_arguments_depth;
use rust_sdk_common_utils::signal_handling::SigtermHandler;

use anyhow::{Context, Result};
use clap::Parser;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;
use tracing::info_span;

/// Executes a Rhai script under a Cedar policy.
///
/// Reads inputs from the filesystem
#[derive(Parser, Debug)]
#[command(name = "runner")]
struct Args {
    /// Path to the Rhai script file to execute.
    #[arg(long = "script-file", short = 's')]
    script_file: PathBuf,

    /// Path to the Cedar policy file.
    #[arg(long = "policy-file", short = 'p')]
    policy_file: PathBuf,

    /// Path to a JSON file containing script arguments (map of string keys
    /// to ScriptArgumentValue values).
    #[arg(long = "script-arguments-file", short = 'a')]
    script_arguments_file: Option<PathBuf>,

    /// Output format: json (default), pretty-json, or human.
    #[arg(long = "output-format", short = 'o', value_enum, default_value_t = OutputFormat::Json)]
    output_format: OutputFormat,

    /// Show additional detail (logs, metrics summary) in the output.
    #[arg(long, short = 'v')]
    verbose: bool,
}

/// Loads runner inputs from CLI file paths
fn load_runner_input_from_files(args: &Args) -> Result<RunnerInput> {
    let script = fs::read_to_string(&args.script_file)
        .with_context(|| format!("Failed to read script file: {}", args.script_file.display()))?;
    let policy = fs::read_to_string(&args.policy_file)
        .with_context(|| format!("Failed to read policy file: {}", args.policy_file.display()))?;

    let script_arguments: Option<HashMap<String, ScriptArgumentValue>> =
        match &args.script_arguments_file {
            Some(path) => {
                let raw = fs::read_to_string(path).with_context(|| {
                    format!("Failed to read script arguments file: {}", path.display())
                })?;
                Some(serde_json::from_str(&raw).with_context(|| {
                    format!("Failed to parse script arguments JSON: {}", path.display())
                })?)
            }
            None => None,
        };

    Ok(RunnerInput {
        script,
        policy,
        script_arguments,
    })
}

fn main() {
    let start_time = Instant::now();
    init_logging();

    let args = Args::parse();

    let (mut rex_alarm_registry, rex_metric_registry) = handle_or_exit!(
        initialize_rex_alarm_and_metric_registries(),
        "Failed to initialize registries",
        ErrorType::InternalException,
        None
    );

    if let Err(e) = SigtermHandler::register() {
        let error = format!("Failed to register SIGTERM handler: {e}");
        warn!(error);
        rex_alarm_registry.add_alarm(build_alarm(
            RexRunnerAlarm::RexRunnerInternalAlarm.to_string(),
            Some(error.clone()),
        ));
    }

    let runner_monitoring_context =
        RunnerMonitoringContext::new(start_time, rex_alarm_registry, rex_metric_registry);

    let RunnerInput {
        script,
        policy,
        script_arguments,
    } = handle_or_exit!(
        load_runner_input_from_files(&args),
        "Failed to load input files",
        ErrorType::CommunicationException,
        Some(&runner_monitoring_context)
    );

    let _runner_execution_span = info_span!("runner_execution_span").entered();

    let mut runner_execution_context =
        RunnerExecutionContext::new(script, policy, script_arguments, runner_monitoring_context);

    if let Some(args) = runner_execution_context.script_arguments.clone() {
        let monitoring = runner_execution_context.monitoring_mut();

        handle_or_exit!(
            validate_script_arguments_depth(&args),
            "Script arguments depth validation failed",
            ErrorType::ValidationException,
            &mut monitoring.rex_alarm_registry,
            RexRunnerAlarm::RexRunnerScriptArgumentValidationFailure,
            &mut monitoring.rex_metric_registry,
            build_rex_failure_count_metric(
                RexRunnerMetric::RexRunnerScriptArgumentValidationFailureCount.to_string(),
            ),
            Some(&monitoring.runner_execution_start_time)
        );
    }

    let output = execute_script(&mut runner_execution_context);

    write_output(&output, args.output_format, args.verbose);
}
