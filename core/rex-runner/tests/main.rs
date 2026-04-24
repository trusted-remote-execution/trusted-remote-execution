mod test_utils;

use rex_runner::model::{ErrorType, ExecutionStatus};
use std::collections::HashMap;
use std::process::Command;
use tempfile::NamedTempFile;
use test_utils::{DEFAULT_POLICY, deserialize_output, run_with_files, run_with_files_and_args};

const BINARY_PATH: &str = env!("CARGO_BIN_EXE_rex-runner");

/// Helper: write content to a named temp file and return it (kept alive).
fn write_temp(content: &str) -> NamedTempFile {
    let file = NamedTempFile::new().expect("Failed to create temp file");
    std::fs::write(file.path(), content).expect("Failed to write temp file");
    file
}

/// Given: No arguments provided to the runner
/// When: The runner is invoked without --script-file and --policy-file
/// Then: The process exits with a non-zero code (clap usage error)
#[test]
fn test_missing_required_args_fails() {
    let output = Command::new(BINARY_PATH)
        .output()
        .expect("Failed to execute process");
    assert_ne!(output.status.code(), Some(0));
}

/// Given: Valid script and policy files
/// When: The runner executes the script
/// Then: Exits with code 0 and Success status
#[test]
fn test_simple_script_success() {
    let script = write_temp(r#"info("hello world"); "done""#);
    let policy = write_temp(DEFAULT_POLICY);

    let output = run_with_files(script.path(), policy.path());

    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let parsed = deserialize_output(&output.stdout).expect("Failed to parse output");
    assert_eq!(parsed.status, ExecutionStatus::Success);
    assert!(parsed.error.is_none());
    assert_eq!(parsed.output, "done");
}

/// Given: A script that fails at runtime
/// When: The runner executes it
/// Then: Returns Error status with ScriptException
#[test]
fn test_script_runtime_error() {
    let script = write_temp(r#"throw "intentional error";"#);
    let policy = write_temp(DEFAULT_POLICY);

    let output = run_with_files(script.path(), policy.path());

    let parsed = deserialize_output(&output.stdout).expect("Failed to parse output");
    assert_eq!(parsed.status, ExecutionStatus::Error);
    assert!(parsed.error.is_some());
    assert_eq!(parsed.error.unwrap().error_type, ErrorType::ScriptException);
}

/// Given: A script with a compilation error
/// When: The runner tries to compile it
/// Then: Returns Error status
#[test]
fn test_script_compilation_error() {
    let script = write_temp(r#"this is not valid rhai syntax ???"#);
    let policy = write_temp(DEFAULT_POLICY);

    let output = run_with_files(script.path(), policy.path());

    let parsed = deserialize_output(&output.stdout).expect("Failed to parse output");
    assert_eq!(parsed.status, ExecutionStatus::Error);
    assert!(parsed.error.is_some());
}

/// Given: A script that produces output with metrics
/// When: Executed successfully
/// Then: Output contains metrics
#[test]
fn test_script_with_metrics_in_output() {
    let script = write_temp(r#""result value""#);
    let policy = write_temp(DEFAULT_POLICY);

    let output = run_with_files(script.path(), policy.path());
    assert_eq!(output.status.code(), Some(0));

    let parsed = deserialize_output(&output.stdout).expect("Failed to parse output");
    assert_eq!(parsed.status, ExecutionStatus::Success);
    assert_eq!(parsed.output, "result value");
    assert!(parsed.metrics.is_some(), "Expected metrics to be present");
}

/// Given: A script that uses script arguments
/// When: Input includes a script arguments JSON file
/// Then: Script can access them and returns the correct value
#[test]
fn test_script_with_arguments() {
    let script = write_temp(r#"name"#);
    let policy = write_temp(DEFAULT_POLICY);

    let mut args_map: HashMap<&str, serde_json::Value> = HashMap::new();
    args_map.insert("name", serde_json::json!({"stringValue": "Alice"}));
    let args_json = serde_json::to_string(&args_map).expect("Failed to serialize args");
    let args_file = write_temp(&args_json);

    let output = run_with_files_and_args(script.path(), policy.path(), Some(args_file.path()));

    assert_eq!(output.status.code(), Some(0));
    let parsed = deserialize_output(&output.stdout).expect("Failed to parse output");
    assert_eq!(parsed.status, ExecutionStatus::Success);
    assert_eq!(parsed.output, "Alice");
}
