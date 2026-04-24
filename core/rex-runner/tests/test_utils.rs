//! Utilities for testing the runner binary via CLI file arguments.

use anyhow::Result;
use rex_runner::model::RunnerExecutionOutput;
use std::path::Path;
use std::process::{Command, Output};

pub const DEFAULT_POLICY: &str = "permit(principal, action, resource);";

const BINARY_PATH: &str = env!("CARGO_BIN_EXE_rex-runner");

/// Runs the runner binary with the given script and policy file paths.
pub fn run_with_files(script_path: &Path, policy_path: &Path) -> Output {
    Command::new(BINARY_PATH)
        .arg("--script-file")
        .arg(script_path)
        .arg("--policy-file")
        .arg(policy_path)
        .output()
        .expect("Failed to execute process")
}

/// Runs the runner binary with script, policy, and optional arguments file.
pub fn run_with_files_and_args(
    script_path: &Path,
    policy_path: &Path,
    args_path: Option<&Path>,
) -> Output {
    let mut cmd = Command::new(BINARY_PATH);
    cmd.arg("--script-file")
        .arg(script_path)
        .arg("--policy-file")
        .arg(policy_path);
    if let Some(args) = args_path {
        cmd.arg("--script-arguments-file").arg(args);
    }
    cmd.output().expect("Failed to execute process")
}

/// Deserializes `RunnerExecutionOutput` from raw bytes.
pub fn deserialize_output(data: &[u8]) -> Result<RunnerExecutionOutput> {
    Ok(serde_json::from_slice(data)?)
}
