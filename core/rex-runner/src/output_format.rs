use crate::model::RunnerExecutionOutput;
use clap::ValueEnum;
use std::io::{self, Write};
use std::process::exit;

/// Controls how the runner output is formatted.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum OutputFormat {
    /// Compact JSON (default) — full payload on a single line.
    #[default]
    Json,
    /// Indented JSON — full payload, human-readable formatting.
    PrettyJson,
    /// Human-readable — just the script output or error message.
    Human,
}

/// Writes the execution output to stdout in the requested format.
///
/// When `verbose` is true and format is `Human`, logs and a metrics summary
/// are included after the main output.
pub fn write_output(output: &RunnerExecutionOutput, format: OutputFormat, verbose: bool) {
    match format {
        OutputFormat::Json => write_json(output),
        OutputFormat::PrettyJson => write_pretty_json(output),
        OutputFormat::Human => write_human(output, verbose),
    }
}

fn write_json(output: &RunnerExecutionOutput) {
    let bytes = match serde_json::to_vec(output) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Failed to serialize output: {e}");
            exit(1);
        }
    };
    write_bytes(&bytes);
}

fn write_pretty_json(output: &RunnerExecutionOutput) {
    let bytes = match serde_json::to_vec_pretty(output) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Failed to serialize output: {e}");
            exit(1);
        }
    };
    write_bytes(&bytes);
}

fn write_human(output: &RunnerExecutionOutput, verbose: bool) {
    let stdout = io::stdout();
    let stderr = io::stderr();
    let mut out = stdout.lock();
    let mut err = stderr.lock();

    // Show logs before the main output when verbose
    if verbose && let Some(logs) = &output.logs {
        for entry in logs {
            if let Some(attrs) = &entry.attributes {
                let level = attrs.get("level").map_or("INFO", |s| s.as_str());
                let message = attrs.get("message").map_or("", |s| s.as_str());
                let _ = writeln!(out, "[{level}] {message}");
            }
        }
    }

    // Main output or error
    if let Some(error) = &output.error {
        let _ = writeln!(err, "error: {}", error.message);
    } else if !output.output.is_empty() {
        let _ = writeln!(out, "{}", output.output);
    }

    // Metrics summary when verbose
    if verbose && let Some(metrics) = &output.metrics {
        let _ = writeln!(out, "--- metrics ---");
        for metric in metrics {
            let _ = writeln!(out, "{}: {}", metric.metric_name, metric.metric_value);
        }
    }

    let _ = out.flush();
    let _ = err.flush();
}

fn write_bytes(bytes: &[u8]) {
    if let Err(e) = io::stdout().write_all(bytes) {
        eprintln!("Failed to write output: {e}");
        exit(1);
    }
    let _ = io::stdout().flush();
}
