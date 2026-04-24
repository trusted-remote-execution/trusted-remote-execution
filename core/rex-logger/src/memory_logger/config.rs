//! Configuration types and constants for the memory-based script logging system.
//!
//! This module provides the core data structures and configuration constants used
//! by the script logging functionality. The memory logger captures log entries
//! from Rhai scripts during execution and stores them in memory for later retrieval.
use chrono::{DateTime, Utc};

/// Target identifier for logging events to both Runner output and syslogs.
pub const RUNNER_AND_SYSLOG_TARGET: &str = "runner_and_syslog_target";

/// Target identifier for logging events to only Runner output.
pub const RUNNER_TARGET: &str = "runner_target";

/// Target identifier for logging events to only Runner output that comes from script logs.
pub const RUNNER_TARGET_FOR_SCRIPT_LOGS: &str = "runner_target_for_script_logs";

/// Default message length limit when not configured is 2Kb
pub const DEFAULT_MESSAGE_LENGTH_LIMIT: usize = 2048;

/// Maximum number of log entries that can be stored in memory
pub const DEFAULT_LOG_ENTRIES_LIMIT: usize = 1000;

/// Represents a single log entry captured from script execution.
///
/// This structure contains all the essential information about a log event
/// that occurred during Rhai script execution.
///
/// # Fields
///
/// * `timestamp` - UTC timestamp when the log entry was created
/// * `line_number` - Line number in the script where the log occurred
/// * `message` - The actual log message content
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub line_number: u32,
    pub level: String,
    pub message: String,
    pub rhai_api_name: Option<String>,
}

/// Represents the execution context of a Rhai script function.
///
/// # Fields
///
/// * `function_name` - The name of the Rhai function currently being executed
/// * `line_number` - The line number in the script where execution is occurring
#[derive(Debug, Clone)]
pub struct RhaiContext {
    pub rhai_api_name: Option<String>,
    pub line_number: u32,
}
