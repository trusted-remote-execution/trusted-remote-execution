//! Shared model types for the runner.

pub use rex_metrics_and_alarms::alarms::RexAlarm;
pub use rex_metrics_and_alarms::metrics::RexMetric;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Full input payload for the CLI runner.
#[derive(Debug, Deserialize, Serialize)]
pub struct RunnerInput {
    pub script: String,
    pub policy: String,
    pub script_arguments: Option<HashMap<String, ScriptArgumentValue>>,
}

/// Recursive script argument value mirroring the Smithy model.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ScriptArgumentValue {
    StringValue(String),
    IntegerValue(i32),
    LongValue(i64),
    DoubleValue(f64),
    BooleanValue(bool),
    ListValue(Vec<ScriptArgumentValue>),
    MapValue(HashMap<String, ScriptArgumentValue>),
}

/// High-level execution status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionStatus {
    Success,
    Error,
}

/// Error classification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorType {
    ValidationException,
    AccessDeniedException,
    InternalException,
    ScriptException,
    CommunicationException,
}

impl std::fmt::Display for ErrorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorType::ValidationException => write!(f, "VALIDATION_EXCEPTION"),
            ErrorType::AccessDeniedException => write!(f, "ACCESS_DENIED_EXCEPTION"),
            ErrorType::InternalException => write!(f, "INTERNAL_EXCEPTION"),
            ErrorType::ScriptException => write!(f, "SCRIPT_EXCEPTION"),
            ErrorType::CommunicationException => write!(f, "COMMUNICATION_EXCEPTION"),
        }
    }
}

/// Structured execution error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionError {
    pub error_type: ErrorType,
    pub message: String,
}

impl ExecutionError {
    pub fn new(error_type: ErrorType, message: impl Into<String>) -> Self {
        let msg = message.into();
        let msg = if msg.len() > 1024 {
            let mut truncated = msg.chars().take(1021).collect::<String>();
            truncated.push_str("...");
            truncated
        } else {
            msg
        };
        Self {
            error_type,
            message: msg,
        }
    }
}

/// A single log entry as key-value attributes in the runner output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<HashMap<String, String>>,
}

/// The full output payload written to runner's stdout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunnerExecutionOutput {
    pub output: String,
    pub status: ExecutionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ExecutionError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alarms: Option<Vec<RexAlarm>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<Vec<RexMetric>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logs: Option<Vec<LogEntry>>,
}

impl RunnerExecutionOutput {
    pub fn success(output: String) -> Self {
        Self {
            output,
            status: ExecutionStatus::Success,
            error: None,
            alarms: None,
            metrics: None,
            logs: None,
        }
    }

    pub fn error(error: ExecutionError) -> Self {
        Self {
            output: String::new(),
            status: ExecutionStatus::Error,
            error: Some(error),
            alarms: None,
            metrics: None,
            logs: None,
        }
    }
}
