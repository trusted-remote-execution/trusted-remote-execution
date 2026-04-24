pub mod errors;
pub mod memory_logger;
pub mod tracing_logger;
pub use tracing;
mod macros;

pub use tracing_logger::config::{LoggingOption, LoggingOptionBuilder};
pub use tracing_logger::logger::init_logger;

pub use memory_logger::config::{
    LogEntry, RUNNER_AND_SYSLOG_TARGET, RUNNER_TARGET, RUNNER_TARGET_FOR_SCRIPT_LOGS,
};
pub use memory_logger::handler::{
    ScriptLogHandle, get_script_handle, push_rhai_context_with_guard,
};
