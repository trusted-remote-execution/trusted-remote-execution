#[cfg(target_family = "unix")]
use crate::create_syslog_layer;
use crate::errors::RexLoggerError;
use crate::memory_logger::config::{DEFAULT_LOG_ENTRIES_LIMIT, DEFAULT_MESSAGE_LENGTH_LIMIT};
use crate::memory_logger::handler::{SCRIPT_HANDLE, ScriptLogHandle};
use crate::tracing_logger::config::LoggingOption;
#[cfg(target_family = "unix")]
use crate::tracing_logger::config::SYSLOG_IDENTITY;
use crate::tracing_logger::level::log_level;
use crate::{
    RUNNER_TARGET, RUNNER_TARGET_FOR_SCRIPT_LOGS, create_console_layer, create_script_log_layer,
    default_fmt_layer,
};
use anyhow::Result;
use std::error::Error;
#[cfg(target_family = "unix")]
use std::ffi::CString;
#[cfg(target_family = "unix")]
use syslog_tracing::{Facility, Options, Syslog};
use tracing_subscriber::filter::FilterExt;
use tracing_subscriber::fmt::time::UtcTime;
use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{Layer, filter, fmt};

/// Initializes the tracing registry with the provided layers.
///
/// This macro creates a tracing subscriber registry and adds the specified layers to it.
/// It handles the initialization process and converts any initialization errors into
/// [`RexLoggerError::InitializationError`].
///
/// # Arguments
///
/// * `$layer` - One or more layer expressions to add to the registry
///
/// # Errors
///
/// Returns [`RexLoggerError::InitializationError`] if the registry initialization fails,
/// typically due to a global subscriber already being set.
macro_rules! init_registry {
    ($($layer:expr),*) => {
        let _ = tracing_subscriber::registry()
            $(.with($layer))*
            .try_init()

            .map_err(|e| RexLoggerError::InitializationError {
                reason: "Failed to initialize logger".to_string(),
                source: Some(Box::new(e)),
            })?;

    };
}

/// Initializes the global tracing logger with the specified configuration.
///
/// This function sets up the tracing infrastructure based on the provided logging
/// configuration. It supports both console and syslog output destinations, with
/// platform-specific behavior for syslog (Unix systems only).
///
/// # Arguments
///
/// * `log_config` - Configuration specifying which logging outputs to enable
///
/// # Returns
///
/// * `Ok(())` - Logger initialized successfully
/// * `Err(Box<dyn Error>)` - Initialization failed
///
/// # Platform Support
///
/// - **All platforms**: Console logging
/// - **Unix only**: Syslog logging (ignored on other platforms)
///
/// # Errors
///
/// This function can fail if:
/// - A global subscriber has already been set
/// - Syslog initialization fails (Unix systems)
/// - Layer creation encounters an error
pub fn init_logger(log_config: &LoggingOption) -> Result<(), Box<dyn Error>> {
    if !log_config.console && !log_config.syslog && !log_config.script_log {
        return Ok(());
    }

    let log_level = log_level();
    let console_layer = create_console_layer!(log_config.console, log_level);
    let script_layer = create_script_log_layer!(
        log_config.script_log,
        log_config
            .max_script_log_message_length
            .unwrap_or(DEFAULT_MESSAGE_LENGTH_LIMIT)
    );

    if let Some(ref handle) = script_layer {
        SCRIPT_HANDLE.set(handle.clone()).ok();
    }

    // Initialize registry with platform-specific layers
    #[cfg(target_family = "unix")]
    {
        let syslog_layer = create_syslog_layer!(log_config.syslog, log_level);
        init_registry!(console_layer, syslog_layer, script_layer);
    }
    #[cfg(not(target_family = "unix"))]
    {
        init_registry!(console_layer, script_layer);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::init_logger;
    use crate::tracing_logger::config::LoggingOptionBuilder;
    use sealed_test::prelude::*;
    use std::env::set_var;

    /// Given: LoggingOptionBuilder is created with default settings
    /// When: the builder is built
    /// Then: it should have all subscribers set to false and succeed
    #[test]
    fn test_logging_option_builder_defaults() {
        let config = LoggingOptionBuilder::default().build().unwrap();
        assert!(
            !config.console,
            "Console logging should be disabled by default"
        );
        assert!(!config.syslog, "Syslog should be disabled by default");

        let result = init_logger(&config);

        assert!(
            result.is_ok(),
            "init_logger should succeed even with all logging disabled"
        );
    }

    /// Given: LoggingOption has only console logging enabled
    /// When: init_logger is called with this configuration
    /// Then: it should succeed and return empty guards (console doesn't create guards)
    #[test]
    fn test_init_logger_console_only() {
        let config = LoggingOptionBuilder::default()
            .console(true)
            .syslog(false)
            .build()
            .unwrap();

        let result = init_logger(&config);
        assert!(
            result.is_ok(),
            "init_logger should succeed with only console subscriber enabled"
        );
    }

    /// Given: LOG_LEVEL is set to INFO and all logging is disabled
    /// When: init_logger is called with the refactored implementation
    /// Then: it should work correctly maintaining backward compatibility
    #[sealed_test]
    fn test_init_logger_integration() {
        unsafe {
            set_var("LOG_LEVEL", "INFO");
        }

        let config = LoggingOptionBuilder::default()
            .console(false) // Disable console to avoid tracing conflicts
            .syslog(false) // Disable syslog for testing
            .build()
            .unwrap();

        let result = init_logger(&config);
        assert!(
            result.is_ok(),
            "Refactored init_logger should work correctly"
        );
    }
}
