/// Creates a formatted layer with standard configuration options.
///
/// This macro applies consistent formatting settings to any tracing layer,
/// including line numbers, log levels, thread IDs, and target information.
/// ANSI colors are disabled for compatibility with various output destinations.
///
/// # Arguments
///
/// * `$layer` - A tracing layer expression to be configured
///
/// # Returns
///
/// The configured layer with the following settings:
/// - ANSI colors: disabled
/// - Line numbers: enabled
/// - Log levels: enabled
/// - Thread IDs: enabled
/// - Target information: enabled
#[macro_export]
macro_rules! default_fmt_layer {
    ($layer:expr) => {
        $layer
            .with_ansi(false)
            .with_file(true)
            .with_line_number(true)
            .with_level(true)
            .with_thread_ids(true)
            .with_target(true)
    };
}

/// Creates a console logging layer that outputs to stdout.
///
/// This macro conditionally creates a console logging layer based on the enabled flag.
/// When enabled, it creates a formatted layer that writes to stdout with RFC 3339
/// timestamps and applies the specified log level filter.
///
/// # Arguments
///
/// * `$enabled` - Boolean expression indicating whether console logging should be enabled
/// * `$log_level` - Log level filter to apply to the layer
///
/// # Returns
///
/// * `Some(Layer)` - Configured console layer if enabled
/// * `None` - If console logging is disabled
#[macro_export]
macro_rules! create_console_layer {
    ($enabled:expr, $log_level:expr) => {
        if $enabled {
            Some(
                default_fmt_layer!(fmt::layer()
                    .with_writer(std::io::stdout)
                    .with_timer(UtcTime::rfc_3339()))
                .with_filter($log_level),
            )
        } else {
            None
        }
    };
}

/// Creates a script logging layer for capturing script execution logs in memory.
///
/// This macro conditionally creates a script logging layer that captures log entries
/// in memory for later retrieval. When enabled, it creates a [`ScriptLogHandle`] that
/// implements the tracing [`Layer`] trait and stores log entries in an in-memory buffer.
///
/// # Arguments
///
/// * `$enabled` - Boolean expression indicating whether script logging should be enabled
///
/// # Returns
///
/// * `Some(ScriptLogHandle)` - Configured script log layer if enabled
/// * `None` - If script logging is disabled
#[macro_export]
macro_rules! create_script_log_layer {
    ($enabled:expr, $max_script_log_message_length:expr) => {
        if $enabled {
            Some(ScriptLogHandle::new(
                $max_script_log_message_length,
                DEFAULT_LOG_ENTRIES_LIMIT,
            ))
        } else {
            None
        }
    };
}

/// Creates a syslog logging layer for Unix systems.
///
/// This macro conditionally creates a syslog logging layer based on the enabled flag.
/// When enabled, it initializes a connection to the system's syslog daemon using the
/// `Daemon` facility and includes the process ID in log entries.
///
/// **Platform Support**: Unix-based systems only (Linux, macOS, etc.)
///
/// # Arguments
///
/// * `$enabled` - Boolean expression indicating whether syslog logging should be enabled
/// * `$log_level` - Log level filter to apply to the layer
///
/// # Returns
///
/// * `Some(Layer)` - Configured syslog layer if enabled and initialization succeeds
/// * `None` - If syslog logging is disabled
///
/// # Errors
///
/// Returns [`RexLoggerError::InitializationError`] if:
/// * Failed to create `CString` for syslog identity
/// * Failed to initialize syslog connection
#[macro_export]
#[cfg(target_family = "unix")]
macro_rules! create_syslog_layer {
    ($enabled:expr, $log_level:expr) => {
        if $enabled {
            let identity =
                CString::new(SYSLOG_IDENTITY).map_err(|e| RexLoggerError::InitializationError {
                    reason: "Failed to create CString for syslog identity".to_string(),
                    source: Some(Box::new(e)),
                })?;
            let options = Options::LOG_PID;
            let facility = Facility::Daemon;
            let syslog = Syslog::new(identity, options, facility).ok_or_else(|| {
                RexLoggerError::InitializationError {
                    reason: "Failed to initialize syslog".to_string(),
                    source: None,
                }
            })?;
            Some(
                default_fmt_layer!(fmt::layer().with_writer(syslog).without_time()).with_filter(
                    $log_level.and(filter::filter_fn(|metadata| {
                        metadata.target() != RUNNER_TARGET
                            && metadata.target() != RUNNER_TARGET_FOR_SCRIPT_LOGS
                    })),
                ),
            )
        } else {
            None
        }
    };
}
