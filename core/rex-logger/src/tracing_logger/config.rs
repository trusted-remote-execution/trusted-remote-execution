use derive_builder::Builder;

/// This constant defines the program name that will appear in syslog entries
/// when syslog logging is enabled. It helps identify log entries from this
/// application in system logs.
pub const SYSLOG_IDENTITY: &str = "rex_runner";

/// Configuration options for logging output destinations.
///
/// This struct defines which logging outputs should be enabled. It uses the builder
/// pattern via `derive_builder` for convenient configuration. Both console and syslog
/// logging are disabled by default.
///
/// # Platform Support
///
/// - **Console logging**: Available on all platforms
/// - **Syslog logging**: Unix-based systems only (Linux, macOS, etc.)
/// - **Memory logging**: Available on all platforms
/// - **Max Log Message Length**: Maximun length for individual log messages stored in-memory. Defaults to 2Kb if not set.
///
/// # Examples
///
/// ```rust
/// use rex_logger::tracing_logger::config::LoggingOptionBuilder;
///
/// let config = LoggingOptionBuilder::default()
///     .console(true)
///     .syslog(false)
///     .build()
///     .unwrap();
/// ```
#[derive(Builder, Debug, Copy, Clone)]
pub struct LoggingOption {
    #[builder(default = false)]
    pub console: bool,

    #[builder(default = false)]
    pub syslog: bool,

    #[builder(default = false)]
    pub script_log: bool,

    #[builder(default)]
    pub max_script_log_message_length: Option<usize>,
}
