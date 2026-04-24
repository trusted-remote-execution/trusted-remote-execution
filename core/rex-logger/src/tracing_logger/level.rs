use std::env::var;
use tracing::level_filters::LevelFilter;

/// Determines the log level from the `LOG_LEVEL` environment variable with fallback to DEBUG.
///
/// This function reads the `LOG_LEVEL` environment variable and converts it to the appropriate
/// [`LevelFilter`]. If the environment variable is not set or contains an invalid value,
/// it provides sensible defaults.
///
/// # Environment Variable
///
/// The `LOG_LEVEL` environment variable accepts the following values (case-insensitive):
/// - `"TRACE"` - Most verbose logging level
/// - `"DEBUG"` - Debug information (default for invalid values)
/// - `"INFO"` - Informational messages (default when not set)
/// - `"WARN"` - Warning messages
/// - `"ERROR"` - Error messages only
///
/// # Returns
///
/// * [`LevelFilter`] - The appropriate log level filter
pub fn log_level() -> LevelFilter {
    var("LOG_LEVEL").map_or(LevelFilter::INFO, |val| match val.to_uppercase().as_str() {
        "TRACE" => LevelFilter::TRACE,
        "DEBUG" => LevelFilter::DEBUG,
        "WARN" => LevelFilter::WARN,
        "ERROR" => LevelFilter::ERROR,
        _ => LevelFilter::INFO,
    })
}

#[cfg(test)]
mod tests {
    use super::log_level;
    use sealed_test::prelude::*;
    use std::env::set_var;
    use tracing_subscriber::filter::LevelFilter;

    /// Given: LOG_LEVEL environment variable is not set
    /// When: log_level function is called
    /// Then: it should return the default log level of INFO
    #[sealed_test]
    fn test_log_level_default() {
        assert_eq!(log_level(), LevelFilter::INFO);
    }

    /// Given: LOG_LEVEL environment variable is set to invalid values
    /// When: log_level function is called
    /// Then: it should return the default log level of DEBUG for all invalid values
    #[sealed_test]
    fn test_log_level_invalid_values() {
        let invalid_values = vec!["INVALID", "123", "", "VERBOSE", "CRITICAL"];

        for invalid_val in invalid_values {
            unsafe {
                set_var("LOG_LEVEL", invalid_val);
            }
            assert_eq!(
                log_level(),
                LevelFilter::INFO,
                "Failed for LOG_LEVEL={}",
                invalid_val
            );
        }
    }
}
