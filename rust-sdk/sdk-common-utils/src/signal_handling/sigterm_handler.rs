use anyhow::{Context, Result};
use signal_hook::{consts::SIGTERM, flag};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, OnceLock};
use time::OffsetDateTime;

static SIGTERM_HANDLER: OnceLock<Arc<AtomicBool>> = OnceLock::new();
static SIGTERM_TIMESTAMP: AtomicI64 = AtomicI64::new(0);

/// This implementation uses signal handling and provides static methods
/// that can be called from anywhere in the application without object instantiation.
/// The signal handler is registered once and timestamps are captured lazily when first requested.
///
/// # Example Usage
///
/// ```rust
/// use rust_sdk_common_utils::signal_handling::SigtermHandler;
///
/// // Register signal handler once (typically in main)
/// SigtermHandler::register().expect("Failed to register SIGTERM handler");
///
/// // Check for SIGTERM anywhere in your application
/// if SigtermHandler::is_received() {
///     println!("SIGTERM received, beginning graceful shutdown");
///     
///     if let Some(elapsed) = SigtermHandler::get_elapsed_seconds() {
///         println!("SIGTERM received {} seconds ago", elapsed);
///     }
/// }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct SigtermHandler;

impl SigtermHandler {
    /// Registers the SIGTERM signal handler (idempotent - safe to call multiple times)
    ///
    /// This method should be called once during application startup.
    /// Subsequent calls are safe and will have no effect. The flag is set automatically
    /// when SIGTERM is received, and timestamps are captured lazily.
    ///
    /// # Returns
    /// * `Ok(())` - Successfully registered handler or already registered
    /// * `Err(anyhow::Error)` - Failed to register signal handler
    pub fn register() -> Result<()> {
        if SIGTERM_HANDLER.get().is_some() {
            return Ok(());
        }
        let flag = Arc::new(AtomicBool::new(false));
        flag::register(SIGTERM, flag.clone()).context("Failed to register SIGTERM flag handler")?;
        SIGTERM_HANDLER
            .set(flag)
            .map_err(|_| anyhow::anyhow!("SIGTERM handler already registered"))?;

        Ok(())
    }

    /// Checks if SIGTERM was received
    ///
    /// This method can be called from anywhere in the application to check if
    /// SIGTERM has been received.
    ///
    /// # Returns
    /// * `true` - SIGTERM has been received
    /// * `false` - SIGTERM has not been received
    pub fn is_received() -> bool {
        SIGTERM_HANDLER
            .get()
            .is_some_and(|flag| flag.load(Ordering::Relaxed))
    }

    /// Get elapsed seconds since SIGTERM was received
    ///
    /// Returns the number of seconds that have elapsed since SIGTERM was first
    /// detected. The timestamp is captured lazily when this function is first called,
    /// providing a consistent reference point for elapsed time calculations.
    ///
    /// # Returns
    /// * `Some(seconds)` - Number of seconds since SIGTERM was first detected
    /// * `None` - SIGTERM has not been received
    pub fn get_elapsed_seconds() -> Option<i64> {
        if !Self::is_received() {
            return None;
        }
        let mut timestamp = SIGTERM_TIMESTAMP.load(Ordering::Relaxed);
        if timestamp == 0 {
            let current_time = OffsetDateTime::now_utc().unix_timestamp();
            SIGTERM_TIMESTAMP.store(current_time, Ordering::Relaxed);
            timestamp = current_time;
        }
        let current_time = OffsetDateTime::now_utc().unix_timestamp();
        Some(current_time.saturating_sub(timestamp))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Given: SigtermHandler static methods
    /// When: Checking initial state before any signal
    /// Then: SIGTERM should not be received and no elapsed time
    #[test]
    fn test_initial_state() {
        assert!(
            !SigtermHandler::is_received(),
            "is_received should return false"
        );
    }

    /// Given: SigtermHandler elapsed time calculation
    /// When: SIGTERM has not been received
    /// Then: Should return None
    #[test]
    fn test_elapsed_time_when_not_received() {
        // Since we can't control global state in tests, we test the logic
        // by checking that if timestamp is 0, elapsed time is None
        if SIGTERM_TIMESTAMP.load(Ordering::Relaxed) == 0 {
            assert_eq!(
                SigtermHandler::get_elapsed_seconds(),
                None,
                "Should return None when SIGTERM not received"
            );
        }
    }
}
