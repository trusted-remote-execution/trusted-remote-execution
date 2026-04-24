//! `ps` - List processes (Linux only)
//!
//! Delegates to `RcProcessManager::safe_processes` from `rust-safe-process-mgmt`.
//!
//! # Example (Rhai)
//! ```rhai
//! let procs = ps();
//! for p in procs {
//!     print(`${p.pid} ${p.name} ${p.state}`);
//! }
//! ```

use rhai::Array;
use rust_safe_process_mgmt::errors::RustSafeProcessMgmtError;

/// Returns process list as an array of `ProcessInfo` structs.
#[cfg(target_os = "linux")]
pub(crate) fn ps(
    cedar_auth: &rex_cedar_auth::cedar_auth::CedarAuth,
) -> Result<Array, RustSafeProcessMgmtError> {
    use rhai::Dynamic;
    use rust_safe_process_mgmt::RcProcessManager;

    let pm = RcProcessManager::default();
    let procs =
        pm.safe_processes(cedar_auth)
            .map_err(|e| RustSafeProcessMgmtError::ValidationError {
                reason: format!("ps: {e}"),
            })?;

    Ok(procs.into_iter().map(Dynamic::from).collect())
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::unnecessary_wraps, unused_variables)]
pub(crate) fn ps(
    cedar_auth: &rex_cedar_auth::cedar_auth::CedarAuth,
) -> Result<Array, RustSafeProcessMgmtError> {
    Err(RustSafeProcessMgmtError::ValidationError {
        reason: "ps: only supported on Linux".to_string(),
    })
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_os = "linux"))]
    use super::*;

    #[cfg(not(target_os = "linux"))]
    /// Given: A non-Linux platform
    /// When: Calling ps
    /// Then: An error is returned
    #[test]
    fn test_ps_not_supported_on_non_linux() {
        let cedar_auth = test_utils::rhai::common::create_default_test_cedar_auth();
        let result = ps(&cedar_auth);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("only supported on Linux")
        );
    }
}
