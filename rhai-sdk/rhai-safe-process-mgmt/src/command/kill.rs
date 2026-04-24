//! `kill` - Send signals to processes (Linux only)
//!
//! Delegates to `RcProcessManager::safe_kill` from `rust-safe-process-mgmt`.
//!
//! # Example (Rhai)
//! ```rhai
//! kill(1234);
//! kill([kill::signal(9)], 1234);
//! ```

use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::Array;
#[cfg(any(target_os = "linux", test))]
use rhai_sdk_common_utils::args::extract_flags;
use rhai_sdk_common_utils::args::find_flag_value;
use rust_safe_process_mgmt::errors::RustSafeProcessMgmtError;

/// Flags for the `kill` command, registered as a Rhai custom type.
///
/// Available flags:
/// - `kill::signal(n)` — signal number (default 15 = SIGTERM)
/// - `kill::SIGTERM` — alias for signal(15)
/// - `kill::SIGKILL` — alias for signal(9)
/// - `kill::SIGHUP` — alias for signal(1)
#[derive(Debug, Clone)]
pub(crate) enum KillFlag {
    #[allow(dead_code)]
    Signal(i64),
}

pub(crate) struct KillOptions {
    pub signal: i64,
}

impl KillOptions {
    pub(crate) fn from_flags(flags: &[KillFlag]) -> Self {
        Self {
            signal: find_flag_value(flags, |f| match f {
                KillFlag::Signal(n) => Some(*n),
            })
            .unwrap_or(15),
        }
    }
}

/// Send SIGTERM to a process by PID.
///
/// Returns a list of `(name, pid)` pairs for killed processes.
///
/// # Example
/// ```rhai
/// let killed = kill(1234);
/// ```
#[cfg(target_os = "linux")]
pub(crate) fn kill(
    pid: i64,
    cedar_auth: &CedarAuth,
) -> Result<Vec<(String, i64)>, RustSafeProcessMgmtError> {
    kill_with_flags(pid, &Array::new(), cedar_auth)
}

/// Send a signal to a process with user-provided flags.
///
/// # Example
/// ```rhai
/// let killed = kill([kill::signal(9)], 5678);
/// ```
#[cfg(target_os = "linux")]
pub(crate) fn kill_with_flags(
    pid: i64,
    flags_arr: &Array,
    cedar_auth: &CedarAuth,
) -> Result<Vec<(String, i64)>, RustSafeProcessMgmtError> {
    use rust_safe_process_mgmt::RcProcessManager;
    use rust_safe_process_mgmt::options::KillOptionsBuilder;

    let flags = extract_flags::<KillFlag>(flags_arr)
        .map_err(|e| RustSafeProcessMgmtError::ValidationError { reason: e })?;
    let opts = KillOptions::from_flags(&flags);

    let pm = RcProcessManager::default();

    let mut kill_builder = KillOptionsBuilder::default();
    kill_builder.pid(pid);

    let signal = signal_from_number(opts.signal)?;
    kill_builder.signal(signal);

    let kill_options =
        kill_builder
            .build()
            .map_err(|e| RustSafeProcessMgmtError::ValidationError {
                reason: format!("kill: failed to build options: {e}"),
            })?;

    let killed = pm.safe_kill(cedar_auth, kill_options).map_err(|e| {
        RustSafeProcessMgmtError::ValidationError {
            reason: format!("kill: {e}"),
        }
    })?;

    Ok(killed
        .into_iter()
        .map(|(name, pid)| (name, i64::from(pid)))
        .collect())
}

#[cfg(target_os = "linux")]
fn signal_from_number(num: i64) -> Result<rustix::process::Signal, RustSafeProcessMgmtError> {
    use rustix::process::Signal;
    match num {
        1 => Ok(Signal::HUP),
        9 => Ok(Signal::KILL),
        15 => Ok(Signal::TERM),
        3 => Ok(Signal::QUIT),
        _ => Err(RustSafeProcessMgmtError::ValidationError {
            reason: format!("kill: unsupported signal number {num}"),
        }),
    }
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::unnecessary_wraps, unused_variables)]
pub(crate) fn kill(
    pid: i64,
    cedar_auth: &CedarAuth,
) -> Result<Vec<(String, i64)>, RustSafeProcessMgmtError> {
    Err(RustSafeProcessMgmtError::ValidationError {
        reason: "kill: only supported on Linux".to_string(),
    })
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::unnecessary_wraps, unused_variables)]
pub(crate) fn kill_with_flags(
    pid: i64,
    flags_arr: &Array,
    cedar_auth: &CedarAuth,
) -> Result<Vec<(String, i64)>, RustSafeProcessMgmtError> {
    Err(RustSafeProcessMgmtError::ValidationError {
        reason: "kill: only supported on Linux".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rhai::Dynamic;

    /// Given: A set of KillFlag values
    /// When: Parsing KillOptions
    /// Then: The signal is captured correctly
    #[test]
    fn test_kill_options_from_flags() {
        let flags = vec![KillFlag::Signal(9)];
        let opts = KillOptions::from_flags(&flags);
        assert_eq!(opts.signal, 9);
    }

    /// Given: No flags provided
    /// When: Parsing KillOptions
    /// Then: Default signal is SIGTERM (15)
    #[test]
    fn test_kill_options_default_signal() {
        let opts = KillOptions::from_flags(&[]);
        assert_eq!(opts.signal, 15);
    }

    /// Given: An array with a non-KillFlag element
    /// When: Extracting flags
    /// Then: An error is returned
    #[test]
    fn test_kill_rejects_wrong_flag_type() {
        let arr: Array = vec![Dynamic::from("not_a_flag")];
        let result = extract_flags::<KillFlag>(&arr);
        assert!(result.is_err());
    }

    #[cfg(target_os = "linux")]
    /// Given: A valid signal number on Linux
    /// When: Converting to Signal enum
    /// Then: The correct Signal variant is returned
    #[test]
    fn test_signal_from_number_valid() {
        assert!(signal_from_number(15).is_ok());
        assert!(signal_from_number(9).is_ok());
        assert!(signal_from_number(1).is_ok());
        assert!(signal_from_number(3).is_ok());
    }

    #[cfg(target_os = "linux")]
    /// Given: An unsupported signal number on Linux
    /// When: Converting to Signal enum
    /// Then: An error is returned
    #[test]
    fn test_signal_from_number_invalid() {
        assert!(signal_from_number(999).is_err());
    }
}
