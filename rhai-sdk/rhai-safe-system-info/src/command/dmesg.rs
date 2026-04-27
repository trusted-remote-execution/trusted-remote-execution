//! `dmesg` — Kernel ring buffer messages (Linux only)
//!
//! # Example (Rhai)
//! ```rhai
//! let entries = dmesg();
//! for entry in entries {
//!     print(`[${entry.timestamp_from_system_start}] ${entry.message}`);
//! }
//! ```

use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::Array;

/// Returns kernel log entries as an array of `DmesgEntry` structs (Linux only).
#[cfg(target_os = "linux")]
pub(crate) fn dmesg(cedar_auth: &CedarAuth) -> Result<Array, String> {
    use rhai::Dynamic;
    use rust_safe_system_info::{DmesgOptionsBuilder, SystemInfo};

    let sysinfo = SystemInfo::new().map_err(|e| e.to_string())?;
    let options = DmesgOptionsBuilder::default()
        .build()
        .map_err(|e| e.to_string())?;
    let entries = sysinfo
        .dmesg_info(cedar_auth, options)
        .map_err(|e| e.to_string())?;

    Ok(entries.into_iter().map(Dynamic::from).collect())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn dmesg(_cedar_auth: &CedarAuth) -> Result<Array, String> {
    Err("dmesg is only supported on Linux".to_string())
}
