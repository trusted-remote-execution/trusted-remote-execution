//! `hostname` — Return the system hostname
//!
//! # Example (Rhai)
//! ```rhai
//! let name = hostname();
//! print(`Host: ${name}`);
//! ```

use rex_cedar_auth::cedar_auth::CedarAuth;

/// Returns the system hostname as a string.
#[cfg(target_os = "linux")]
pub(crate) fn hostname(cedar_auth: &CedarAuth) -> Result<String, String> {
    use rust_system_info::SystemInfo;

    let sysinfo = SystemInfo::new().map_err(|e| e.to_string())?;
    sysinfo.hostname(cedar_auth).map_err(|e| e.to_string())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn hostname(_cedar_auth: &CedarAuth) -> Result<String, String> {
    Err("hostname is only supported on Linux".to_string())
}
