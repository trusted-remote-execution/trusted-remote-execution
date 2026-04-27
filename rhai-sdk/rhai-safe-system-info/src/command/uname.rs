//! `uname` — System information (Linux only)
//!
//! # Example (Rhai)
//! ```rhai
//! let info = uname();
//! print(`${info.kernel_name} ${info.nodename} ${info.kernel_release}`);
//! ```

use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::Dynamic;

/// Returns system information as an `UnameInfo` struct (Linux only).
#[cfg(target_os = "linux")]
pub(crate) fn uname(cedar_auth: &CedarAuth) -> Result<Dynamic, String> {
    let sysinfo = rust_safe_system_info::SystemInfo::new().map_err(|e| e.to_string())?;
    let info = sysinfo.uname_info(cedar_auth).map_err(|e| e.to_string())?;
    Ok(Dynamic::from(info))
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn uname(_cedar_auth: &CedarAuth) -> Result<Dynamic, String> {
    Err("uname is only supported on Linux".to_string())
}
