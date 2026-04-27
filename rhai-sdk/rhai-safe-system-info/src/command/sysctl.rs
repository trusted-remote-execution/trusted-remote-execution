//! `sysctl` — Read/write/find kernel parameters (Linux only)
//!
//! # Example (Rhai)
//! ```rhai
//! let val = sysctl_read("kernel.hostname");
//! let entries = sysctl_find("net.ipv4");
//! sysctl_write("net.ipv4.ip_forward", "1");
//! ```

use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::Array;
#[cfg(target_os = "linux")]
use rhai::{Dynamic, Map};

#[cfg(target_os = "linux")]
use rust_safe_system_info::SysctlManager;

/// Read a kernel parameter value.
#[cfg(target_os = "linux")]
pub(crate) fn sysctl_read(key: &str, cedar_auth: &CedarAuth) -> Result<String, String> {
    let mgr = SysctlManager::new().map_err(|e| e.to_string())?;
    mgr.read(cedar_auth, key).map_err(|e| e.to_string())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn sysctl_read(_key: &str, _cedar_auth: &CedarAuth) -> Result<String, String> {
    Err("sysctl is only supported on Linux".to_string())
}

/// Find kernel parameters matching a regex pattern.
#[cfg(target_os = "linux")]
pub(crate) fn sysctl_find(pattern: &str, cedar_auth: &CedarAuth) -> Result<Array, String> {
    let mgr = SysctlManager::new().map_err(|e| e.to_string())?;
    let entries = mgr.find(cedar_auth, pattern).map_err(|e| e.to_string())?;

    Ok(entries
        .into_iter()
        .map(|entry| {
            let mut m = Map::new();
            m.insert("key".into(), Dynamic::from(entry.key().clone()));
            m.insert("value".into(), Dynamic::from(entry.value().clone()));
            Dynamic::from(m)
        })
        .collect())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn sysctl_find(_pattern: &str, _cedar_auth: &CedarAuth) -> Result<Array, String> {
    Err("sysctl is only supported on Linux".to_string())
}

/// Write a kernel parameter value.
#[cfg(target_os = "linux")]
pub(crate) fn sysctl_write(key: &str, value: &str, cedar_auth: &CedarAuth) -> Result<(), String> {
    let mgr = SysctlManager::new().map_err(|e| e.to_string())?;
    mgr.write(cedar_auth, key, value).map_err(|e| e.to_string())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn sysctl_write(
    _key: &str,
    _value: &str,
    _cedar_auth: &CedarAuth,
) -> Result<(), String> {
    Err("sysctl is only supported on Linux".to_string())
}
