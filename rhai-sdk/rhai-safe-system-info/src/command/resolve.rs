//! `resolve` — DNS hostname resolution
//!
//! # Example (Rhai)
//! ```rhai
//! let ips = resolve("example.com");
//! for ip in ips { print(ip); }
//! ```

use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::Array;

/// Resolves a hostname to IP addresses.
#[cfg(target_os = "linux")]
pub(crate) fn resolve(hostname: &str, cedar_auth: &CedarAuth) -> Result<Array, String> {
    use rhai::Dynamic;
    use rust_safe_system_info::{ResolveConfigBuilder, SystemInfo};

    let sysinfo = SystemInfo::new().map_err(|e| e.to_string())?;
    let config = ResolveConfigBuilder::default()
        .hostname(hostname)
        .build()
        .map_err(|e| e.to_string())?;
    let ips = sysinfo
        .resolve(cedar_auth, config)
        .map_err(|e| e.to_string())?;
    Ok(ips.into_iter().map(Dynamic::from).collect())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn resolve(_hostname: &str, _cedar_auth: &CedarAuth) -> Result<Array, String> {
    Err("resolve is only supported on Linux".to_string())
}
