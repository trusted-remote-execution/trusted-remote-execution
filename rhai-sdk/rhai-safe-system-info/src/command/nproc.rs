//! `nproc` — Return the number of available CPUs
//!
//! # Example (Rhai)
//! ```rhai
//! let cpus = nproc();
//! print(`CPUs: ${cpus}`);
//! ```

use rex_cedar_auth::cedar_auth::CedarAuth;

/// Returns the number of logical CPUs.
#[cfg(target_os = "linux")]
pub(crate) fn nproc(cedar_auth: &CedarAuth) -> Result<i64, String> {
    use rust_system_info::SystemInfo;

    let sysinfo = SystemInfo::new().map_err(|e| e.to_string())?;
    let count = sysinfo.cpu_count(cedar_auth).map_err(|e| e.to_string())?;
    #[allow(clippy::cast_possible_wrap)]
    Ok(count as i64)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn nproc(_cedar_auth: &CedarAuth) -> Result<i64, String> {
    Err("nproc is only supported on Linux".to_string())
}
