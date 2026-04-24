//! `iostat` — I/O statistics snapshot
//!
//! # Example (Rhai)
//! ```rhai
//! let stats = iostat();
//! print(`CPU idle: ${stats.cpu_stats.idle_percent}%`);
//! for dev in stats.device_stats {
//!     print(`${dev.device_name}: ${dev.util_percent}% util`);
//! }
//! ```

use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::Dynamic;

/// Returns I/O statistics as an `IoStatSnapshot` struct.
#[cfg(target_os = "linux")]
pub(crate) fn iostat(cedar_auth: &CedarAuth) -> Result<Dynamic, String> {
    use rust_disk_info::{FilesystemOptionsBuilder, Filesystems};

    let fs_opts = FilesystemOptionsBuilder::default()
        .build()
        .map_err(|e| e.to_string())?;
    let fss = Filesystems::new(fs_opts);
    let snapshot = fss.iostat(cedar_auth).map_err(|e| e.to_string())?;

    Ok(Dynamic::from(snapshot))
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn iostat(_cedar_auth: &CedarAuth) -> Result<Dynamic, String> {
    Err("iostat is only supported on Linux".to_string())
}
