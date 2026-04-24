//! `df` — Report filesystem disk space usage
//!
//! # Example (Rhai)
//! ```rhai
//! let filesystems = df();
//! for fs in filesystems {
//!     print(`${fs.mounted_on}: ${fs.block_use_percent}% used`);
//! }
//! ```

use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::Array;

/// Returns filesystem disk space usage as an array of `Filesystem` structs.
#[cfg(target_os = "linux")]
pub(crate) fn df(cedar_auth: &CedarAuth) -> Result<Array, String> {
    use rhai::Dynamic;
    use rust_disk_info::{FilesystemOptionsBuilder, Filesystems};

    let fs_opts = FilesystemOptionsBuilder::default()
        .build()
        .map_err(|e| e.to_string())?;
    let fss = Filesystems::new(fs_opts);
    let filesystems = fss.filesystems(cedar_auth).map_err(|e| e.to_string())?;

    Ok(filesystems.into_iter().map(Dynamic::from).collect())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn df(_cedar_auth: &CedarAuth) -> Result<Array, String> {
    Err("df is only supported on Linux".to_string())
}
