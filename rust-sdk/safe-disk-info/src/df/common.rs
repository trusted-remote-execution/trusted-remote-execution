use crate::{FilesystemOptions, RustDiskinfoError, Unit};
use derive_getters::Getters;
use rex_cedar_auth::cedar_auth::CedarAuth;
use serde::Serialize;

pub trait FilesystemProvider {
    /// Get all filesystems matching the configuration
    fn get_filesystems(
        &self,
        cedar_auth: &CedarAuth,
        config: &FilesystemOptions,
    ) -> Result<Vec<Filesystem>, RustDiskinfoError>;
}

#[derive(Debug, Clone, Getters, Serialize)]
pub struct Filesystem {
    /// Filesystem device (e.g., "devtmpfs", "tmpfs", "/dev/xdva1")
    fs_device: String,

    /// Filesystem kind (e.g., "ext4", "tmpfs")
    fs_kind: String,

    /// Total number of inodes
    inodes: u64,

    /// Number of used inodes
    iused: u64,

    /// Number of free inodes
    ifree: u64,

    /// Percentage of inodes used
    iuse_percent: f64,

    /// Number of used blocks
    block_used: u64,

    /// Number of available blocks
    block_available: u64,

    /// Percentage of blocks used
    block_use_percent: f64,

    /// Mount point path
    mounted_on: String,

    /// 1KB blocks
    kb_blocks: u64,

    /// 1MB blocks
    mb_blocks: u64,

    /// Raw size in bytes (defaults to 1024 bytes to match df)
    #[serde(rename(serialize = "size"))]
    raw_size: u64,

    /// Mount options (per-mount)
    mount_options: Vec<String>,
}

impl Filesystem {
    /// Create a new `Filesystem` instance
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        fs_device: String,
        fs_kind: String,
        inodes: u64,
        iused: u64,
        ifree: u64,
        iuse_percent: f64,
        block_used: u64,
        block_available: u64,
        block_use_percent: f64,
        mounted_on: String,
        kb_blocks: u64,
        mb_blocks: u64,
        raw_size: u64,
        mount_options: Vec<String>,
    ) -> Self {
        Self {
            fs_device,
            fs_kind,
            inodes,
            iused,
            ifree,
            iuse_percent,
            block_used,
            block_available,
            block_use_percent,
            mounted_on,
            kb_blocks,
            mb_blocks,
            raw_size,
            mount_options,
        }
    }

    /// Format a size value in bytes to the specified unit
    ///
    /// This function converts byte values to the requested unit using integer division.
    /// Users can call this on any size value returned by the filesystem methods.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rust_disk_info::{Filesystem, Unit};
    /// # let filesystem = Filesystem::new(
    /// #     "test".to_string(), "ext4".to_string(), 1000, 250, 750, 25.0,
    /// #     5000, 15000, 25.0, "/test".to_string(), 3000, 2, 20480000,
    /// #     vec!["rw".to_string()]
    /// # );
    ///
    /// // Convert filesystem size to megabytes
    /// let size_mb = Filesystem::format_bytes(*filesystem.raw_size(), Unit::Megabytes);
    ///
    /// // Convert used space to kilobytes
    /// let used_kb = Filesystem::format_bytes(*filesystem.block_used(), Unit::Kilobytes);
    /// ```
    pub const fn format_bytes(size: u64, unit: Unit) -> u64 {
        match unit {
            Unit::Bytes => size,
            Unit::Kilobytes => size / 1024,
            Unit::Megabytes => size / (1024 * 1024),
        }
    }
}
