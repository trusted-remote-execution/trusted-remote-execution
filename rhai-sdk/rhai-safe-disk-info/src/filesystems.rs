#![deny(missing_docs)]
#![cfg(unix)]
#![allow(
    unused_variables,
    unreachable_code,
    clippy::unreachable,
    unused_mut,
    clippy::needless_pass_by_value,
    dead_code,
    clippy::unused_self,
    clippy::trivially_copy_pass_by_ref
)]
//! The functions used here are declared in the `RustSysinfo` package.

use anyhow::Result;
use rhai::Array;
use rhai::EvalAltResult;
#[cfg(target_os = "linux")]
use rust_safe_disk_info::UnmountOptions;
use rust_safe_disk_info::{FilesystemOptions, IoStatSnapshot};

/// Query mounted filesystems, disk usage, and I/O statistics.
#[derive(Clone, Debug, Copy)]
pub struct Filesystems;

impl Filesystems {
    /// Creates a new [`rust_safe_disk_info::Filesystems`] instance
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::sysinfo::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// #     &mut scope,
    /// #     r#"
    /// let options = FilesystemOptions().local(true).build();
    /// let filesystems = Filesystems(options);
    /// #     "#);
    /// #
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    pub fn new(fs_opts: FilesystemOptions) -> Self {
        unreachable!("This method exists only for documentation.")
    }

    /// Gets filesystem information matching the provided options
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"read"` | [`file_system::File`](cedar_auth::fs::entities::FileEntity) |
    ///
    /// NB: Files are `/proc/mounts` and `/proc/diskstats`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// # use rex_test_utils::rhai::sysinfo::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// #     &mut scope,
    /// #     r#"
    /// let options = FilesystemOptions()
    ///     .local(true)
    ///     .targets(["/dev", "/tmp"])
    ///     .build();
    /// let filesystems = Filesystems(options);
    /// let fs_list = filesystems.filesystems();
    /// for fs in fs_list {
    ///     print(fs.mounted_on + ": " + fs.block_use_percent + "% used");
    /// }
    /// #     "#);
    /// #
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[doc(alias = "df")]
    #[doc(alias = "findmnt")]
    pub fn filesystems(&self) -> Result<Array, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Gets a snapshot of I/O statistics for CPU and block devices
    ///
    /// Returns CPU utilization statistics and per-device I/O statistics,
    /// similar to the `iostat -x` command.
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"read"` | [`file_system::File`](cedar_auth::fs::entities::FileEntity) |
    ///
    /// NB: Files are `/proc/stat` and `/proc/diskstats`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use rex_test_utils::rhai::sysinfo::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// #     &mut scope,
    /// #     r#"
    /// let options = FilesystemOptions().build();
    /// let filesystems = Filesystems(options);
    /// let snapshot = filesystems.iostat();
    ///
    /// // CPU statistics
    /// let cpu = snapshot.cpu_stats;
    /// print(`CPU: user=${cpu.user_percent}% system=${cpu.system_percent}% idle=${cpu.idle_percent}%`);
    ///
    /// // Per-device I/O statistics
    /// for device in snapshot.device_stats {
    ///     print(`${device.device_name}: r/s=${device.read_requests_per_sec} w/s=${device.write_requests_per_sec} util=${device.util_percent}%`);
    /// }
    /// #     "#);
    /// #
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    pub fn iostat(&self) -> Result<IoStatSnapshot, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }
}

/// Unmounts a filesystem at the specified path with Cedar authorization
///
/// This function unmounts the filesystem at the specified path after performing Cedar
/// authorization checks. This API will fail if the path provided is a symlink.
///
/// # Cedar Permissions
///
/// | Action | Resource |
/// |--------|----------|
/// | `file_system::Action::"unmount"` | [`file_system::Dir`](cedar_auth::fs::entities::DirEntity) |
///
/// NB: Resource is the mount path passed to `unmount()`.
///
/// # Linux Capabilities
///
/// | Capability | Condition |
/// |------------|-----------|
/// | `CAP_SYS_ADMIN` | Always required |
///
/// # Example
///
/// ```
/// # use rex_test_utils::rhai::sysinfo::create_temp_test_env;
/// # let (mut scope, engine) = create_temp_test_env();
/// # let result = engine.eval_with_scope::<()>(
/// #     &mut scope,
/// #     r#"
/// let options = UnmountOptions()
///     .path("/mnt/data")
///     .build();
/// unmount(options);
/// print("Successfully unmounted /mnt/data");
/// #     "#);
/// ```
#[cfg(target_os = "linux")]
#[doc(alias = "umount")]
pub fn unmount(options: UnmountOptions) -> Result<(), Box<EvalAltResult>> {
    unreachable!("This function exists only for documentation.")
}
