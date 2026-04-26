use crate::df::{Df, FilesystemProvider};
use crate::iostat::IoStat;
use crate::iostat::IoStatProvider;
use crate::{Filesystem, FilesystemOptions, IoStatSnapshot, RustDiskinfoError};
use rex_cedar_auth::cedar_auth::CedarAuth;

#[derive(Debug, Clone)]
pub struct Filesystems {
    config: FilesystemOptions,
    df: Df,
    iostat: IoStat,
}

impl Filesystems {
    pub const fn new(fs_opts: FilesystemOptions) -> Self {
        Filesystems {
            config: fs_opts,
            df: Df,
            iostat: IoStat,
        }
    }

    /// Get all filesystems matching the configuration
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use rust_safe_disk_info::{FilesystemOptionsBuilder, Filesystems};
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_schema, get_test_rex_principal};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// #
    /// # let principal = get_test_rex_principal();
    /// # let policy = format!(r#"permit(principal == User::"{}",action in ["get_mounts","file_system::get_inode_metadata"],resource);"#, principal);
    /// # let cedar_auth = CedarAuth::new(&policy, get_default_test_rex_schema(), "[]").unwrap().0;
    /// let fs_opts = FilesystemOptionsBuilder::default().build().unwrap();
    /// let fss = Filesystems::new(fs_opts);
    ///
    /// let filesystems = fss.filesystems(&cedar_auth).unwrap();
    /// for fs in filesystems {
    ///     println!("Mount: {} - {}% used", fs.mounted_on(), fs.block_use_percent());
    /// }
    /// ```
    pub fn filesystems(
        &self,
        cedar_auth: &CedarAuth,
    ) -> Result<Vec<Filesystem>, RustDiskinfoError> {
        self.df.get_filesystems(cedar_auth, &self.config)
    }

    /// Get I/O statistics snapshot
    ///
    /// This function provides iostat-like functionality, returning a single snapshot
    /// of system I/O statistical averages since system boot, equivalent to running
    /// `iostat -x`. The snapshot contains:
    /// - CPU utilization statistics (user, nice, system, iowait, steal, idle percentages)
    /// - Per-device I/O statistics (throughput, latency, utilization metrics)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use rust_safe_disk_info::{FilesystemOptionsBuilder, Filesystems};
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_schema, get_test_rex_principal};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// #
    /// # let principal = get_test_rex_principal();
    /// # let policy = format!(r#"permit(principal == User::"{}",action,resource);"#, principal);
    /// # let cedar_auth = CedarAuth::new(&policy, get_default_test_rex_schema(), "[]").unwrap().0;
    /// let fs_opts = FilesystemOptionsBuilder::default().build().unwrap();
    /// let fss = Filesystems::new(fs_opts);
    ///
    /// // Get I/O statistics snapshot (equivalent to: iostat -x)
    /// let snapshot = fss.iostat(&cedar_auth).unwrap();
    ///
    /// // Access CPU statistics
    /// println!("CPU Usage - User: {}%, System: {}%, I/O Wait: {}%",
    ///          snapshot.cpu_stats().user_percent(),
    ///          snapshot.cpu_stats().system_percent(),
    ///          snapshot.cpu_stats().iowait_percent());
    ///
    /// // Access device statistics
    /// for device in snapshot.device_stats() {
    ///     println!("Device: {} - Reads: {}/s, Writes: {}/s, Util: {}%",
    ///              device.device_name(),
    ///              device.read_requests_per_sec(),
    ///              device.write_requests_per_sec(),
    ///              device.util_percent());
    /// }
    /// ```
    pub fn iostat(&self, cedar_auth: &CedarAuth) -> Result<IoStatSnapshot, RustDiskinfoError> {
        self.iostat.get_snapshot(cedar_auth)
    }
}
