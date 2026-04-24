use crate::RcFileHandle;
use crate::constants::BLOCK_SIZE_BYTES;
use crate::dir::DiskUsageEntry;
use crate::errors::RustSafeIoError;
use crate::options::DiskUsageOptions;
use rex_cedar_auth::cedar_auth::CedarAuth;

impl RcFileHandle {
    /// Calculates disk usage for a file
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rust_safe_io::DirConfigBuilder;
    /// # use rust_safe_io::options::{OpenDirOptionsBuilder, OpenFileOptionsBuilder, DiskUsageOptionsBuilder};
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    ///
    /// let dir_handle = DirConfigBuilder::default()
    ///     .path("/tmp".to_string())
    ///     .build().unwrap()
    ///     .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap()).unwrap();
    ///
    /// let file_handle = dir_handle.safe_open_file(
    ///     &cedar_auth,
    ///     "test.txt",
    ///     OpenFileOptionsBuilder::default().read(true).build().unwrap()
    /// ).unwrap();
    ///
    /// let options = DiskUsageOptionsBuilder::default().build().unwrap();
    /// let results = file_handle.safe_disk_usage(&cedar_auth, options).unwrap();
    /// ```
    pub fn safe_disk_usage(
        &self,
        cedar_auth: &CedarAuth,
        options: DiskUsageOptions,
    ) -> Result<DiskUsageEntry, RustSafeIoError> {
        let metadata = self.metadata(cedar_auth)?;

        let size_bytes = if options.apparent_size {
            let size = metadata.file_size()?;
            u64::try_from(size)?
        } else {
            let blocks = metadata.blocks()?;
            u64::try_from(blocks * BLOCK_SIZE_BYTES)?
        };

        Ok(DiskUsageEntry::new(self.full_path(), size_bytes, 1))
    }
}
