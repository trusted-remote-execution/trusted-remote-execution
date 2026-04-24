use crate::errors::RustSafeIoError;
use crate::is_authorized;
use crate::options::DiskAllocationOptions;
use anyhow::Result;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::fs::entities::FileEntity;
use rustix::fs::{FallocateFlags, fallocate};

use crate::RcFileHandle;

impl RcFileHandle {
    /// Initializes bytes on disk by preallocating disk space for the file.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rust_safe_io::{DirConfigBuilder, DiskAllocationOptionsBuilder};
    /// # use rust_safe_io::options::{OpenDirOptionsBuilder, OpenFileOptionsBuilder, SizeUnit};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// #
    /// # let cedar_auth = CedarAuth::new("", "", "").unwrap().0;
    /// let dir_config = DirConfigBuilder::default()
    ///     .path("/tmp".to_string())
    ///     .build().unwrap();
    /// let dir_handle = dir_config.safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap()).unwrap();
    ///
    /// // Create and preallocate a 10 GB swap file
    /// let file = dir_handle.safe_open_file(
    ///     &cedar_auth,
    ///     "swapfile",
    ///     OpenFileOptionsBuilder::default().create(true).build().unwrap()
    /// ).unwrap();
    ///
    /// let options = DiskAllocationOptionsBuilder::default()
    ///     .length(10)
    ///     .format(SizeUnit::Gigabytes)
    ///     .build()
    ///     .unwrap();
    ///
    /// file.safe_initialize_bytes_on_disk(&cedar_auth, options).unwrap();
    /// ```
    #[allow(clippy::cast_sign_loss)]
    pub fn safe_initialize_bytes_on_disk(
        &self,
        cedar_auth: &CedarAuth,
        options: DiskAllocationOptions,
    ) -> Result<(), RustSafeIoError> {
        is_authorized(
            cedar_auth,
            &FilesystemAction::Write,
            &FileEntity::from_string_path(&self.full_path())?,
        )?;

        self.validate_write_open_option()?;

        let length_bytes = options.format.to_bytes(options.length) as u64;

        fallocate(
            &self.file_handle.file,
            FallocateFlags::empty(),
            0,
            length_bytes,
        )?;

        Ok(())
    }
}
