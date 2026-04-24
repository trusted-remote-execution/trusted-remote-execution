use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::fs::entities::FileEntity;

use anyhow::Result;
use cap_fs_ext::OsMetadataExt;

use crate::errors::RustSafeIoError;
use crate::{Metadata, RcFileHandle, is_authorized};

impl RcFileHandle {
    /// Retrieves metadata for the file.
    ///
    /// This method fetches metadata information about the file, including size, permissions,
    /// modification times, and other file attributes.
    ///
    /// # Errors
    /// Returns an error if:
    /// * The principal doesn't have permission to access the file metadata
    /// * The file metadata cannot be retrieved
    ///
    /// # Example
    /// ```no_run
    /// use rust_safe_io::DirConfigBuilder;
    /// use rust_safe_io::options::{OpenDirOptionsBuilder, OpenFileOptionsBuilder};
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    ///
    /// let dir_path = "/tmp";
    /// let file_path = "file.txt";
    /// let dir_handle = DirConfigBuilder::default()
    ///     .path(dir_path.to_string())
    ///     .build().unwrap()
    ///     .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap())
    ///     .unwrap();
    /// let file_handle = dir_handle.safe_open_file(
    ///     &cedar_auth,
    ///     file_path,
    ///     OpenFileOptionsBuilder::default().read(true).build().unwrap()
    /// ).unwrap();
    /// let metadata = file_handle.metadata(&cedar_auth).unwrap();
    /// println!("File size: {}", metadata.cap_std_metadata().len());
    /// ```
    pub fn metadata(&self, cedar_auth: &CedarAuth) -> Result<Metadata, RustSafeIoError> {
        let file_entity = &FileEntity::from_string_path(&self.full_path())?;
        is_authorized(cedar_auth, &FilesystemAction::Stat, file_entity)?;
        let metadata = Metadata::from_cap_std_metadata(self.file_handle.file.metadata()?)?;

        Ok(metadata)
    }

    /// Gets the last modified time of a file.
    ///
    /// # Returns
    /// * `Result<i64>` - The last modified time as nanoseconds since Unix epoch (January 1, 1970 UTC)
    ///
    /// # Errors
    /// Returns an error if:
    /// * The principal doesn't have permission to access the file metadata
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_safe_io::DirConfigBuilder;
    /// use rust_safe_io::options::{OpenDirOptionsBuilder, OpenFileOptionsBuilder};
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    ///
    /// let dir_path = "/tmp";
    /// let file_path = "file.txt";
    /// let dir_handle = DirConfigBuilder::default()
    ///     .path(dir_path.to_string())
    ///     .build().unwrap()
    ///     .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap())
    ///     .unwrap();
    /// let file_handle = dir_handle.safe_open_file(&cedar_auth, file_path, OpenFileOptionsBuilder::default().build().unwrap()).unwrap();
    /// let modified_time = file_handle.safe_get_last_modified_time(&cedar_auth).unwrap();
    /// ```
    #[cfg(unix)]
    pub fn safe_get_last_modified_time(
        &self,
        cedar_auth: &CedarAuth,
    ) -> Result<i64, RustSafeIoError> {
        is_authorized(
            cedar_auth,
            &FilesystemAction::Stat,
            &FileEntity::from_string_path(&self.full_path())?,
        )?;

        let file = &self.file_handle.file;
        let metadata = file.metadata()?;

        // The file's modification time is represented by two separate values: mtime() provides
        // the seconds since Unix epoch, while mtime_nsec() provides just the nanosecond component
        // within that second. To get the complete nanosecond-precision timestamp, we convert the
        // seconds to nanoseconds by multiplying by 10^9, then add the nanosecond component.
        let seconds_as_nanos = metadata.mtime() * 1_000_000_000;
        let nanos_component = metadata.mtime_nsec();

        Ok(seconds_as_nanos + nanos_component)
    }
}
