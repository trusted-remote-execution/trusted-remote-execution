use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::fs::entities::FileEntity;

use anyhow::Result;
use std::io::Write;

use crate::errors::RustSafeIoError;
use crate::{RcFileHandle, is_authorized};

impl RcFileHandle {
    /// Unix-specific: Non-atomic write to an opened file. This is less safe to use than
    /// `RcFileHandle::safe_write`, since interrupting the write can cause file corruption.
    /// It's therefore recommended to try the atomic write first. If that fails due to storage full,
    /// this method can be used to write to the file, as long as the new contents are smaller than
    /// 1 filesystem block.
    ///
    /// This function asserts the same [`FilesystemAction::Write`] permission as the atomic
    /// `RcFileHandle::safe_write` implementation.
    ///
    /// This method assumes the caller opened the file with the `OpenFileOption.write` set to true.
    ///
    /// # Arguments
    ///
    /// * `cedar_auth` - The Cedar authorization instance
    /// * `content` - Content to write
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The principal doesn't have permission to write to the file
    /// * The file does not exist, or otherwise is invalid for writing
    /// * The file is not opened with the write flag
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
    ///
    /// let file_handle = dir_handle.safe_open_file(&cedar_auth,
    ///     file_path,
    ///     OpenFileOptionsBuilder::default().write(true).build().unwrap()).unwrap();
    ///
    /// file_handle.safe_write_in_place(&cedar_auth, "FileContents").unwrap();
    /// ```
    pub fn safe_write_in_place(
        &self,
        cedar_auth: &CedarAuth,
        content: &str,
    ) -> Result<(), RustSafeIoError> {
        is_authorized(
            cedar_auth,
            &FilesystemAction::Write,
            &FileEntity::from_string_path(&self.full_path())?,
        )?;

        // The write will fail anyway if we don't add the following check, but this improves the error message from "Bad file descriptor"
        // to "Attempted to write a file without opening it with the write option."
        self.validate_write_open_option()?;

        let mut file = &self.file_handle.file;
        let bytes = content.as_bytes();
        let content_size = bytes.len() as u64;

        file.write_all(bytes)?;

        // Skip truncate/sync/rewind for special files (e.g., /proc/sys)
        // The kernel handles these operations automatically for special files
        if self.validate_special_file_option().is_ok() {
            // truncate the file: if the new contents are shorter than the old contents, we won't get any remnants of the old contents left over.
            file.set_len(content_size)?;
            file.sync_all()?; // fsync
            self.rewind()?; // Rewind the file to the beginning so that the next reader or writer starts from the beginning instead of the end.
        }

        Ok(())
    }
}
