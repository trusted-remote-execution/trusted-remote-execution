use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::fs::entities::FileEntity;

use anyhow::Result;

use cap_tempfile::TempFile;
use std::rc::Rc;
use std::{io::Seek, io::Write};

#[cfg(target_os = "linux")]
use cap_fs_ext::OsMetadataExt;
#[cfg(target_os = "linux")]
use rustix::fs::{Gid, Uid};

#[cfg(target_os = "linux")]
use crate::chown_fd;
use crate::errors::RustSafeIoError;
use crate::options::WriteOptions;
use crate::{FileHandle, RcFileHandle, is_authorized};

impl RcFileHandle {
    /// Writes a string into an opened file atomically with default options.
    ///
    /// This is a convenience function for [`safe_write_with_options`](Self::safe_write_with_options)
    /// with default [`WriteOptions`].
    pub fn safe_write(
        &self,
        cedar_auth: &CedarAuth,
        content: &str,
    ) -> Result<RcFileHandle, RustSafeIoError> {
        self.safe_write_with_options(cedar_auth, content, WriteOptions::default())
    }

    /// Writes a string into an opened file atomically with configurable options.
    ///
    /// The file is atomically written by creating a temporary file that is then
    /// moved using `renameat2` (implemented by cap-std's [`TempFile::replace`] and
    /// is OS agnostic). After writing, a new file handle is returned that points to the new file.
    /// The new file will have the same file permissions as the original file.
    ///
    /// By default, the write attempts to preserve the original file's ownership (uid/gid).
    /// This requires `CAP_CHOWN` when the file is owned by a different user. To disable
    /// this behavior and let the file be owned by the current user and group, set
    /// [`preserve_ownership(false)`](WriteOptions::preserve_ownership) in [`WriteOptions`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_safe_io::DirConfigBuilder;
    /// use rust_safe_io::options::{OpenDirOptionsBuilder, OpenFileOptionsBuilder, WriteOptionsBuilder};
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
    /// let write_options = WriteOptionsBuilder::default().preserve_ownership(false).build().unwrap();
    /// let file_handle = file_handle.safe_write_with_options(&cedar_auth, "RandomStringAsFileContent", write_options).unwrap();
    /// ```
    pub fn safe_write_with_options(
        &self,
        cedar_auth: &CedarAuth,
        content: &str,
        #[allow(unused_variables)] write_options: WriteOptions, // not used for MacOS
    ) -> Result<RcFileHandle, RustSafeIoError> {
        is_authorized(
            cedar_auth,
            &FilesystemAction::Write,
            &FileEntity::from_string_path(&self.full_path())?,
        )?;

        // Reject special_file flag for atomic writes
        self.validate_special_file_option()?;

        // Although strictly speaking write mode isn't needed for an atomic write, we check it for consistency with non-atomic write in place.
        self.validate_write_open_option()?;

        let dir_handle = &self.file_handle.dir_handle.dir;
        let file = &self.file_handle.file;

        let mut temp_file = TempFile::new(dir_handle)?;
        let existing_metadata = file.metadata()?;

        temp_file
            .as_file()
            .set_permissions(existing_metadata.permissions())?;

        #[cfg(target_os = "linux")]
        if write_options.preserve_ownership {
            chown_fd(
                temp_file.as_file(),
                Some(Uid::from_raw(existing_metadata.uid())),
                Some(Gid::from_raw(existing_metadata.gid())),
            )?;
        }

        temp_file.write_all(content.as_bytes())?;
        temp_file.as_file().sync_all()?;
        temp_file.rewind()?;

        let cloned_fd = temp_file.as_file().try_clone()?;

        temp_file.replace(self.path())?;

        let new_file_handle = FileHandle {
            file: cloned_fd,
            file_path: self.file_handle.file_path.clone(),
            resolved_path: self.file_handle.resolved_path.clone(),
            dir_handle: Rc::clone(&self.file_handle.dir_handle),
            open_options: self.file_handle.open_options,
        };

        Ok(RcFileHandle {
            file_handle: Rc::new(new_file_handle),
        })
    }
}
