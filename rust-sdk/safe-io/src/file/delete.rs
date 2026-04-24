use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::fs::entities::FileEntity;

use std::path::PathBuf;

use crate::errors::RustSafeIoError;
use crate::options::DeleteFileOptions;
use crate::{RcFileHandle, build_path, is_authorized};

impl RcFileHandle {
    /// Deletes a file using the [`RcFileHandle`] reference created by [`crate::dir::RcDirHandle::safe_open_file`]
    ///
    /// # Arguments
    ///
    /// * `cedar_auth` - The Cedar authorization instance
    /// * `delete_file_options` - [`DeleteFileOptions`] that has the configurations for deleting a file
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The principal doesn't have permission to delete the file
    /// * Throws an error when [`cap_std::fs::Dir`] or [`cap_std::fs::File`] does not exist and `force` = false is selected.
    /// * If the file type [`std::fs::DirEntry::file_type`] cannot be removed by [`std::fs::remove_file`] then an error [`std::io::ErrorKind`] will be returned.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_safe_io::DirConfigBuilder;
    /// use rust_safe_io::options::{OpenDirOptionsBuilder, OpenFileOptionsBuilder, DeleteFileOptionsBuilder};
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
    ///     .build().unwrap().safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap()).unwrap();
    /// let file_handle = dir_handle.safe_open_file(&cedar_auth, &file_path, OpenFileOptionsBuilder::default().build().unwrap()).unwrap();
    /// file_handle.safe_delete(&cedar_auth, DeleteFileOptionsBuilder::default().force(true).build().unwrap());
    /// ```
    pub fn safe_delete(
        &self,
        cedar_auth: &CedarAuth,
        delete_file_options: DeleteFileOptions,
    ) -> Result<(), RustSafeIoError> {
        let file_name = self.path();
        let dir_handle = &self.file_handle.dir_handle.dir;
        let dir_path = self.dir_path();
        let original_path = build_path(dir_path, file_name);
        is_authorized(
            cedar_auth,
            &FilesystemAction::Delete,
            &FileEntity::from_string_path(&original_path)?,
        )?;

        match dir_handle.remove_file(file_name) {
            Ok(()) => Ok(()),
            Err(e) => match e.kind() {
                std::io::ErrorKind::NotFound => {
                    if delete_file_options.force {
                        Ok(())
                    } else {
                        Err(RustSafeIoError::NotFound {
                            path: PathBuf::from(&dir_path),
                            source: Box::new(e),
                        })
                    }
                }
                _ => Err(RustSafeIoError::FileError {
                    reason: "Error removing file".to_string(),
                    path: PathBuf::from(&dir_path),
                    source: Box::new(e),
                }),
            },
        }
    }
}
