use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::fs::entities::DirEntity;

use std::path::{Path, PathBuf};

use crate::errors::RustSafeIoError;
use crate::options::DeleteDirOptions;
use crate::{RcDirHandle, auth::is_authorized};

impl RcDirHandle {
    /// Deletes a directory using the [`RcDirHandle`] reference created by [`crate::dir::DirConfig::safe_open`]
    ///
    /// # Arguments
    ///
    /// * `cedar_auth` - The Cedar authorization instance
    /// * `delete_dir_options` - [`DeleteDirOptions`] that has the configurations for deleting a directory
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The principal doesn't have permission to delete the directory
    /// * If directory cannot be opened (e.g., due to symlinks) or does not exist with [`DeleteDirOptions::force`] = false, an error [`std::io::ErrorKind`] is thrown.
    /// * If [`DeleteDirOptions::recursive`] = false and directory that is being deleted is not empty an error will be returned from `anyhow` [`anyhow::Error`] crate.
    /// * If file type [`std::fs::DirEntry::file_type`] cannot be recognized, an error [`std::io::ErrorKind`] is thrown by `file_type`.
    /// * If the file type [`std::fs::DirEntry::file_type`] cannot be removed by `remove_file` [`std::fs::remove_file`] then an error [`std::io::ErrorKind`] will be returned.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_safe_io::DirConfigBuilder;
    /// use rust_safe_io::options::{OpenDirOptionsBuilder, DeleteDirOptionsBuilder};
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    ///
    /// let dir_config = DirConfigBuilder::default()
    ///     .path("/tmp/rex".to_string())
    ///     .build().unwrap();
    ///
    /// let dir_handle = dir_config.safe_open(&cedar_auth, OpenDirOptionsBuilder::default().create(true).recursive(true).build().unwrap()).unwrap();
    /// dir_handle.safe_delete(&cedar_auth, DeleteDirOptionsBuilder::default().force(true).recursive(true).build().unwrap()).unwrap();
    /// ```
    pub fn safe_delete(
        &self,
        cedar_auth: &CedarAuth,
        delete_dir_options: DeleteDirOptions,
    ) -> Result<(), RustSafeIoError> {
        let dir_path = &self.dir_handle.dir_config.path;
        let entity = &DirEntity::new(Path::new(dir_path))?;
        is_authorized(
            cedar_auth,
            &FilesystemAction::Delete,
            // Add check to see if we are using fields that are exposed and are unsafe.
            entity,
        )?;

        let dir_handle = self.dir_handle.dir.try_clone()?;

        let result = if delete_dir_options.recursive {
            dir_handle.remove_open_dir_all()
        } else {
            dir_handle.remove_open_dir()
        };

        match result {
            Ok(()) => Ok(()),
            Err(e) => match e.kind() {
                std::io::ErrorKind::NotFound => {
                    if delete_dir_options.force {
                        Ok(())
                    } else {
                        Err(RustSafeIoError::NotFound {
                            path: PathBuf::from(&dir_path),
                            source: Box::new(e),
                        })
                    }
                }
                std::io::ErrorKind::DirectoryNotEmpty => Err(RustSafeIoError::DirectoryNotEmpty {
                    path: PathBuf::from(&dir_path),
                    source: Box::new(e),
                }),
                _ => Err(RustSafeIoError::DirectoryError {
                    reason: "Error removing directory".to_string(),
                    path: PathBuf::from(&dir_path),
                    source: Box::new(e),
                }),
            },
        }
    }
}
