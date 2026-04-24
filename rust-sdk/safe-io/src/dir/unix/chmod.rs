use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::fs::entities::DirEntity;
use rex_logger::warn;

use cap_std::fs::PermissionsExt;
use std::path::Path;

use crate::auth::is_authorized;
use crate::errors::RustSafeIoError;
use crate::options::{
    ChmodDirOptions, DirWalkOptions, OpenDirOptionsBuilder, READ_ONLY_FILE_OPTIONS,
};
use crate::recursive::{DirWalk, WalkEntry};
use crate::{RcDirHandle, validate_permissions};

impl RcDirHandle {
    /// Changes the permissions of a directory
    ///
    /// Only supported for unix based platforms.
    ///
    /// Note: While Linux systems typically use capabilities like `CAP_FOWNER` to allow
    /// non-owners to change directory permissions, this implementation adds Cedar authorization
    /// as an additional security layer.
    ///
    /// # Arguments
    ///
    /// * `cedar_auth` - The Cedar authorization instance
    /// * `options` - [`ChmodDirOptions`] that has the configurations for changing directory permissions
    ///
    /// # Returns
    ///
    /// * `Result<()>` - Success or error
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The principal doesn't have permission to change directory permissions
    /// * The permissions value is invalid (greater than 0o777)
    /// * The directory permissions cannot be changed due to insufficient privileges
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_safe_io::DirConfigBuilder;
    /// use rust_safe_io::options::{OpenDirOptionsBuilder, ChmodDirOptionsBuilder};
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
    ///     .path("/tmp/test".to_string())
    ///     .build().unwrap()
    ///     .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap())
    ///     .unwrap();
    ///
    /// let options = ChmodDirOptionsBuilder::default()
    ///     .permissions(0o755)
    ///     .recursive(true)
    ///     .build().unwrap();
    /// dir_handle.safe_chmod(&cedar_auth, options).unwrap();
    /// ```
    pub fn safe_chmod(
        &self,
        cedar_auth: &CedarAuth,
        options: ChmodDirOptions,
    ) -> Result<(), RustSafeIoError> {
        if options.recursive {
            self.chmod_recursive_impl(cedar_auth, options)
        } else {
            self.chmod_single_impl(cedar_auth, options)
        }
    }

    /// Internal implementation for changing permissions on a single directory
    fn chmod_single_impl(
        &self,
        cedar_auth: &CedarAuth,
        options: ChmodDirOptions,
    ) -> Result<(), RustSafeIoError> {
        let dir_entity = &DirEntity::new(Path::new(&self.dir_handle.dir_config.path))?;
        is_authorized(cedar_auth, &FilesystemAction::Chmod, dir_entity)?;

        validate_permissions(u32::try_from(options.permissions)?)?;

        let new_permissions = PermissionsExt::from_mode(u32::try_from(options.permissions)?);
        self.dir_handle.dir.set_permissions(".", new_permissions)?;
        Ok(())
    }

    /// Internal implementation for recursively changing permissions on directory and all contents
    ///
    /// Uses `DirWalk` to traverse the directory tree with memoization and applies permissions to all directories
    /// and files encountered during traversal.
    fn chmod_recursive_impl(
        &self,
        cedar_auth: &CedarAuth,
        options: ChmodDirOptions,
    ) -> Result<(), RustSafeIoError> {
        // Process directory root
        if let Err(e) = self.chmod_single_impl(cedar_auth, options) {
            warn!(
                "Failed to chmod root directory '{}': {}",
                self.dir_handle.dir_config.path, e
            );
        }

        let dir_walk_options = &DirWalkOptions::default();
        for entry in DirWalk::new(self, cedar_auth, dir_walk_options) {
            match entry? {
                WalkEntry::Entry(mut dir_entry) => {
                    if dir_entry.is_file() {
                        dir_entry
                            .open_as_file(cedar_auth, READ_ONLY_FILE_OPTIONS)
                            .and_then(|file| file.safe_chmod(cedar_auth, options.permissions))
                            .inspect_err(|e| {
                                warn!("Failed to chmod file '{}': {}", dir_entry.name(), e);
                            })
                            .ok();
                    } else if dir_entry.is_dir() {
                        dir_entry
                            .open_as_dir(cedar_auth, OpenDirOptionsBuilder::default().build()?)
                            .and_then(|dir_handle| {
                                dir_handle.chmod_single_impl(cedar_auth, options)
                            })
                            .inspect_err(|e| {
                                warn!("Failed to chmod directory '{}': {}", dir_entry.name(), e);
                            })
                            .ok();
                    }
                }
                WalkEntry::DirPre(_) | WalkEntry::DirPost(_) | WalkEntry::File(_) => {}
            }
        }
        Ok(())
    }
}
