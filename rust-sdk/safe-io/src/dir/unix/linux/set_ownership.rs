use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::fs::entities::DirEntity;
use rex_logger::{debug, warn};

use std::path::Path;

use crate::errors::RustSafeIoError;
use crate::options::{
    DirWalkOptions, OpenDirOptionsBuilder, READ_ONLY_FILE_OPTIONS, SetOwnershipOptions,
};
use crate::recursive::{DirWalk, WalkEntry};
use crate::{RcDirHandle, auth::is_authorized, set_ownership_inner};

impl RcDirHandle {
    /// Changes the ownership of a directory. Only supported for unix based platforms.
    ///
    /// # Arguments
    /// * `cedar_auth` - The Cedar authorization instance
    /// * `options` - [`SetOwnershipOptions`] that has the new owning user and group. If neither
    ///   user nor group are provided, the function effectively does nothing.
    ///
    /// # Returns
    /// * `Result<()>` - Success or error
    ///
    /// # Permissions
    /// In addition to requiring `chown` permission via the Cedar policy for the target directory, one of the following
    /// must be true for the ownership to be changed successfully:
    /// * The calling user has ownership over the directory, or
    /// * The script is called with `CAP_CHOWN` capability.
    ///
    /// # Errors
    /// * The principal doesn't have the `chown` cedar permission on the directory
    /// * The script doesn't have OS permissions to change the directory ownership (via e.g. `CAP_CHOWN`)
    /// * The provided user or group is invalid
    ///
    /// # Example
    /// ```no_run
    /// # use rust_safe_io::DirConfigBuilder;
    /// # use rust_safe_io::options::{OpenDirOptionsBuilder, SetOwnershipOptionsBuilder};
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    /// #
    /// # let dir_handle = DirConfigBuilder::default()
    /// #     .path("/tmp/test".to_string())
    /// #     .build().unwrap()
    /// #     .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap())
    /// #     .unwrap();
    /// #
    /// let options = SetOwnershipOptionsBuilder::default()
    ///     .user("newuser".to_string())
    ///     .group("newgroup".to_string())
    ///     .recursive(true)
    ///     .build().unwrap();
    /// dir_handle.set_ownership(&cedar_auth, options).unwrap();
    /// ```
    pub fn set_ownership(
        &self,
        cedar_auth: &CedarAuth,
        options: SetOwnershipOptions,
    ) -> Result<(), RustSafeIoError> {
        if options.recursive {
            self.set_ownership_recursive_impl(cedar_auth, options)
        } else {
            self.set_ownership_single_impl(cedar_auth, options)
        }
    }

    fn set_ownership_single_impl(
        &self,
        cedar_auth: &CedarAuth,
        options: SetOwnershipOptions,
    ) -> Result<(), RustSafeIoError> {
        let dir_entity = &DirEntity::new(Path::new(&self.dir_handle.dir_config.path))?;
        is_authorized(cedar_auth, &FilesystemAction::Chown, dir_entity)?;

        // NB: get_ownership is unchecked because we are only logging it to syslog. This should not be returned to user output without checking for cedar permissions
        let before = self.get_ownership_unchecked()?;
        set_ownership_inner(
            &self.dir_handle.dir,
            options.user.clone(),
            options.group.clone(),
        )?;
        let after = self.get_ownership_unchecked()?;

        let user_changed = options
            .user
            .is_some_and(|_u: String| before.user() != after.user());
        let group_changed = options
            .group
            .is_some_and(|_g| before.group() != after.group());
        let path = &self.dir_handle.dir_config.path;

        if user_changed || group_changed {
            // environment, so this branch can't be reached in tests
            debug!(
                "Ownership changed for '{}': user: '{}' -> '{}', group: '{}' -> '{}'",
                path,
                before.user(),
                after.user(),
                before.group(),
                after.group()
            );
        } else {
            debug!(
                "Ownership unchanged for '{}': user: '{}', group: '{}'",
                path,
                after.user(),
                after.group()
            );
        }

        Ok(())
    }

    /// Uses `DirWalk` to traverse the directory tree with memoization and applies ownership changes to all directories
    /// and files encountered during traversal.
    #[allow(clippy::needless_pass_by_value)]
    fn set_ownership_recursive_impl(
        &self,
        cedar_auth: &CedarAuth,
        options: SetOwnershipOptions,
    ) -> Result<(), RustSafeIoError> {
        if let Err(e) = self.set_ownership_single_impl(cedar_auth, options.clone()) {
            warn!(
                "Failed to chown root directory '{}': {}",
                self.dir_handle.dir_config.path, e
            );
        }

        let dir_walk_options = &DirWalkOptions::default();
        for entry in DirWalk::new(self, cedar_auth, dir_walk_options) {
            match entry? {
                WalkEntry::Entry(mut dir_entry) => {
                    // Check for symlink first, before is_file() or is_dir(), because symlinks
                    // to files/directories will return true for those checks
                    if dir_entry.is_symlink() {
                        dir_entry
                            .open_as_symlink(cedar_auth)
                            .and_then(|symlink| symlink.set_ownership(cedar_auth, options.clone()))
                            .inspect_err(|e| {
                                warn!("Failed to chown symlink '{}': {}", dir_entry.name(), e);
                            })
                            .ok();
                    } else if dir_entry.is_file() {
                        dir_entry
                            .open_as_file(cedar_auth, READ_ONLY_FILE_OPTIONS)
                            .and_then(|file| file.set_ownership(cedar_auth, options.clone()))
                            .inspect_err(|e| {
                                warn!("Failed to chown file '{}': {}", dir_entry.name(), e);
                            })
                            .ok();
                    } else if dir_entry.is_dir() {
                        dir_entry
                            .open_as_dir(cedar_auth, OpenDirOptionsBuilder::default().build()?)
                            .and_then(|dir_handle| {
                                dir_handle.set_ownership_single_impl(cedar_auth, options.clone())
                            })
                            .inspect_err(|e| {
                                warn!("Failed to chown directory '{}': {}", dir_entry.name(), e);
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
