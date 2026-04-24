use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::fs::entities::FileEntity;

use rex_logger::debug;

use crate::errors::RustSafeIoError;
use crate::options::SetOwnershipOptions;
use crate::{RcFileHandle, is_authorized, set_ownership_inner};

impl RcFileHandle {
    /// Changes the ownership of a file. Only supported for unix based platforms.
    ///
    /// # Arguments
    /// * `cedar_auth` - The Cedar authorization instance
    /// * `options` - [`SetOwnershipOptions`] that has the new owning user and group. If neither
    ///   user nor group are provided, the function effectively does nothing.
    ///
    /// # Returns
    /// * `Result<()>` - Success or error
    ///
    /// # Errors
    /// * The principal doesn't have the `chown` cedar permission on the file
    /// * The script doesn't have OS permissions to change the file ownership (via e.g. `CAP_CHOWN`)
    /// * The provided user or group is invalid
    ///
    /// # Example
    /// ```no_run
    /// # use rust_safe_io::DirConfigBuilder;
    /// # use rust_safe_io::options::{OpenDirOptionsBuilder, OpenFileOptionsBuilder, SetOwnershipOptionsBuilder};
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    /// #
    /// # let dir_path = "/tmp";
    /// # let file_path = "file.txt";
    /// # let dir_handle = DirConfigBuilder::default()
    /// #    .path(dir_path.to_string())
    /// #    .build().unwrap()
    /// #    .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap())
    /// #    .unwrap();
    /// # let file_handle = dir_handle.safe_open_file(&cedar_auth, file_path, OpenFileOptionsBuilder::default().build().unwrap()).unwrap();
    ///
    /// let options = SetOwnershipOptionsBuilder::default()
    ///     .user("newuser".to_string())
    ///     .group("newgroup".to_string())
    ///     .build().unwrap();
    /// file_handle.set_ownership(&cedar_auth, options).unwrap();
    /// ```
    pub fn set_ownership(
        &self,
        cedar_auth: &CedarAuth,
        options: SetOwnershipOptions,
    ) -> Result<(), RustSafeIoError> {
        let file_entity = &FileEntity::from_string_path(&self.full_path())?;
        is_authorized(cedar_auth, &FilesystemAction::Chown, file_entity)?;

        // NB: get_ownership is unchecked because we are only logging it to syslog. This should not be returned to user output without checking for cedar permissions
        let before = self.get_ownership_unchecked()?;
        set_ownership_inner(
            &self.file_handle.file,
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
        let path = &self.full_path();

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
}
