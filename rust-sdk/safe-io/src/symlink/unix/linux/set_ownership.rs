use cap_fs_ext::OsMetadataExt;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::fs::FileEntity;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_logger::debug;

use crate::errors::RustSafeIoError;
use crate::options::SetOwnershipOptions;
use crate::{
    Ownership, RcSymlinkHandle, build_path, get_user_and_group_names, is_authorized,
    set_ownership_inner,
};

impl RcSymlinkHandle {
    /// Changes the ownership of a symlink itself (without following it).
    ///
    /// This is equivalent to using `chown -h`.
    ///
    /// NB: `CAP_CHOWN` capability is required to change symlink ownership on Linux.
    /// Only supported on Linux-based platforms.
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
    /// let dir_path = "/tmp";
    /// let symlink_name = "my_symlink";
    /// let dir_handle = DirConfigBuilder::default()
    ///    .path(dir_path.to_string())
    ///    .build().unwrap()
    ///    .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap())
    ///    .unwrap();
    /// let symlink_handle = dir_handle.safe_open_symlink(&cedar_auth, symlink_name).unwrap();
    ///
    /// let options = SetOwnershipOptionsBuilder::default()
    ///     .user("newuser".to_string())
    ///     .group("newgroup".to_string())
    ///     .build().unwrap();
    /// symlink_handle.set_ownership(&cedar_auth, options).unwrap();
    /// ```
    pub fn set_ownership(
        &self,
        cedar_auth: &CedarAuth,
        options: SetOwnershipOptions,
    ) -> Result<(), RustSafeIoError> {
        let full_path = build_path(
            &self.symlink_handle.dir_handle.dir_config.path,
            &self.symlink_handle.symlink_name,
        );
        let file_entity = &FileEntity::from_string_path(&full_path)?;
        is_authorized(cedar_auth, &FilesystemAction::Chown, file_entity)?;

        // NB: get_ownership is unchecked because we are only logging it to syslog. This should not be returned to user output without checking for cedar permissions
        let before = self.get_ownership_unchecked()?;
        set_ownership_inner(
            &self.symlink_handle.fd,
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

        if user_changed || group_changed {
            // environment, so this branch can't be reached in tests
            debug!(
                "Ownership changed for symlink '{}': user: '{}' -> '{}', group: '{}' -> '{}'",
                full_path,
                before.user(),
                after.user(),
                before.group(),
                after.group()
            );
        } else {
            debug!(
                "Ownership unchanged for symlink '{}': user: '{}', group: '{}'",
                full_path,
                after.user(),
                after.group()
            );
        }

        Ok(())
    }

    /// Gets the ownership information of the symlink itself (without following it).
    ///
    /// NB: This method bypasses Cedar authorization checks. It is intended for
    /// internal logging/testing
    pub fn get_ownership_unchecked(&self) -> Result<Ownership, RustSafeIoError> {
        let metadata = self.symlink_handle.fd.metadata()?;
        let uid = metadata.uid();
        let gid = metadata.gid();
        let (username, groupname) = get_user_and_group_names(uid, gid)?;

        Ok(Ownership {
            owner: username,
            group: groupname,
        })
    }
}
