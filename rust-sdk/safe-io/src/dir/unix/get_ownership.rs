use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::fs::entities::DirEntity;

use cap_fs_ext::OsMetadataExt;
use std::path::Path;

use crate::errors::RustSafeIoError;
use crate::{Ownership, RcDirHandle, auth::is_authorized, get_user_and_group_names};

impl RcDirHandle {
    /// Gets the ownership information of a directory.
    ///
    /// Only supported for unix based platforms.
    ///
    /// # Arguments
    ///
    /// * `cedar_auth` - Cedar authorization instance
    /// * `principal` - Principal requesting authorization access
    ///
    /// # Returns
    ///
    /// * `Result<Ownership>` - Username and group name of the directory owner
    ///
    /// # Errors
    ///
    /// * Permission denied for directory ownership access
    /// * Directory metadata retrieval failure
    /// * Owner information determination failure
    /// * No mapping found for user ID or group ID
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use rust_safe_io::{DirConfigBuilder, Ownership};
    /// # use rust_safe_io::options::OpenDirOptionsBuilder;
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
    /// #    .path("/tmp".to_string())
    /// #    .build().unwrap()
    /// #    .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap())
    /// #    .unwrap();
    /// #
    /// let ownership = dir_handle.safe_get_ownership(&cedar_auth).unwrap();
    /// let owner = ownership.user();
    /// let group = ownership.group();
    /// ```
    pub fn safe_get_ownership(&self, cedar_auth: &CedarAuth) -> Result<Ownership, RustSafeIoError> {
        let dir_entity = &DirEntity::new(Path::new(&self.dir_handle.dir_config.path))?;
        is_authorized(cedar_auth, &FilesystemAction::Stat, dir_entity)?;

        self.get_ownership_unchecked()
    }

    /// Internal implementation for getting unix ownership for a directory.
    pub(crate) fn get_ownership_unchecked(&self) -> Result<Ownership, RustSafeIoError> {
        let metadata = self.dir_handle.dir.dir_metadata()?;
        let uid = metadata.uid();
        let gid = metadata.gid();

        let (username, groupname) = get_user_and_group_names(uid, gid)?;

        Ok(Ownership {
            owner: username,
            group: groupname,
        })
    }
}
