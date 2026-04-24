use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::fs::entities::FileEntity;

use cap_fs_ext::OsMetadataExt;

use crate::errors::RustSafeIoError;
use crate::{Ownership, RcFileHandle, get_user_and_group_names, is_authorized};

impl RcFileHandle {
    /// Gets the ownership information of a file. Only supported for unix based platforms.
    ///
    /// # Errors
    /// * Permission denied for file ownership access
    /// * File metadata retrieval failure
    /// * No mapping found for user ID or group ID
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use rust_safe_io::{DirConfigBuilder, Ownership};
    /// # use rust_safe_io::options::{OpenDirOptionsBuilder, OpenFileOptionsBuilder};
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
    /// #     .path("/tmp".to_string())
    /// #    .build().unwrap()
    /// #    .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap())
    /// #    .unwrap();
    /// #
    /// # let file_handle = dir_handle.safe_open_file(
    /// #    &cedar_auth,
    /// #    "file.txt",
    /// #    OpenFileOptionsBuilder::default().read(true).build().unwrap()
    /// # ).unwrap();
    /// #
    /// let ownership = file_handle.safe_get_ownership(&cedar_auth).unwrap();
    /// let owner = ownership.user();
    /// let group = ownership.group();
    /// ```
    pub fn safe_get_ownership(&self, cedar_auth: &CedarAuth) -> Result<Ownership, RustSafeIoError> {
        let file_entity = &FileEntity::from_string_path(&self.full_path())?;
        is_authorized(cedar_auth, &FilesystemAction::Stat, file_entity)?;

        self.get_ownership_unchecked()
    }

    /// Internal implementation for getting unix ownership for a file.
    pub(crate) fn get_ownership_unchecked(&self) -> Result<Ownership, RustSafeIoError> {
        let metadata = self.file_handle.file.metadata()?;
        let uid = metadata.uid();
        let gid = metadata.gid();

        let (username, groupname) = get_user_and_group_names(uid, gid)?;

        Ok(Ownership {
            owner: username,
            group: groupname,
        })
    }
}
