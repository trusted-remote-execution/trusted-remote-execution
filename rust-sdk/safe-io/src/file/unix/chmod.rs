use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::fs::entities::FileEntity;

use cap_std::fs::PermissionsExt;

use crate::errors::RustSafeIoError;
use crate::{RcFileHandle, is_authorized, validate_permissions};

impl RcFileHandle {
    /// Changes the permissions of an existing file.
    ///
    /// Only supported for unix based platforms.
    ///
    /// Note: While Linux systems typically use capabilities like `CAP_FOWNER` to allow
    /// non-owners to change file permissions, this implementation adds Cedar authorization
    /// as an additional security layer.
    ///
    /// # Arguments
    ///
    /// * `cedar_auth` - The Cedar authorization instance
    /// * `permissions` - The new permissions to set (as a u32 octal value)
    ///
    /// # Returns
    ///
    /// * `Result<()>` - Success or error
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The principal doesn't have permission to change file permissions
    /// * The permissions value is invalid (greater than 0o777)
    /// * The file permissions cannot be changed due to insufficient privileges
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
    /// let file_handle = dir_handle.safe_open_file(&cedar_auth, file_path, OpenFileOptionsBuilder::default().read(true).build().unwrap()).unwrap();
    /// file_handle.safe_chmod(&cedar_auth, 0o644).unwrap();
    /// ```
    pub fn safe_chmod(
        &self,
        cedar_auth: &CedarAuth,
        permissions: i64,
    ) -> Result<(), RustSafeIoError> {
        is_authorized(
            cedar_auth,
            &FilesystemAction::Chmod,
            &FileEntity::from_string_path(&self.full_path())?,
        )?;

        let input_perms = u32::try_from(permissions)?;
        validate_permissions(input_perms)?;

        let new_permissions = PermissionsExt::from_mode(input_perms);
        self.file_handle.file.set_permissions(new_permissions)?;

        Ok(())
    }
}
