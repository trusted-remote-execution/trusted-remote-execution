use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::fs::entities::FileEntity;

use crate::auth::is_authorized;
use crate::errors::RustSafeIoError;
use crate::{RcDirHandle, build_path};

impl RcDirHandle {
    /// Safely resolves a symlink and returns the target path as a string.
    ///
    /// # Arguments
    ///
    /// * `cedar_auth` - The Cedar authorization instance
    /// * `symlink_name` - The name of the symlink file within the directory
    ///
    /// # Returns
    ///
    /// * `Result<String>` - The target path that the symlink points to
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The principal doesn't have permission to read the symlink
    /// * The symlink file is not a symlink
    /// * The symlink cannot be read
    ///
    /// # Warning
    /// This function should only be used to inspect the target path. Opening the target using this
    /// returned path is not safe from Time-of-Check to Time-of-Use (TOCTOU) attacks. The symlink
    /// target could change between when this function returns and when the target is accessed.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// # use rust_safe_io::DirConfigBuilder;
    /// # use rust_safe_io::options::OpenDirOptionsBuilder;
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    ///
    /// let dir_handle = DirConfigBuilder::default()
    ///     .path("/tmp".to_string())
    ///     .build().unwrap()
    ///     .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap())
    ///     .unwrap();
    ///
    /// dir_handle.safe_read_link_target(&cedar_auth, "valid_symlink").unwrap();
    /// ```
    pub fn safe_read_link_target(
        &self,
        cedar_auth: &CedarAuth,
        symlink_name: &str,
    ) -> Result<String, RustSafeIoError> {
        is_authorized(
            cedar_auth,
            &FilesystemAction::Read,
            &FileEntity::from_string_path(&build_path(
                &self.dir_handle.dir_config.path,
                symlink_name,
            ))?,
        )?;

        let target_path = &self.dir_handle.dir.read_link_contents(symlink_name)?;
        Ok(target_path.to_string_lossy().to_string())
    }
}
