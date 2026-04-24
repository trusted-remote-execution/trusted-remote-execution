use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::fs::entities::FileEntity;

use crate::errors::RustSafeIoError;
use crate::{Metadata, RcDirHandle, RcSymlinkHandle, build_path, is_authorized};

impl RcSymlinkHandle {
    /// Retrieves metadata for the symlink itself (not the target).
    ///
    /// This method fetches metadata information about the symlink, including size, permissions,
    /// modification times, other attributes, and the target path of the symlink itself.
    ///
    /// If the principal has permission to stat the symlink but not to read the symlink target,
    /// the metadata will be returned with `symlink_target` set to `None`.
    ///
    /// # Errors
    /// Returns an error if:
    /// * The principal doesn't have permission to access the symlink metadata
    /// * The symlink metadata cannot be retrieved
    ///
    /// # Example
    /// ```ignore
    /// use rust_safe_io::DirConfigBuilder;
    /// use rust_safe_io::options::OpenDirOptionsBuilder;
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
    /// let symlink_name = "my_symlink";
    /// let dir_handle = DirConfigBuilder::default()
    ///     .path(dir_path.to_string())
    ///     .build().unwrap()
    ///     .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap())
    ///     .unwrap();
    /// let symlink_handle = dir_handle.safe_open_symlink(&cedar_auth, symlink_name).unwrap();
    /// let metadata = symlink_handle.metadata(&cedar_auth).unwrap();
    /// println!("Symlink permissions: {}", metadata.permissions());
    /// println!("Symlink target: {:?}", metadata.symlink_target());
    /// ```
    pub fn metadata(&self, cedar_auth: &CedarAuth) -> Result<Metadata, RustSafeIoError> {
        let full_path = build_path(
            &self.symlink_handle.dir_handle.dir_config.path,
            &self.symlink_handle.symlink_name,
        );
        let file_entity = &FileEntity::from_string_path(&full_path)?;
        is_authorized(cedar_auth, &FilesystemAction::Stat, file_entity)?;
        let mut metadata = Metadata::from_cap_std_metadata(self.symlink_handle.fd.metadata()?)?;

        // Read symlink target path using safe_read_link_target from RcDirHandle
        let rc_dir_handle = RcDirHandle {
            dir_handle: self.symlink_handle.dir_handle.clone(),
        };
        match rc_dir_handle.safe_read_link_target(cedar_auth, &self.symlink_handle.symlink_name) {
            Ok(target_path) => metadata.set_symlink_target(Some(target_path)),
            Err(RustSafeIoError::PermissionDenied { ref action, .. })
                if action == &FilesystemAction::Read.to_string() =>
            {
                // No Read permission - return metadata without symlink target
            }
            Err(e) => return Err(e),
        }

        Ok(metadata)
    }
}
