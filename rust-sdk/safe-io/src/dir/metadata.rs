use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::fs::entities::DirEntity;

use std::path::Path;

use crate::auth::is_authorized;
use crate::errors::RustSafeIoError;
use crate::{Metadata, RcDirHandle};

impl RcDirHandle {
    /// Retrieves metadata for the directory.
    ///
    /// This method fetches metadata information about the directory, including size, permissions,
    /// modification times, and other directory attributes.
    ///
    /// # Arguments
    ///
    /// * `cedar_auth` - The Cedar authorization instance
    ///
    /// # Returns
    ///
    /// * `Result<Metadata>` - The directory metadata if successful
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The principal doesn't have permission to access the directory metadata
    /// * The directory metadata cannot be retrieved
    ///
    /// # Example
    ///
    /// ```no_run
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
    /// let dir_handle = DirConfigBuilder::default()
    ///     .path("/tmp".to_string())
    ///     .build().unwrap()
    ///     .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap())
    ///     .unwrap();
    /// let metadata = dir_handle.metadata(&cedar_auth).unwrap();
    /// println!("Directory size: {}", metadata.cap_std_metadata().len());
    /// ```
    pub fn metadata(&self, cedar_auth: &CedarAuth) -> Result<Metadata, RustSafeIoError> {
        let dir_entity = &DirEntity::new(Path::new(&self.dir_handle.dir_config.path))?;
        is_authorized(cedar_auth, &FilesystemAction::Stat, dir_entity)?;
        let metadata = Metadata::from_cap_std_metadata(self.dir_handle.dir.metadata(".")?)?;

        Ok(metadata)
    }
}
