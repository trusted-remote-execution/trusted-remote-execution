use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::fs::entities::DirEntity;

use std::path::Path;

use crate::auth::is_authorized;
use crate::errors::RustSafeIoError;
use crate::{DirEntry, RcDirHandle};

impl RcDirHandle {
    /// Lists the contents of a directory
    ///
    /// # Arguments
    ///
    /// * `cedar_auth` - The Cedar authorization instance
    ///
    /// # Returns
    ///
    /// * `Result<Vec<DirEntry>>` - A vector of directory entries if successful
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The principal doesn't have permission to list the directory
    /// * The directory cannot be read
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
    /// let entries = dir_handle.safe_list_dir(&cedar_auth).unwrap();
    /// ```
    pub fn safe_list_dir(&self, cedar_auth: &CedarAuth) -> Result<Vec<DirEntry>, RustSafeIoError> {
        is_authorized(
            cedar_auth,
            &FilesystemAction::Read,
            &DirEntity::new(Path::new(&self.dir_handle.dir_config.path))?,
        )?;

        let mut entries = Vec::new();
        for entry_result in self.dir_handle.dir.entries()? {
            entries.push(DirEntry::from_cap_std(self, &entry_result?));
        }

        Ok(entries)
    }
}
