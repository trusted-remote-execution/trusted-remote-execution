use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::fs::entities::DirEntity;

use std::path::{Path, PathBuf};

use crate::auth::is_authorized;
use crate::errors::{RustSafeIoError, map_dir_symlink_error};
use crate::{RcDirHandle, build_path};

impl RcDirHandle {
    /// Creates sub directories with per-level Cedar authorization.
    ///
    /// This method creates all necessary parent directories in the specified path,
    /// performing Cedar authorization checks for each directory level before creation.
    ///
    /// # Arguments
    ///
    /// * `cedar_auth` - The Cedar authorization instance
    /// * `path` - The relative path of directories to create within the current directory
    ///
    /// # Returns
    ///
    /// * `Result<()>`
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The principal doesn't have permission to create any directory in the path hierarchy
    /// * Any directory in the path already exists as a file
    /// * Any I/O errors occur during directory creation
    /// * The path contains invalid characters or traversal attempts
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
    ///
    /// dir_handle.safe_create_sub_directories(&cedar_auth, "parent/child/grandchild").unwrap();
    /// ```
    pub fn safe_create_sub_directories(
        &self,
        cedar_auth: &CedarAuth,
        path: &str,
    ) -> Result<(), RustSafeIoError> {
        let normalized_path = path.trim_end_matches('/');
        let path_obj = Path::new(normalized_path);
        let mut current_path = PathBuf::new();

        for component in path_obj.components() {
            current_path.push(component);
            let full_path = build_path(
                &self.dir_handle.dir_config.path,
                &current_path.to_string_lossy(),
            );
            let dir_entity = DirEntity::new(Path::new(&full_path))?;
            is_authorized(cedar_auth, &FilesystemAction::Create, &dir_entity)?;
        }

        let dir_path = build_path(&self.dir_handle.dir_config.path, normalized_path);
        self.dir_handle
            .dir
            .create_dir_all(normalized_path)
            .map_err(|e| map_dir_symlink_error(e, &dir_path))?;
        Ok(())
    }
}
