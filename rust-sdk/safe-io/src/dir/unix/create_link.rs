use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::fs::entities::FileEntity;

use std::path::Path;

use super::super::validate_is_basename;
use crate::auth::is_authorized;
use crate::errors::RustSafeIoError;
use crate::options::CreateSymlinkOptions;
use crate::{RcDirHandle, build_path};

impl RcDirHandle {
    /// Creates a symbolic link pointing to the specified target.
    ///
    /// This function creates a symbolic link at `link_name` that points to `target`.
    /// The target can be either an absolute path (e.g., "/dev/null") or a relative path (e.g., "../file.txt").
    /// When `force` is set to `true` in the options, it will atomically replace any existing file at the link location.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_safe_io::DirConfigBuilder;
    /// use rust_safe_io::options::{OpenDirOptionsBuilder, CreateSymlinkOptionsBuilder};
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
    /// dir_handle.safe_create_symlink(
    ///     &cedar_auth,
    ///     "../other_file.txt",
    ///     "relative_link",
    ///     CreateSymlinkOptionsBuilder::default().force(true).build().unwrap()
    /// ).unwrap();
    /// ```
    pub fn safe_create_symlink(
        &self,
        cedar_auth: &CedarAuth,
        target: &str,
        link_name: &str,
        options: CreateSymlinkOptions,
    ) -> Result<(), RustSafeIoError> {
        let link_path = build_path(&self.dir_handle.dir_config.path, link_name);

        let file_entity = &FileEntity::from_string_path(&link_path)?;
        is_authorized(cedar_auth, &FilesystemAction::Create, file_entity)?;

        validate_is_basename(Path::new(link_name))?;

        let dir = &self.dir_handle.dir;

        if options.force {
            is_authorized(cedar_auth, &FilesystemAction::Delete, file_entity)?;

            let temp_dir = cap_tempfile::tempdir_in(dir)?;

            temp_dir.symlink_contents(target, link_name)?;

            temp_dir.rename(link_name, dir, link_name)?;
        } else {
            dir.symlink_contents(target, link_name)?;
        }

        Ok(())
    }
}
