use cap_fs_ext::DirExt;
use cap_std::fs::Dir;
use derive_builder::Builder;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::fs::entities::DirEntity;
use rex_logger::debug;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use super::common::get_resolved_path_from_fd;
use super::validate_is_basename;
use crate::constants::error_constants::{
    FAILED_CREATE_DIR, FAILED_OPEN_DIR, FAILED_OPEN_LEAF, FAILED_OPEN_PARENT, LEAF_PATH_INVALID,
    PARENT_PATH_INVALID, PATH_COMPONENT_NOT_UTF8,
};
use crate::errors::{RustSafeIoError, map_dir_symlink_error};
use crate::options::OpenDirOptions;
use crate::{
    DirHandle, RcDirHandle, auth::is_authorized, build_path, check_for_traversal, get_basename,
};

/// Configuration parameters for opening a directory.
///
/// This struct is used to specify how a directory should be opened or created.
/// It uses the builder pattern for construction via the derived `DirConfigBuilder`.
///
/// # Arguments
///
/// * `path` - The full path to the directory containing the file
///
/// # Examples
///
/// ```no_run
/// use rust_safe_io::DirConfigBuilder;
///
/// let dir_handle = DirConfigBuilder::default()
///     .path("/some/path".to_string())
///     .build()
///     .unwrap();
/// ```
#[derive(Builder, Debug, Clone)]
#[builder(derive(Debug), build_fn(error = RustSafeIoError))]
#[allow(clippy::struct_excessive_bools)]
pub struct DirConfig {
    pub path: String,
}

impl DirConfig {
    /// Opens or creates a directory with Cedar authorization and returns a [`DirHandle`] for I/O operations.
    ///
    /// By default, symlinks and directory traversal are blocked. When `follow_symlinks` is enabled,
    /// the target directory will be opened instead.
    ///
    /// # Examples
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
    /// let dir_config = DirConfigBuilder::default()
    ///     .path("/some/path".to_string())
    ///     .build().unwrap();
    ///
    /// let dir_handle = dir_config.safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap()).unwrap();
    /// ```
    pub fn safe_open(
        &self,
        cedar_auth: &CedarAuth,
        open_dir_options: OpenDirOptions,
    ) -> Result<RcDirHandle, RustSafeIoError> {
        let entity = &DirEntity::new(Path::new(&self.path))?;
        is_authorized(cedar_auth, &FilesystemAction::Open, entity).and_then(|()| {
            if open_dir_options.create {
                is_authorized(cedar_auth, &FilesystemAction::Create, entity)
            } else {
                Ok(())
            }
        })?;

        let (dir_fd, final_path) = if open_dir_options.follow_symlinks {
            let dir = Dir::open_ambient_dir(&self.path, cap_std::ambient_authority())?;

            let resolved_path = get_resolved_path_from_fd(&dir)?;
            debug!(
                "Symlink resolved: symlink: '{}' -> target: '{}'",
                self.path, resolved_path
            );
            let resolved_entity = &DirEntity::new(Path::new(&resolved_path))?;
            is_authorized(cedar_auth, &FilesystemAction::Open, resolved_entity)?;

            (dir, resolved_path)
        } else {
            let base_dir =
                Dir::open_ambient_dir("/", cap_std::ambient_authority()).map_err(|e| {
                    RustSafeIoError::DirectoryOpenError {
                        reason: FAILED_OPEN_DIR.to_string(),
                        path: PathBuf::from("/"),
                        source: Box::new(e),
                    }
                })?;

            let dir_fd = self.open_directory(base_dir, open_dir_options)?;

            // path traversal and absolute symlink paths will fail in the function above.
            // Any error here means we have a symlink with a relative path
            check_for_traversal(Path::new(&self.path)).map_err(|_| {
                map_dir_symlink_error(
                    std::io::Error::from(std::io::ErrorKind::NotADirectory),
                    &self.path,
                )
            })?;

            (dir_fd, self.path.clone())
        };

        let basename = get_basename(&final_path);

        Ok(RcDirHandle {
            dir_handle: Rc::new(DirHandle {
                dir_config: DirConfig { path: final_path },
                dir: dir_fd,
                basename,
            }),
        })
    }

    fn create_leaf_dir(&self, base_dir: &Dir, sbox_path: &Path) -> Result<Dir, RustSafeIoError> {
        let parent = sbox_path
            .parent()
            .ok_or_else(|| RustSafeIoError::InvalidPath {
                reason: PARENT_PATH_INVALID.to_string(),
                path: PathBuf::from(&self.path),
            })?;

        let leaf = sbox_path
            .file_name()
            .ok_or_else(|| RustSafeIoError::InvalidPath {
                reason: LEAF_PATH_INVALID.to_string(),
                path: PathBuf::from(&self.path),
            })?;

        // In order to safely open and create a directory, open the parent directory first, and use the open
        // file descriptor to create the leaf. Once the leaf is created, use the still open parent to
        // open the leaf.
        let parent_dir = base_dir.open_dir_nofollow(parent).map_err(|e| {
            RustSafeIoError::DirectoryOpenError {
                reason: FAILED_OPEN_PARENT.to_string(),
                path: parent.into(),
                source: Box::new(e),
            }
        })?;

        parent_dir
            .create_dir(leaf)
            .map_err(|e| RustSafeIoError::DirectoryOpenError {
                reason: FAILED_CREATE_DIR.to_string(),
                path: PathBuf::from(leaf),
                source: Box::new(e),
            })?;

        parent_dir
            .open_dir_nofollow(leaf)
            .map_err(|e| RustSafeIoError::DirectoryOpenError {
                reason: FAILED_OPEN_LEAF.to_string(),
                path: PathBuf::from(leaf),
                source: Box::new(e),
            })
    }

    fn open_directory(
        &self,
        base_dir: Dir,
        open_dir_options: OpenDirOptions,
    ) -> Result<Dir, RustSafeIoError> {
        // slashes need to be trimmed since the top level [`Dir`] was opened using '/'.
        // calling open_dir() on `//path` causes errors.
        let root_sbox_path = self.path.trim_matches('/');
        let sbox_path = Path::new(root_sbox_path);

        if !open_dir_options.create {
            return base_dir
                .open_dir_nofollow(root_sbox_path)
                .map_err(|e| map_dir_symlink_error(e, &self.path));
        }

        if !open_dir_options.recursive {
            return self.create_leaf_dir(&base_dir, sbox_path);
        }

        let components = sbox_path.components();
        let mut current_dir = base_dir;

        for component in components {
            let component_str =
                component
                    .as_os_str()
                    .to_str()
                    .ok_or_else(|| RustSafeIoError::InvalidPath {
                        reason: PATH_COMPONENT_NOT_UTF8.to_string(),
                        path: PathBuf::from(&self.path),
                    })?;

            match current_dir.create_dir(component_str) {
                Ok(()) => {
                    current_dir = current_dir
                        .open_dir_nofollow(component_str)
                        .map_err(|e| map_dir_symlink_error(e, &self.path))?;
                }
                Err(err) => {
                    if err.kind() == std::io::ErrorKind::AlreadyExists {
                        current_dir = current_dir
                            .open_dir_nofollow(component_str)
                            .map_err(|e| map_dir_symlink_error(e, &self.path))?;
                    } else {
                        return Err(RustSafeIoError::DirectoryOpenError {
                            reason: FAILED_OPEN_DIR.to_string(),
                            path: PathBuf::from(component_str),
                            source: Box::new(err),
                        });
                    }
                }
            }
        }

        Ok(current_dir)
    }
}

impl RcDirHandle {
    /// Opens a subdirectory within the current directory.
    ///
    /// This method performs authorization checks and path validation before opening
    /// the subdirectory.
    ///
    /// # Errors
    /// Returns an error if:
    /// * Authorization check fails
    /// * Path contains relative paths (e.g. "..")
    /// * Path contains symlinks
    /// * Subdirectory cannot be opened
    pub fn safe_open_subdir(
        &self,
        cedar_auth: &CedarAuth,
        subdir_name: &str,
    ) -> Result<RcDirHandle, RustSafeIoError> {
        let subdir_path = build_path(&self.dir_handle.dir_config.path, subdir_name);

        let dir_entity = DirEntity::new(Path::new(&subdir_path))?;
        is_authorized(cedar_auth, &FilesystemAction::Open, &dir_entity)?;

        validate_is_basename(Path::new(subdir_name))?;
        let subdir_dir = self
            .dir_handle
            .dir
            .open_dir_nofollow(subdir_name)
            .map_err(|e| map_dir_symlink_error(e, &subdir_path))?;

        let basename = get_basename(&subdir_path);

        Ok(RcDirHandle {
            dir_handle: Rc::new(DirHandle {
                dir_config: DirConfig { path: subdir_path },
                dir: subdir_dir,
                basename,
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::DirConfigBuilder;

    /// Given: A [`DirConfigBuilder`] with valid path
    /// When: Building [`DirConfig`] with a path
    /// Then: Should successfully create [`DirConfig`] with correct path
    #[test]
    fn test_arg_build_success() {
        let result = DirConfigBuilder::default()
            .path("test/path".to_string())
            .build();

        assert!(
            result.is_ok(),
            "Expected DirConfig build to succeed, but received {:?}",
            result
        );

        let dir_args = result.unwrap();
        assert_eq!(
            dir_args.path, "test/path",
            "Expected path to be 'test/path', but got '{}'",
            dir_args.path
        );
    }

    /// Given: A default [`DirConfigBuilder`] with no configuration
    /// When: Attempting to build [`DirConfig`] without setting required path
    /// Then: Should return an error indicating missing path field
    #[test]
    fn test_arg_build_error() {
        // Test the direct builder error
        let result = DirConfigBuilder::default().build();

        assert!(
            result.is_err(),
            "Expected DirConfigBuilder to fail without path, but it succeeded"
        );

        let error = result.unwrap_err().to_string();
        assert!(
            error.contains("path"),
            "Error should mention missing path field"
        );
    }
}
