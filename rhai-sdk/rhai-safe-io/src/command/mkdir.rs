//! `mkdir` — Create directories
//!
//! # Example (Rhai)
//! ```rhai
//! // Create a single directory (parent must exist)
//! mkdir("/tmp/newdir");
//!
//! // Create nested directories recursively
//! mkdir([mkdir::parents], "/tmp/parent/child/grandchild");
//! ```

use super::open_dir_from_path;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::Array;
use rhai_sdk_common_utils::args::{extract_flags, has_flag};
use rust_safe_io::errors::RustSafeIoError;
use std::path::Path;

/// Flags for the `mkdir` command, registered as a Rhai custom type.
///
/// Available flags:
/// - `mkdir::parents` / `mkdir::p` — create parent directories as needed
#[derive(Debug, Clone)]
pub(crate) enum MkdirFlag {
    Parents,
}

pub(crate) struct MkdirOptions {
    pub parents: bool,
}

impl MkdirOptions {
    pub(crate) fn from_flags(flags: &[MkdirFlag]) -> Self {
        Self {
            parents: has_flag(flags, |f| matches!(f, MkdirFlag::Parents)),
        }
    }
}

/// Create a single directory (parent must exist).
pub(crate) fn mkdir(path: &str, cedar_auth: &CedarAuth) -> Result<(), RustSafeIoError> {
    mkdir_with_flags(path, &Array::new(), cedar_auth)
}

/// Create a directory with user-provided flags.
pub(crate) fn mkdir_with_flags(
    path: &str,
    flags_arr: &Array,
    cedar_auth: &CedarAuth,
) -> Result<(), RustSafeIoError> {
    let flags = extract_flags::<MkdirFlag>(flags_arr)?;
    let opts = MkdirOptions::from_flags(&flags);

    let path_obj = Path::new(path);

    if opts.parents {
        // Walk up to find the deepest existing ancestor.
        let mut ancestor = path_obj.to_path_buf();
        while !ancestor.exists() {
            if !ancestor.pop() {
                break;
            }
        }

        let relative = path_obj
            .strip_prefix(&ancestor)
            .map_err(|e| RustSafeIoError::InvalidArguments {
                reason: format!("mkdir: cannot compute relative path: {e}"),
            })?
            .to_string_lossy()
            .to_string();

        if relative.is_empty() {
            return Ok(());
        }

        let dir_handle = open_dir_from_path(ancestor.to_str().unwrap_or("."), cedar_auth)?;
        dir_handle.safe_create_sub_directories(cedar_auth, &relative)?;
    } else {
        let parent = path_obj
            .parent()
            .map_or_else(|| ".".to_string(), |p| p.to_string_lossy().to_string());

        let leaf = path_obj
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .ok_or_else(|| RustSafeIoError::InvalidArguments {
                reason: format!("Invalid directory path: {path}"),
            })?;

        let dir_handle = open_dir_from_path(&parent, cedar_auth)?;
        dir_handle.safe_create_sub_directories(cedar_auth, &leaf)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_fs::TempDir;
    use rex_test_utils::rhai::common::create_default_test_cedar_auth;
    use rhai::Dynamic;
    use std::fs;

    /// Given: An existing parent directory
    /// When: Calling mkdir to create a single child
    /// Then: The directory is created
    #[test]
    #[cfg(target_os = "linux")]
    fn test_mkdir_basic() {
        let temp = TempDir::new().unwrap();
        let target = fs::canonicalize(temp.path()).unwrap().join("newdir");
        let target_str = target.to_str().unwrap();
        let cedar_auth = create_default_test_cedar_auth();

        mkdir(target_str, &cedar_auth).unwrap();
        assert!(target.exists());
    }

    /// Given: A non-existent nested directory path without -p flag
    /// When: Calling mkdir
    /// Then: An error is returned
    #[test]
    #[cfg(target_os = "linux")]
    fn test_mkdir_fails_without_parents_flag() {
        let temp = TempDir::new().unwrap();
        let target = fs::canonicalize(temp.path()).unwrap().join("a/b/c");
        let target_str = target.to_str().unwrap();
        let cedar_auth = create_default_test_cedar_auth();

        let result = mkdir(target_str, &cedar_auth);
        assert!(result.is_err());
    }

    /// Given: A non-existent nested directory path with Parents flag
    /// When: Calling mkdir_with_flags
    /// Then: All directories in the path are created
    #[test]
    #[cfg(target_os = "linux")]
    fn test_mkdir_with_parents_flag() {
        let temp = TempDir::new().unwrap();
        let target = fs::canonicalize(temp.path()).unwrap().join("a/b/c");
        let target_str = target.to_str().unwrap();
        let cedar_auth = create_default_test_cedar_auth();
        let flags: Array = vec![Dynamic::from(MkdirFlag::Parents)];

        mkdir_with_flags(target_str, &flags, &cedar_auth).unwrap();
        assert!(target.exists());
    }

    /// Given: An array with a non-MkdirFlag element
    /// When: Calling mkdir_with_flags
    /// Then: An error is returned
    #[test]
    fn test_mkdir_rejects_wrong_flag_type() {
        let temp = TempDir::new().unwrap();
        let target = temp.path().join("x");
        let cedar_auth = create_default_test_cedar_auth();
        let flags: Array = vec![Dynamic::from("not_a_flag")];

        let result = mkdir_with_flags(target.to_str().unwrap(), &flags, &cedar_auth);
        assert!(result.is_err());
    }
}
