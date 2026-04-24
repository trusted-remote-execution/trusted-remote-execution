//! `rm` - Remove files or directories
//!
//! # Example (Rhai)
//! ```rhai
//! // Remove a file
//! rm("/path/to/file.txt");
//!
//! // Force remove
//! rm([rm::force], "/path/to/file.txt");
//!
//! // Recursive directory removal
//! rm([rm::recursive, rm::force], "/path/to/dir");
//! ```

use super::{open_dir_from_path, open_file_from_path};
use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::Array;
use rhai_sdk_common_utils::args::{extract_flags, has_flag};
use rust_safe_io::errors::RustSafeIoError;
use rust_safe_io::options::{DeleteDirOptionsBuilder, DeleteFileOptionsBuilder};
use std::path::Path;

/// Flags for the `rm` command, registered as a Rhai custom type.
///
/// Available flags:
/// - `rm::force` / `rm::f` — ignore nonexistent files
/// - `rm::recursive` / `rm::r` — remove directories and their contents recursively
#[derive(Debug, Clone)]
pub(crate) enum RmFlag {
    Force,
    Recursive,
}

pub(crate) struct RmOptions {
    pub force: bool,
    pub recursive: bool,
}

impl RmOptions {
    pub(crate) fn from_flags(flags: &[RmFlag]) -> Self {
        Self {
            force: has_flag(flags, |f| matches!(f, RmFlag::Force)),
            recursive: has_flag(flags, |f| matches!(f, RmFlag::Recursive)),
        }
    }
}

/// Remove a file or directory with default options
pub(crate) fn rm(path: &str, cedar_auth: &CedarAuth) -> Result<(), RustSafeIoError> {
    rm_with_flags(path, &Array::new(), cedar_auth)
}

/// Remove a file or directory with user-provided flags
pub(crate) fn rm_with_flags(
    path: &str,
    flags_arr: &Array,
    cedar_auth: &CedarAuth,
) -> Result<(), RustSafeIoError> {
    let flags = extract_flags::<RmFlag>(flags_arr)?;
    let opts = RmOptions::from_flags(&flags);

    let target = Path::new(path);

    if target.is_dir() {
        let dir_handle = open_dir_from_path(path, cedar_auth)?;
        let delete_opts = DeleteDirOptionsBuilder::default()
            .force(opts.force)
            .recursive(opts.recursive)
            .build()
            .map_err(|e| RustSafeIoError::InvalidArguments {
                reason: e.to_string(),
            })?;
        dir_handle.safe_delete(cedar_auth, delete_opts)?;
    } else {
        let file_handle = open_file_from_path(path, cedar_auth)?;
        let delete_opts = DeleteFileOptionsBuilder::default()
            .force(opts.force)
            .build()
            .map_err(|e| RustSafeIoError::InvalidArguments {
                reason: e.to_string(),
            })?;
        file_handle.safe_delete(cedar_auth, delete_opts)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_fs::TempDir;
    use assert_fs::prelude::*;
    use rex_test_utils::rhai::common::create_default_test_cedar_auth;
    use rhai::Dynamic;
    use std::fs;

    /// Given: A file that exists
    /// When: Calling rm on it
    /// Then: The file is deleted
    #[test]
    fn test_rm_file() {
        let temp = TempDir::new().unwrap();
        temp.child("delete_me.txt").write_str("bye").unwrap();
        let path = fs::canonicalize(temp.path().join("delete_me.txt"))
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let cedar_auth = create_default_test_cedar_auth();

        let result = rm(&path, &cedar_auth);
        assert!(result.is_ok());
        assert!(!Path::new(&path).exists());
    }

    /// Given: An array with a non-RmFlag element
    /// When: Calling rm_with_flags
    /// Then: An error is returned
    #[test]
    fn test_rm_rejects_wrong_flag_type() {
        let temp = TempDir::new().unwrap();
        temp.child("file.txt").write_str("content").unwrap();
        let path = fs::canonicalize(temp.path().join("file.txt"))
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let cedar_auth = create_default_test_cedar_auth();
        let flags: Array = vec![Dynamic::from("not_a_flag")];

        let result = rm_with_flags(&path, &flags, &cedar_auth);
        assert!(result.is_err());
    }
}
