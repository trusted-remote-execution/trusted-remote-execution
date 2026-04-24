//! `glob` - Find files matching wildcard patterns
//!
//! # Example (Rhai)
//! ```rhai
//! // Find all .txt files
//! let files = glob("*.txt", "/path/to/dir");
//!
//! // Recursive search
//! let files = glob([glob::recursive], "*.log", "/path/to/dir");
//! ```

use super::open_dir_from_path;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::Array;
use rhai_sdk_common_utils::args::{extract_flags, has_flag};
use rust_safe_io::WalkEntry;
use rust_safe_io::errors::RustSafeIoError;
use rust_safe_io::options::FindOptionsBuilder;

/// Flags for the `glob` command, registered as a Rhai custom type.
///
/// Available flags:
/// - `glob::recursive` / `glob::r` — search subdirectories recursively
#[derive(Debug, Clone)]
pub(crate) enum GlobFlag {
    Recursive,
}

pub(crate) struct GlobOptions {
    pub recursive: bool,
}

impl GlobOptions {
    pub(crate) fn from_flags(flags: &[GlobFlag]) -> Self {
        Self {
            recursive: has_flag(flags, |f| matches!(f, GlobFlag::Recursive)),
        }
    }
}

/// Find files matching a pattern in a directory
pub(crate) fn glob(
    pattern: &str,
    path: &str,
    cedar_auth: &CedarAuth,
) -> Result<Vec<String>, RustSafeIoError> {
    glob_with_flags(pattern, path, &Array::new(), cedar_auth)
}

/// Find files matching a pattern with user-provided flags
pub(crate) fn glob_with_flags(
    pattern: &str,
    path: &str,
    flags_arr: &Array,
    cedar_auth: &CedarAuth,
) -> Result<Vec<String>, RustSafeIoError> {
    let flags = extract_flags::<GlobFlag>(flags_arr)?;
    let opts = GlobOptions::from_flags(&flags);

    let dir_handle = open_dir_from_path(path, cedar_auth)?;

    let mut builder = FindOptionsBuilder::default();
    builder.name(pattern.to_string());
    if !opts.recursive {
        builder.max_depth(1_i64);
    }
    let find_options = builder
        .build()
        .map_err(|e| RustSafeIoError::InvalidArguments {
            reason: e.to_string(),
        })?;

    let mut results = Vec::new();
    dir_handle.safe_find(cedar_auth, find_options, |entry| {
        if let WalkEntry::Entry(dir_entry) = entry {
            results.push(dir_entry.name().clone());
        }
        Ok(())
    })?;

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_fs::TempDir;
    use assert_fs::prelude::*;
    use rex_test_utils::rhai::common::create_default_test_cedar_auth;
    use rhai::Dynamic;
    use std::fs;

    /// Given: A directory with .txt and .log files
    /// When: Calling glob with "*.txt"
    /// Then: Only .txt files are returned
    #[test]
    fn test_glob_matches_pattern() {
        let temp = TempDir::new().unwrap();
        temp.child("file1.txt").write_str("a").unwrap();
        temp.child("file2.txt").write_str("b").unwrap();
        temp.child("file3.log").write_str("c").unwrap();
        let path = fs::canonicalize(temp.path())
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let cedar_auth = create_default_test_cedar_auth();

        let result = glob("*.txt", &path, &cedar_auth).unwrap();
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|f| f.ends_with(".txt")));
    }

    /// Given: An array with a non-GlobFlag element
    /// When: Calling glob_with_flags
    /// Then: An error is returned
    #[test]
    fn test_glob_rejects_wrong_flag_type() {
        let temp = TempDir::new().unwrap();
        let path = fs::canonicalize(temp.path())
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let cedar_auth = create_default_test_cedar_auth();
        let flags: Array = vec![Dynamic::from("not_a_flag")];

        let result = glob_with_flags("*", &path, &flags, &cedar_auth);
        assert!(result.is_err());
    }
}
