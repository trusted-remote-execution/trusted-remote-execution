//! `ls` - List directory contents at path
//!
//! # Example (Rhai)
//! ```rhai
//! // Simple usage
//! let entries = ls("/path/to/directory");
//!
//! // With flags
//! let entries = ls([Ls::ALL, Ls::LONG], "/path/to/directory");
//! ```

use super::open_dir_from_path;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::{Array, Dynamic, Map};
use rhai_sdk_common_utils::args::{extract_flags, has_flag};
use rust_safe_io::{DirEntry, errors::RustSafeIoError};

/// Flags for the `ls` command, registered as a Rhai custom type.
///
/// Available flags:
/// - `Ls::ALL` / `Ls::A` — include hidden entries (names starting with '.')
/// - `Ls::LONG` / `Ls::L` — long listing format (reserved for future use)
/// - `Ls::RECURSIVE` / `Ls::R` — list subdirectories recursively (reserved for future use)
#[derive(Debug, Clone)]
pub(crate) enum LsFlag {
    All,
    Long,
    Recursive,
}

/// Parsed options from `LsFlag` values.
#[allow(dead_code)]
pub(crate) struct LsOptions {
    pub all: bool,
    pub long: bool,
    pub recursive: bool,
}

impl LsOptions {
    pub(crate) fn from_flags(flags: &[LsFlag]) -> Self {
        Self {
            all: has_flag(flags, |f| matches!(f, LsFlag::All)),
            long: has_flag(flags, |f| matches!(f, LsFlag::Long)),
            recursive: has_flag(flags, |f| matches!(f, LsFlag::Recursive)),
        }
    }
}

/// List directory contents
pub(crate) fn ls(
    path: &str,
    options: &LsOptions,
    cedar_auth: &CedarAuth,
) -> Result<Vec<DirEntry>, RustSafeIoError> {
    let dir_handle = open_dir_from_path(path, cedar_auth)?;
    let entries = dir_handle.safe_list_dir(cedar_auth)?;

    if options.all {
        Ok(entries)
    } else {
        Ok(entries
            .into_iter()
            .filter(|e| !e.name().starts_with('.'))
            .collect())
    }
}

/// `ls` wrapper that returns a Rhai Map, with default options
pub(crate) fn ls_rhai(path: &str, cedar_auth: &CedarAuth) -> Result<Map, RustSafeIoError> {
    ls_rhai_with_flags(path, &Array::new(), cedar_auth)
}

/// `ls` wrapper that returns a Rhai Map, with user-provided flags
pub(crate) fn ls_rhai_with_flags(
    path: &str,
    flags_arr: &Array,
    cedar_auth: &CedarAuth,
) -> Result<Map, RustSafeIoError> {
    let flags = extract_flags::<LsFlag>(flags_arr)?;
    let options = LsOptions::from_flags(&flags);
    ls(path, &options, cedar_auth).map(|entries| {
        entries
            .into_iter()
            .map(|e| (e.name().into(), Dynamic::from(e)))
            .collect::<Map>()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_fs::TempDir;
    use assert_fs::prelude::*;
    use rex_test_utils::rhai::common::create_default_test_cedar_auth;
    use std::fs;

    fn setup_test_dir() -> (TempDir, String) {
        let temp = TempDir::new().unwrap();
        temp.child("file1.txt").write_str("content1").unwrap();
        temp.child("file2.txt").write_str("content2").unwrap();
        temp.child(".hidden").write_str("secret").unwrap();
        let path = fs::canonicalize(temp.path())
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        (temp, path)
    }

    /// Given: A directory with visible and hidden files
    /// When: Calling ls with default options
    /// Then: Only non-hidden entries are returned
    #[test]
    fn test_ls_filters_hidden_by_default() {
        let (_temp, path) = setup_test_dir();
        let cedar_auth = create_default_test_cedar_auth();
        let opts = LsOptions {
            all: false,
            long: false,
            recursive: false,
        };

        let result = ls(&path, &opts, &cedar_auth).unwrap();
        let names: Vec<String> = result.iter().map(|e| e.name().to_string()).collect();
        assert!(names.contains(&"file1.txt".to_string()));
        assert!(!names.contains(&".hidden".to_string()));
    }

    /// Given: A directory with hidden files
    /// When: Calling ls with LsFlag::All
    /// Then: Hidden entries are included
    #[test]
    fn test_ls_show_all() {
        let (_temp, path) = setup_test_dir();
        let cedar_auth = create_default_test_cedar_auth();
        let opts = LsOptions::from_flags(&[LsFlag::All]);

        let result = ls(&path, &opts, &cedar_auth).unwrap();
        let names: Vec<String> = result.iter().map(|e| e.name().to_string()).collect();
        assert!(names.contains(&".hidden".to_string()));
    }

    /// Given: An array with a non-LsFlag element
    /// When: Calling ls_rhai_with_flags
    /// Then: An error is returned
    #[test]
    fn test_ls_rejects_wrong_flag_type() {
        let (_temp, path) = setup_test_dir();
        let cedar_auth = create_default_test_cedar_auth();
        let flags: Array = vec![Dynamic::from("not_a_flag")];

        let result = ls_rhai_with_flags(&path, &flags, &cedar_auth);
        assert!(result.is_err());
    }

    /// Given: A valid directory path with files
    /// When: Calling ls_rhai with the path
    /// Then: A Map with file names as keys is returned
    #[test]
    fn test_ls_rhai_returns_map() {
        let temp = TempDir::new().unwrap();
        temp.child("test.txt").write_str("content").unwrap();
        let test_dir = fs::canonicalize(temp.path()).unwrap();

        let cedar_auth = create_default_test_cedar_auth();
        let result = ls_rhai(test_dir.to_str().unwrap(), &cedar_auth);
        assert!(result.is_ok());
        let map = result.unwrap();
        assert!(map.contains_key("test.txt"));
    }
}
