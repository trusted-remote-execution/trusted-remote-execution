//! `ls` - List directory contents at path
//!
//! If the path is a directory, lists its contents (hidden files excluded by default).
//! If the path is a symlink, returns a single-entry Map with the symlink's `DirEntry`.
//!
//! # Cedar Permissions
//!
//! | Action | Resource |
//! |--------|----------|
//! | `file_system::Action::"open"` | [`file_system::Dir::"<absolute_path>"`](rex_cedar_auth::fs::entities::DirEntity) |
//! | `file_system::Action::"read"` | [`file_system::Dir::"<absolute_path>"`](rex_cedar_auth::fs::entities::DirEntity) |
//!
//! # Flags
//!
//! | Flag | Alias | Description |
//! |------|-------|-------------|
//! | `ls::all` | `ls::a` | Include hidden entries (names starting with `.`) |
//!
//! # Returns
//!
//! `Map` — keys are filenames (`String`), values are [`DirEntry`](crate::dir_entry::DirEntry) objects
//! with `name()`, `type()`, `inode()`, `open_as_file()`, `open_as_dir()`, and `metadata()`.
//!
//! # Example
//!
//! ```
//! # use rex_test_utils::rhai::safe_io::create_temp_test_env;
//! # let (mut scope, engine) = create_temp_test_env();
//! # let result = engine.eval_with_scope::<()>(
//! # &mut scope,
//! # r#"
//! # let dir_handle = DirConfig().path(temp_dir_path).build()
//! #     .open(OpenDirOptions().create(true).build());
//! # dir_handle.open_file("file1.txt", OpenFileOptions().create(true).write(true).build())
//! #     .write("hello");
//! # dir_handle.open_file(".hidden", OpenFileOptions().create(true).build());
//! # let path = temp_dir_path;
//! let entries = ls(path);
//! for name in entries.keys() {
//!     print(name);
//! }
//!
//! // Include hidden files
//! let all_entries = ls([ls::all], path);
//!
//! // Access DirEntry values
//! for entry in entries.values() {
//!     if entry.type() == EntryType::FILE {
//!         let fh = entry.open_as_file(OpenFileOptions().read(true).build());
//!         print(fh.read());
//!     }
//! }
//! # "#);
//! # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
//! ```

use super::open_dir_from_path;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::{Array, Dynamic, Map};
use rhai_sdk_common_utils::args::{extract_flags, has_flag};
use rust_safe_io::error_constants::{NOT_A_DIR, NOT_A_SYMLINK};
use rust_safe_io::{DirEntry, errors::RustSafeIoError};
use std::path::Path;

/// Flags for the `ls` command, registered as a Rhai custom type.
///
/// Available flags:
/// - `ls::all` / `ls::a` — include hidden entries (names starting with '.')
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
///
/// If the path is a directory, lists its contents.
/// If the path is a symlink, returns a single-element Vec containing the symlink's DirEntry.
pub(crate) fn ls(
    path: &str,
    options: &LsOptions,
    cedar_auth: &CedarAuth,
) -> Result<Vec<DirEntry>, RustSafeIoError> {
    // If the path is a symlink, handle it directly rather than opening the target directory.
    // open_dir_from_path uses follow_symlinks(true) which would transparently open
    // the symlink's target directory instead of treating the symlink itself as the entry.
    if std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        return try_ls_as_symlink(path, cedar_auth);
    }

    match open_dir_from_path(path, cedar_auth) {
        Ok(dir_handle) => {
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
        Err(RustSafeIoError::DirectoryOpenError { ref reason, .. })
            if reason.starts_with(NOT_A_DIR) =>
        {
            try_ls_as_symlink(path, cedar_auth)
        }
        Err(ref e) if e.to_string().contains(NOT_A_DIR) => try_ls_as_symlink(path, cedar_auth),
        Err(e) => Err(e),
    }
}

/// Path is not a directory - try to open as symlink.
/// Only convert NOT_A_SYMLINK errors; propagate auth/IO errors.
fn try_ls_as_symlink(path: &str, cedar_auth: &CedarAuth) -> Result<Vec<DirEntry>, RustSafeIoError> {
    try_ls_symlink(path, cedar_auth).map_err(|e| {
        if matches!(&e, RustSafeIoError::ValidationError { reason } if reason.contains(NOT_A_SYMLINK))
        {
            RustSafeIoError::InvalidArguments {
                reason: format!("ls: {path}: Not a directory or symlink"),
            }
        } else {
            e
        }
    })
}

/// Attempt to list a symlink path by opening it as a symlink and creating a DirEntry.
fn try_ls_symlink(path: &str, cedar_auth: &CedarAuth) -> Result<Vec<DirEntry>, RustSafeIoError> {
    let path_obj = Path::new(path);

    let parent_path = path_obj
        .parent()
        .map_or_else(|| ".".to_string(), |p| p.to_string_lossy().to_string());

    let name = path_obj
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .ok_or_else(|| RustSafeIoError::InvalidArguments {
            reason: format!("Invalid path: {path}"),
        })?;

    let parent_handle = open_dir_from_path(&parent_path, cedar_auth)?;

    // Try to open as symlink - this will fail if it's not a symlink
    let symlink_handle = parent_handle.safe_open_symlink(cedar_auth, &name)?;

    // Create a DirEntry from the symlink handle
    let entry = DirEntry::from_symlink_handle(&parent_handle, symlink_handle)?;

    Ok(vec![entry])
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
