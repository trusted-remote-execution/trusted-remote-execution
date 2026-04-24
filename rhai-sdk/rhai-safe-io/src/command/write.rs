//! `write` — Write content to a file with configurable mode
//!
//! # Example (Rhai)
//! ```rhai
//! // Append (default when no flags)
//! write("/tmp/file.txt", "appended line\n");
//!
//! // Explicit append
//! write([write::append], "/tmp/file.txt", "appended line\n");
//!
//! // Overwrite (replace)
//! write([write::replace], "/tmp/file.txt", "new content\n");
//! ```

use super::open_dir_from_path;
use super::open_writable;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::Array;
use rhai_sdk_common_utils::args::{extract_flags, has_flag};
use rust_safe_io::errors::RustSafeIoError;
use rust_safe_io::options::OpenFileOptionsBuilder;
use std::path::Path;

/// Flags for the `write` command.
///
/// - `write::append` — append to file (default)
/// - `write::replace` — overwrite file contents
#[derive(Debug, Clone)]
pub(crate) enum WriteFlag {
    Append,
    Replace,
}

/// Write content to a file, defaulting to append mode.
pub(crate) fn write(
    path: &str,
    content: &str,
    cedar_auth: &CedarAuth,
) -> Result<(), RustSafeIoError> {
    append(path, content, cedar_auth)
}

/// Write content to a file with user-provided flags.
pub(crate) fn write_with_flags(
    path: &str,
    content: &str,
    flags_arr: &Array,
    cedar_auth: &CedarAuth,
) -> Result<(), RustSafeIoError> {
    let flags = extract_flags::<WriteFlag>(flags_arr)?;

    if has_flag(&flags, |f| matches!(f, WriteFlag::Replace)) {
        replace(path, content, cedar_auth)
    } else {
        append(path, content, cedar_auth)
    }
}

/// Overwrites a file with the given content, creating it if it doesn't exist.
fn replace(path: &str, content: &str, cedar_auth: &CedarAuth) -> Result<(), RustSafeIoError> {
    let file_handle = open_writable(path, cedar_auth)?;
    file_handle.safe_write_in_place(cedar_auth, content)
}

/// Appends content to a file, creating it if it doesn't exist.
fn append(path: &str, content: &str, cedar_auth: &CedarAuth) -> Result<(), RustSafeIoError> {
    let path_obj = Path::new(path);
    let dir_path = path_obj
        .parent()
        .map_or_else(|| ".".to_string(), |p| p.to_string_lossy().to_string());
    let file_name = path_obj
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .ok_or_else(|| RustSafeIoError::InvalidArguments {
            reason: format!("Invalid file path: {path}"),
        })?;

    let dir_handle = open_dir_from_path(&dir_path, cedar_auth)?;
    let file_handle = dir_handle.safe_open_file(
        cedar_auth,
        &file_name,
        OpenFileOptionsBuilder::default()
            .read(true)
            .write(true)
            .create(true)
            .build()
            .map_err(|e| RustSafeIoError::InvalidArguments {
                reason: e.to_string(),
            })?,
    )?;

    let existing = file_handle.safe_read(cedar_auth).unwrap_or_default();
    let combined = format!("{existing}{content}");
    file_handle.safe_write_in_place(cedar_auth, &combined)
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_fs::TempDir;
    use rex_test_utils::rhai::common::create_default_test_cedar_auth;
    use rhai::Dynamic;
    use std::fs;

    fn create_temp_file(content: &str) -> (TempDir, String) {
        let temp = TempDir::new().unwrap();
        let path = fs::canonicalize(temp.path()).unwrap().join("test.txt");
        let path_str = path.to_str().unwrap().to_string();
        let cedar_auth = create_default_test_cedar_auth();
        replace(&path_str, content, &cedar_auth).unwrap();
        (temp, path_str)
    }

    #[test]
    fn test_write_default_appends() {
        let (_temp, path) = create_temp_file("first\n");
        let cedar_auth = create_default_test_cedar_auth();
        write(&path, "second\n", &cedar_auth).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "first\nsecond\n");
    }

    #[test]
    fn test_write_append_flag() {
        let (_temp, path) = create_temp_file("first\n");
        let cedar_auth = create_default_test_cedar_auth();
        let flags: Array = vec![Dynamic::from(WriteFlag::Append)];
        write_with_flags(&path, "second\n", &flags, &cedar_auth).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "first\nsecond\n");
    }

    #[test]
    fn test_write_replace_flag() {
        let (_temp, path) = create_temp_file("first\n");
        let cedar_auth = create_default_test_cedar_auth();
        let flags: Array = vec![Dynamic::from(WriteFlag::Replace)];
        write_with_flags(&path, "replaced\n", &flags, &cedar_auth).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "replaced\n");
    }

    #[test]
    fn test_write_creates_file() {
        let temp = TempDir::new().unwrap();
        let path = fs::canonicalize(temp.path())
            .unwrap()
            .join("new.txt")
            .to_str()
            .unwrap()
            .to_string();
        let cedar_auth = create_default_test_cedar_auth();
        write(&path, "hello\n", &cedar_auth).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "hello\n");
    }

    #[test]
    fn test_replace_creates_file() {
        let temp = TempDir::new().unwrap();
        let path = fs::canonicalize(temp.path())
            .unwrap()
            .join("output.txt")
            .to_str()
            .unwrap()
            .to_string();
        let cedar_auth = create_default_test_cedar_auth();
        replace(&path, "hello world\n", &cedar_auth).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "hello world\n");
    }

    #[test]
    fn test_replace_overwrites_existing() {
        let (_temp, path) = create_temp_file("first\n");
        let cedar_auth = create_default_test_cedar_auth();
        replace(&path, "second\n", &cedar_auth).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "second\n");
    }

    #[test]
    fn test_append_adds_to_existing() {
        let (_temp, path) = create_temp_file("line one\n");
        let cedar_auth = create_default_test_cedar_auth();
        append(&path, "line two\n", &cedar_auth).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "line one\nline two\n");
    }

    #[test]
    fn test_write_rejects_wrong_flag_type() {
        let (_temp, path) = create_temp_file("content");
        let cedar_auth = create_default_test_cedar_auth();
        let flags: Array = vec![Dynamic::from("not_a_flag")];
        let result = write_with_flags(&path, "x", &flags, &cedar_auth);
        assert!(result.is_err());
    }
}
