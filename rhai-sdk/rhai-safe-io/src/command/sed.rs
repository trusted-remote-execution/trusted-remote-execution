//! `sed` - Stream editor for find/replace in files
//!
//! # Example (Rhai)
//! ```rhai
//! // Simple string replacement (returns modified content)
//! let result = sed("old", "new", "/path/to/file.txt");
//!
//! // Replace all occurrences
//! let result = sed([sed::all], "old", "new", "/path/to/file.txt");
//!
//! // Regex replacement
//! let result = sed([sed::regex, sed::all], "err\\d+", "ERROR", "/path/to/file.txt");
//!
//! // In-place modification
//! sed([sed::in_place, sed::all], "old", "new", "/path/to/file.txt");
//! ```

use super::{open_dir_from_path, open_file_from_path};
use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::Array;
use rhai_sdk_common_utils::args::{extract_flags, has_flag};
use rust_safe_io::RcFileHandle;
use rust_safe_io::errors::RustSafeIoError;
use rust_safe_io::options::{OpenFileOptionsBuilder, ReplacementOptionsBuilder};
use std::path::Path;

/// Opens a file with both read and write permissions.
fn open_file_rw(path: &str, cedar_auth: &CedarAuth) -> Result<RcFileHandle, RustSafeIoError> {
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
    let file_options = OpenFileOptionsBuilder::default()
        .read(true)
        .write(true)
        .build()
        .map_err(|e| RustSafeIoError::InvalidArguments {
            reason: e.to_string(),
        })?;
    dir_handle.safe_open_file(cedar_auth, &file_name, file_options)
}

/// Flags for the `sed` command, registered as a Rhai custom type.
///
/// Available flags:
/// - `sed::regex` — treat pattern as regex
/// - `sed::all` / `sed::g` — replace all occurrences (not just first)
/// - `sed::in_place` / `sed::i` — modify file in place (otherwise returns new content)
#[derive(Debug, Clone)]
pub(crate) enum SedFlag {
    Regex,
    All,
    InPlace,
}

pub(crate) struct SedOptions {
    pub is_regex: bool,
    pub replace_all: bool,
    pub in_place: bool,
}

impl SedOptions {
    pub(crate) fn from_flags(flags: &[SedFlag]) -> Self {
        Self {
            is_regex: has_flag(flags, |f| matches!(f, SedFlag::Regex)),
            replace_all: has_flag(flags, |f| matches!(f, SedFlag::All)),
            in_place: has_flag(flags, |f| matches!(f, SedFlag::InPlace)),
        }
    }
}

/// Find/replace in a file with default options (first occurrence, literal string)
pub(crate) fn sed(
    pattern: &str,
    replacement: &str,
    path: &str,
    cedar_auth: &CedarAuth,
) -> Result<String, RustSafeIoError> {
    sed_with_flags(pattern, replacement, path, &Array::new(), cedar_auth)
}

/// Find/replace in a file with user-provided flags
pub(crate) fn sed_with_flags(
    pattern: &str,
    replacement: &str,
    path: &str,
    flags_arr: &Array,
    cedar_auth: &CedarAuth,
) -> Result<String, RustSafeIoError> {
    let flags = extract_flags::<SedFlag>(flags_arr)?;
    let opts = SedOptions::from_flags(&flags);

    let file_handle = if opts.in_place {
        open_file_rw(path, cedar_auth)?
    } else {
        open_file_from_path(path, cedar_auth)?
    };
    let content = file_handle.safe_read(cedar_auth)?;

    let replacement_options = ReplacementOptionsBuilder::default()
        .is_regex(opts.is_regex)
        .replace_all(opts.replace_all)
        .build()
        .map_err(|e| RustSafeIoError::InvalidArguments {
            reason: e.to_string(),
        })?;

    let result = rust_safe_io::replace_text(&content, pattern, replacement, replacement_options)?;

    if opts.in_place {
        file_handle.safe_write_in_place(cedar_auth, &result)?;
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rex_test_utils::rhai::common::{create_default_test_cedar_auth, create_test_file};
    use rhai::Dynamic;

    /// Given: A file with content containing "hello"
    /// When: Calling sed to replace "hello" with "world"
    /// Then: The first occurrence is replaced
    #[test]
    fn test_sed_basic_replace() {
        let (_temp, path) = create_test_file("hello hello");
        let cedar_auth = create_default_test_cedar_auth();

        let result = sed("hello", "world", &path, &cedar_auth).unwrap();
        assert_eq!(result, "world hello");
    }

    /// Given: A file with repeated content and the All flag
    /// When: Calling sed_with_flags
    /// Then: All occurrences are replaced
    #[test]
    fn test_sed_replace_all() {
        let (_temp, path) = create_test_file("hello hello hello");
        let cedar_auth = create_default_test_cedar_auth();
        let flags: Array = vec![Dynamic::from(SedFlag::All)];

        let result = sed_with_flags("hello", "world", &path, &flags, &cedar_auth).unwrap();
        assert_eq!(result, "world world world");
    }

    /// Given: An array with a non-SedFlag element
    /// When: Calling sed_with_flags
    /// Then: An error is returned
    #[test]
    fn test_sed_rejects_wrong_flag_type() {
        let (_temp, path) = create_test_file("content");
        let cedar_auth = create_default_test_cedar_auth();
        let flags: Array = vec![Dynamic::from("not_a_flag")];

        let result = sed_with_flags("a", "b", &path, &flags, &cedar_auth);
        assert!(result.is_err());
    }
}
