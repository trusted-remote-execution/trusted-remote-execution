//! `wc` — Count lines, words, and bytes in a file
//!
//! # Example (Rhai)
//! ```rhai
//! let counts = wc("/path/to/file.txt");
//! print(`Lines: ${counts.lines}, Words: ${counts.words}, Bytes: ${counts.bytes}`);
//!
//! // Lines only
//! let counts = wc([wc::lines], "/path/to/file.txt");
//!
//! // Words only
//! let counts = wc([wc::words], "/path/to/file.txt");
//! ```

use super::open_file_from_path;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::{Array, Dynamic, Map};
use rhai_sdk_common_utils::args::{extract_flags, has_flag};
use rust_safe_io::errors::RustSafeIoError;

/// Flags for the `wc` command, registered as a Rhai custom type.
///
/// Available flags:
/// - `wc::lines` / `wc::l` — print only the line count
/// - `wc::words` / `wc::w` — print only the word count
/// - `wc::bytes` / `wc::c` — print only the byte count
#[derive(Debug, Clone)]
pub(crate) enum WcFlag {
    Lines,
    Words,
    Bytes,
}

pub(crate) struct WcOptions {
    pub lines: bool,
    pub words: bool,
    pub bytes: bool,
}

impl WcOptions {
    pub(crate) fn from_flags(flags: &[WcFlag]) -> Self {
        let lines = has_flag(flags, |f| matches!(f, WcFlag::Lines));
        let words = has_flag(flags, |f| matches!(f, WcFlag::Words));
        let bytes = has_flag(flags, |f| matches!(f, WcFlag::Bytes));
        // If no specific flag is set, include all
        if !lines && !words && !bytes {
            Self {
                lines: true,
                words: true,
                bytes: true,
            }
        } else {
            Self {
                lines,
                words,
                bytes,
            }
        }
    }
}

/// Returns line, word, and byte counts for a file.
pub(crate) fn wc(path: &str, cedar_auth: &CedarAuth) -> Result<Map, RustSafeIoError> {
    wc_with_flags(path, &Array::new(), cedar_auth)
}

/// Returns counts for a file, filtered by user-provided flags.
pub(crate) fn wc_with_flags(
    path: &str,
    flags_arr: &Array,
    cedar_auth: &CedarAuth,
) -> Result<Map, RustSafeIoError> {
    let flags = extract_flags::<WcFlag>(flags_arr)?;
    let opts = WcOptions::from_flags(&flags);

    let file_handle = open_file_from_path(path, cedar_auth)?;
    let counts = file_handle.counts(cedar_auth)?;

    let mut map = Map::new();
    #[allow(clippy::cast_possible_wrap)]
    if opts.lines {
        map.insert("lines".into(), Dynamic::from(*counts.line_count() as i64));
    }
    #[allow(clippy::cast_possible_wrap)]
    if opts.words {
        map.insert("words".into(), Dynamic::from(*counts.word_count() as i64));
    }
    #[allow(clippy::cast_possible_wrap)]
    if opts.bytes {
        map.insert("bytes".into(), Dynamic::from(*counts.byte_count() as i64));
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_fs::TempDir;
    use assert_fs::prelude::*;
    use rex_test_utils::rhai::common::create_default_test_cedar_auth;
    use std::fs;

    /// Given: A file with known content
    /// When: Calling wc on the file
    /// Then: Correct line, word, and byte counts are returned
    #[test]
    fn test_wc_basic() {
        let temp = TempDir::new().unwrap();
        temp.child("test.txt")
            .write_str("hello world\nfoo bar baz\n")
            .unwrap();
        let path = fs::canonicalize(temp.path().join("test.txt"))
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let cedar_auth = create_default_test_cedar_auth();

        let result = wc(&path, &cedar_auth).unwrap();
        assert_eq!(result["lines"].clone().cast::<i64>(), 2);
        assert_eq!(result["words"].clone().cast::<i64>(), 5);
    }

    /// Given: A file with known content and the Lines flag
    /// When: Calling wc_with_flags
    /// Then: Only the lines key is present
    #[test]
    fn test_wc_lines_only() {
        let temp = TempDir::new().unwrap();
        temp.child("test.txt")
            .write_str("hello world\nfoo bar baz\n")
            .unwrap();
        let path = fs::canonicalize(temp.path().join("test.txt"))
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let cedar_auth = create_default_test_cedar_auth();
        let flags: Array = vec![Dynamic::from(WcFlag::Lines)];

        let result = wc_with_flags(&path, &flags, &cedar_auth).unwrap();
        assert!(result.contains_key("lines"));
        assert!(!result.contains_key("words"));
        assert!(!result.contains_key("bytes"));
    }

    /// Given: An array with a non-WcFlag element
    /// When: Extracting flags
    /// Then: An error is returned
    #[test]
    fn test_wc_rejects_wrong_flag_type() {
        let temp = TempDir::new().unwrap();
        temp.child("test.txt").write_str("x").unwrap();
        let path = fs::canonicalize(temp.path().join("test.txt"))
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let cedar_auth = create_default_test_cedar_auth();
        let flags: Array = vec![Dynamic::from("not_a_flag")];

        let result = wc_with_flags(&path, &flags, &cedar_auth);
        assert!(result.is_err());
    }
}
