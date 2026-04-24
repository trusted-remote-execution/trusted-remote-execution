//! `tail` - Read lines from a file with line selection
//!
//! # Example (Rhai)
//! ```rhai
//! // Last 10 lines (default)
//! let lines = tail("/path/to/file.txt");
//!
//! // Last 5 lines
//! let lines = tail([tail::n(5)], "/path/to/file.txt");
//!
//! // From line 20 to end
//! let lines = tail([tail::from(20)], "/path/to/file.txt");
//!
//! // Lines 10-20
//! let lines = tail([tail::range(10, 20)], "/path/to/file.txt");
//! ```

use super::open_file_from_path;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::Array;
use rhai_sdk_common_utils::args::{extract_flags, find_flag_value};
use rust_safe_io::errors::RustSafeIoError;
use rust_safe_io::options::ReadLinesOptionsBuilder;

/// Flags for the `tail` command, registered as a Rhai custom type.
///
/// Available flags:
/// - `tail::n(count)` — read last N lines (negative = from end, positive = first N)
/// - `tail::from(line)` — start reading from line number (1-indexed)
/// - `tail::range(start, end)` — read lines from start to end (inclusive)
#[derive(Debug, Clone)]
pub(crate) enum TailFlag {
    Count(i64),
    From(i64),
    Range(i64, i64),
}

pub(crate) struct TailOptions {
    pub count: Option<i64>,
    pub start: Option<i64>,
}

impl TailOptions {
    pub(crate) fn from_flags(flags: &[TailFlag]) -> Self {
        let mut count = None;
        let mut start = None;

        if let Some((s, e)) = find_flag_value(flags, |f| match f {
            TailFlag::Range(s, e) => Some((*s, *e)),
            _ => None,
        }) {
            start = Some(s);
            // count = number of lines in range
            count = Some(e - s + 1);
        }

        if let Some(n) = find_flag_value(flags, |f| match f {
            TailFlag::Count(n) => Some(*n),
            _ => None,
        }) {
            count = Some(n);
        }

        if let Some(line) = find_flag_value(flags, |f| match f {
            TailFlag::From(n) => Some(*n),
            _ => None,
        }) {
            start = Some(line);
        }

        Self { count, start }
    }
}

/// Read last 10 lines from a file (default behavior)
pub(crate) fn tail(path: &str, cedar_auth: &CedarAuth) -> Result<Vec<String>, RustSafeIoError> {
    tail_with_flags(path, &Array::new(), cedar_auth)
}

/// Read lines from a file with user-provided flags
pub(crate) fn tail_with_flags(
    path: &str,
    flags_arr: &Array,
    cedar_auth: &CedarAuth,
) -> Result<Vec<String>, RustSafeIoError> {
    let flags = extract_flags::<TailFlag>(flags_arr)?;
    let opts = TailOptions::from_flags(&flags);

    let file_handle = open_file_from_path(path, cedar_auth)?;

    let mut builder = ReadLinesOptionsBuilder::default();

    match (opts.count, opts.start) {
        (Some(count), Some(start)) => {
            #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
            builder.start(start as usize);
            #[allow(clippy::cast_possible_truncation)]
            builder.count(count as isize);
        }
        (Some(count), None) => {
            #[allow(clippy::cast_possible_truncation)]
            builder.count(count as isize);
        }
        (None, Some(start)) => {
            #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
            builder.start(start as usize);
        }
        (None, None) => {
            // Default: last 10 lines
            builder.count(-10_isize);
        }
    }

    let options = builder
        .build()
        .map_err(|e| RustSafeIoError::InvalidArguments {
            reason: e.to_string(),
        })?;

    file_handle.safe_read_lines(cedar_auth, options)
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_fs::TempDir;
    use assert_fs::prelude::*;
    use rex_test_utils::rhai::common::create_default_test_cedar_auth;
    use rhai::Dynamic;
    use std::fs;

    fn create_numbered_file(n: usize) -> (TempDir, String) {
        let temp = TempDir::new().unwrap();
        let content: String = (1..=n)
            .map(|i| format!("line{i}"))
            .collect::<Vec<_>>()
            .join("\n");
        temp.child("test.txt").write_str(&content).unwrap();
        let path = fs::canonicalize(temp.path().join("test.txt"))
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        (temp, path)
    }

    /// Given: A file with 15 lines
    /// When: Calling tail with default options
    /// Then: The last 10 lines are returned
    #[test]
    fn test_tail_default_last_10() {
        let (_temp, path) = create_numbered_file(15);
        let cedar_auth = create_default_test_cedar_auth();

        let result = tail(&path, &cedar_auth).unwrap();
        assert_eq!(result.len(), 10);
        assert_eq!(result[0], "line6");
        assert_eq!(result[9], "line15");
    }

    /// Given: A file with 15 lines and a Count(5) flag
    /// When: Calling tail_with_flags
    /// Then: The last 5 lines are returned
    #[test]
    fn test_tail_last_n() {
        let (_temp, path) = create_numbered_file(15);
        let cedar_auth = create_default_test_cedar_auth();
        let flags: Array = vec![Dynamic::from(TailFlag::Count(-5))];

        let result = tail_with_flags(&path, &flags, &cedar_auth).unwrap();
        assert_eq!(result.len(), 5);
        assert_eq!(result[0], "line11");
    }

    /// Given: An array with a non-TailFlag element
    /// When: Extracting flags
    /// Then: An error is returned
    #[test]
    fn test_tail_rejects_wrong_flag_type() {
        let (_temp, path) = create_numbered_file(5);
        let cedar_auth = create_default_test_cedar_auth();
        let flags: Array = vec![Dynamic::from("not_a_flag")];

        let result = tail_with_flags(&path, &flags, &cedar_auth);
        assert!(result.is_err());
    }
}
