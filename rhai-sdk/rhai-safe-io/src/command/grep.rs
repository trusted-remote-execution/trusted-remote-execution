//! `grep` - Search for patterns in file contents
//!
//! # Example (Rhai)
//! ```rhai
//! // Simple usage
//! let matches = grep("pattern", "/path/to/file.txt");
//!
//! // With flags
//! let matches = grep([grep::ignore_case, grep::line_number], "pattern", "/path/to/file.txt");
//!
//! // With value-carrying flag
//! let matches = grep([grep::ignore_case, max_count(5)], "pattern", "/path/to/file.txt");
//! ```

use super::open_file_from_path;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::Array;
use rhai_sdk_common_utils::args::{extract_flags, find_flag_value, has_flag};
use rust_safe_io::errors::RustSafeIoError;

/// Flags for the `grep` command, registered as a Rhai custom type.
///
/// Available flags:
/// - `grep::ignore_case` / `grep::i` — case-insensitive matching
/// - `grep::count` / `grep::c` — only print a count of matching lines
/// - `grep::invert` / `grep::v` — select non-matching lines
/// - `grep::line_number` / `grep::n` — prefix each line with its line number
/// - `max_count(n)` / `m(n)` — stop after n matches
#[derive(Debug, Clone)]
pub(crate) enum GrepFlag {
    IgnoreCase,
    Count,
    Invert,
    LineNumber,
    MaxCount(i64),
}

/// Parsed options from `GrepFlag` values.
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct GrepOptions {
    pub ignore_case: bool,
    pub count: bool,
    pub invert: bool,
    pub line_number: bool,
    pub max_count: Option<i64>,
}

impl GrepOptions {
    pub(crate) fn from_flags(flags: &[GrepFlag]) -> Self {
        Self {
            ignore_case: has_flag(flags, |f| matches!(f, GrepFlag::IgnoreCase)),
            count: has_flag(flags, |f| matches!(f, GrepFlag::Count)),
            invert: has_flag(flags, |f| matches!(f, GrepFlag::Invert)),
            line_number: has_flag(flags, |f| matches!(f, GrepFlag::LineNumber)),
            max_count: find_flag_value(flags, |f| match f {
                GrepFlag::MaxCount(n) => Some(*n),
                _ => None,
            }),
        }
    }
}

/// Search for a pattern in a file with default options.
/// Uses `safe_search` under the hood for streaming regex matching.
pub(crate) fn grep(
    pattern: &str,
    path: &str,
    cedar_auth: &CedarAuth,
) -> Result<Vec<String>, RustSafeIoError> {
    grep_with_flags(pattern, path, &Array::new(), cedar_auth)
}

/// Search for a pattern in a file with user-provided flags.
/// Wraps `safe_search` and applies post-processing based on flags.
pub(crate) fn grep_with_flags(
    pattern: &str,
    path: &str,
    flags_arr: &Array,
    cedar_auth: &CedarAuth,
) -> Result<Vec<String>, RustSafeIoError> {
    let flags = extract_flags::<GrepFlag>(flags_arr)?;
    let opts = GrepOptions::from_flags(&flags);

    let search_pattern = if opts.ignore_case {
        format!("(?i){pattern}")
    } else {
        pattern.to_string()
    };

    let file_handle = open_file_from_path(path, cedar_auth)?;
    let all_matches = file_handle.safe_search(cedar_auth, &search_pattern)?;

    let filtered: Vec<_> = if opts.invert {
        let content = file_handle.safe_read(cedar_auth)?;
        let match_lines: std::collections::HashSet<usize> =
            all_matches.iter().map(|m| m.line_number).collect();
        content
            .lines()
            .enumerate()
            .filter(|(i, _)| !match_lines.contains(&(i + 1)))
            .map(|(i, line)| (i + 1, line.to_string()))
            .collect()
    } else {
        all_matches
            .into_iter()
            .map(|m| (m.line_number, m.line_content))
            .collect()
    };

    let capped = match opts.max_count {
        Some(n) if n > 0 => {
            #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
            let limit = n as usize;
            filtered.into_iter().take(limit).collect::<Vec<_>>()
        }
        _ => filtered,
    };

    if opts.count {
        return Ok(vec![capped.len().to_string()]);
    }

    let output: Vec<String> = if opts.line_number {
        capped
            .into_iter()
            .map(|(num, content)| format!("{num}:{content}"))
            .collect()
    } else {
        capped.into_iter().map(|(_, content)| content).collect()
    };

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rhai::Dynamic;

    /// Given: A set of GrepFlag values including a value-carrying variant
    /// When: Parsing GrepOptions
    /// Then: All flags are captured correctly
    #[test]
    fn test_grep_options_from_flags() {
        let flags = vec![
            GrepFlag::IgnoreCase,
            GrepFlag::LineNumber,
            GrepFlag::MaxCount(10),
        ];
        let opts = GrepOptions::from_flags(&flags);
        assert!(opts.ignore_case);
        assert!(opts.line_number);
        assert!(!opts.count);
        assert!(!opts.invert);
        assert_eq!(opts.max_count, Some(10));
    }

    /// Given: An array with a non-GrepFlag element
    /// When: Extracting flags
    /// Then: An error is returned
    #[test]
    fn test_grep_rejects_wrong_flag_type() {
        let arr: Array = vec![Dynamic::from("not_a_flag")];
        let result = extract_flags::<GrepFlag>(&arr);
        assert!(result.is_err());
    }

    /// Given: A file with matching content
    /// When: Calling grep with a pattern
    /// Then: Matching lines are returned
    #[test]
    fn test_grep_basic_match() {
        use assert_fs::TempDir;
        use assert_fs::prelude::*;
        use rex_test_utils::rhai::common::create_default_test_cedar_auth;
        use std::fs;

        let temp = TempDir::new().unwrap();
        temp.child("test.txt")
            .write_str("hello world\nfoo bar\nhello again")
            .unwrap();
        let path = fs::canonicalize(temp.path().join("test.txt"))
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let cedar_auth = create_default_test_cedar_auth();

        let result = grep("hello", &path, &cedar_auth).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], "hello world");
        assert_eq!(result[1], "hello again");
    }
}
