//! Search utility functions for line-by-line searching.
//!
//! This module provides streaming search functionality that works with any
//! `BufRead` source, enabling memory-efficient searching for both regular
//! files and gzipped files.

use regex::Regex;
use std::io::BufRead;

use crate::errors::RustSafeIoError;
use crate::file::Match;
use crate::redaction::redact_content_using_patterns;

/// Search that works with any [`BufRead`] source.
///
/// This function performs line-by-line regex searching using streaming,
/// which is memory efficient as it never loads the entire file into memory.
///
/// # Arguments
/// * `reader` - Any `BufRead` source to search
/// * `regex` - The regex pattern to match against each line
/// * `redaction_patterns` - Optional redaction patterns. If `Some`, lines will be
///   redacted before matching and the redacted content will be returned.
///
/// # Regex Pattern Note
///
/// This function uses the Rust `regex` crate, which does not support PCRE's `\K` (keep) assertion.
/// To achieve the same effect, remove `\K` and wrap the text you want to capture in parentheses `()`.
///
/// Example:
/// ```no_run
/// // PCRE pattern with \K (not supported)
/// // "execfn: '\K[^']+"
///
/// // Equivalent Rust regex pattern
/// // "execfn: '([^']+)"
/// ```
pub(crate) fn search_lines<R: BufRead>(
    reader: R,
    regex: &Regex,
    redaction_patterns: Option<&[String]>,
) -> Result<Vec<Match>, RustSafeIoError> {
    let mut matches = Vec::new();

    for (line_index, line_result) in reader.lines().enumerate() {
        let line = line_result?;
        if regex.is_match(&line) {
            let redacted_content = match redaction_patterns {
                Some(patterns) => redact_content_using_patterns(&line, patterns),
                None => line,
            };
            // Since enumerate is 0 indexed, we are just increment by 1 to be 1 indexed so that it's human-readable
            matches.push(Match {
                line_number: line_index + 1,
                line_content: redacted_content,
            });
        }
    }

    Ok(matches)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Given: A BufRead source with multiple lines and a regex pattern
    /// When: search_lines is called
    /// Then: Only matching lines are returned with correct line numbers
    #[test]
    fn test_search_lines_finds_matches() {
        let content = "line one\nerror on line two\nline three\nanother error here\n";
        let reader = Cursor::new(content);
        let regex = Regex::new("error").unwrap();

        let result = search_lines(reader, &regex, None).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].line_number, 2);
        assert_eq!(result[0].line_content, "error on line two");
        assert_eq!(result[1].line_number, 4);
        assert_eq!(result[1].line_content, "another error here");
    }

    /// Given: A BufRead source with no matching lines
    /// When: search_lines is called
    /// Then: An empty vector is returned
    #[test]
    fn test_search_lines_no_matches() {
        let content = "line one\nline two\nline three\n";
        let reader = Cursor::new(content);
        let regex = Regex::new("error").unwrap();

        let result = search_lines(reader, &regex, None).unwrap();

        assert!(result.is_empty());
    }

    /// Given: An empty BufRead source
    /// When: search_lines is called
    /// Then: An empty vector is returned
    #[test]
    fn test_search_lines_empty_input() {
        let content = "";
        let reader = Cursor::new(content);
        let regex = Regex::new(".*").unwrap();

        let result = search_lines(reader, &regex, None).unwrap();

        assert!(result.is_empty());
    }

    /// Given: A BufRead source with all matching lines
    /// When: search_lines is called with a broad pattern
    /// Then: All lines are returned
    #[test]
    fn test_search_lines_all_match() {
        let content = "error one\nerror two\nerror three\n";
        let reader = Cursor::new(content);
        let regex = Regex::new("error").unwrap();

        let result = search_lines(reader, &regex, None).unwrap();

        assert_eq!(result.len(), 3);
        assert_eq!(result[0].line_number, 1);
        assert_eq!(result[1].line_number, 2);
        assert_eq!(result[2].line_number, 3);
    }

    /// Given: A BufRead source with case-sensitive content
    /// When: search_lines is called with a case-insensitive regex
    /// Then: Case-insensitive matches are found
    #[test]
    fn test_search_lines_case_insensitive() {
        let content = "ERROR uppercase\nerror lowercase\nErRoR mixed\n";
        let reader = Cursor::new(content);
        let regex = Regex::new("(?i)error").unwrap();

        let result = search_lines(reader, &regex, None).unwrap();

        assert_eq!(result.len(), 3);
    }

    /// Given: A BufRead source with content and redaction patterns
    /// When: search_lines is called with redaction patterns
    /// Then: Lines are redacted and only matching redacted lines are returned
    #[test]
    fn test_search_lines_with_redaction() {
        let content = "sensitive data\nerror: something went wrong\nnormal line\n";
        let reader = Cursor::new(content);
        let regex = Regex::new("error").unwrap();
        // Pattern that matches lines containing "error"
        let redaction_patterns = vec!["error.*".to_string()];

        let result = search_lines(reader, &regex, Some(&redaction_patterns)).unwrap();

        // Only the "error" line matches and is preserved, others would be [REDACTED]
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].line_number, 2);
        assert_eq!(result[0].line_content, "error: something went wrong");
    }
}
