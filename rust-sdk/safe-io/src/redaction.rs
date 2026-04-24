use crate::DirConfigBuilder;
use crate::RustSafeIoError;
use crate::constants::REDACTION_DICTIONARY;
use crate::options::{OpenDirOptionsBuilder, OpenFileOptionsBuilder};
use crate::{get_basename, get_parent};
use anyhow::Error;
use regex::Regex;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_logger::debug;
use rex_redaction::printf_converter::printf_to_regex;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::OnceLock;

/// Cached redaction patterns initialized once per process to prevent TOCTOU attacks.
/// This cache ensures the redaction dictionary is read only once, preventing scenario where dictionary file is
/// manipulated between multiple `redact_content()` calls.
/// First call initializes from dictionary file, subsequent calls reuse cached patterns.
static CACHED_REDACTION_PATTERNS: OnceLock<Vec<String>> = OnceLock::new();

pub(crate) fn redact_content(
    cedar_auth: &CedarAuth,
    content: &str,
) -> Result<String, RustSafeIoError> {
    let regex_patterns = build_or_get_pattern_cache(cedar_auth)?;
    Ok(redact_content_using_patterns(content, regex_patterns))
}

pub(crate) fn build_or_get_pattern_cache(
    cedar_auth: &CedarAuth,
) -> Result<&Vec<String>, RustSafeIoError> {
    if let Some(patterns) = CACHED_REDACTION_PATTERNS.get() {
        return Ok(patterns);
    }

    let redaction_dictionary_content = read_redaction_dictionary(cedar_auth)?;

    let patterns = convert_entries_to_regex_str(&redaction_dictionary_content);
    debug!("Redaction patterns cached with patterns: {patterns:?}");
    CACHED_REDACTION_PATTERNS.set(patterns).map_err(|_| {
        RustSafeIoError::Other(Error::msg(
            "Race condition: redaction pattern cache already initialized by another thread",
        ))
    })?;
    CACHED_REDACTION_PATTERNS.get().ok_or_else(|| {
        RustSafeIoError::Other(Error::msg(
            "Failed to get cached redaction patterns: internal error",
        ))
    })
}

fn read_redaction_dictionary(cedar_auth: &CedarAuth) -> Result<String, RustSafeIoError> {
    let parent_dir = get_parent(REDACTION_DICTIONARY);
    let filename = get_basename(REDACTION_DICTIONARY);

    let dir_handle = DirConfigBuilder::default()
        .path(parent_dir.clone())
        .build()?
        .safe_open(cedar_auth, OpenDirOptionsBuilder::default().follow_symlinks(true).build()?)
        .map_err(|e| RustSafeIoError::DirectoryError {
            reason: format!("Failed to open redaction dictionary directory: {e}"),
            path: PathBuf::from(parent_dir),
            source: Box::new(e),
        })?;

    let file_handle = dir_handle
        .safe_open_file(
            cedar_auth,
            &filename,
            OpenFileOptionsBuilder::default()
                .read(true)
                .build()
                .map_err(|e| RustSafeIoError::InvalidArguments {
                    reason: format!("Failed to build file options for redaction dictionary: {e}"),
                })?,
        )
        .map_err(|e| RustSafeIoError::FileError {
            reason: format!("Failed to open redaction dictionary file: {e}"),
            path: PathBuf::from(REDACTION_DICTIONARY),
            source: Box::new(e),
        })?;

    file_handle.safe_read(cedar_auth)
}

/// converting regex with soft failure - invalid patterns are logged and skipped
/// but processing continues with remaining valid patterns.
fn convert_entries_to_regex_str(redaction_entries: &str) -> Vec<String> {
    let regex_patterns: Vec<String> = redaction_entries
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| printf_to_regex(line).ok())
        .collect();

    debug!(
        "Successfully compiled {} redaction regex patterns",
        regex_patterns.len()
    );

    regex_patterns
}

pub(crate) fn redact_content_using_patterns(content: &str, str_patterns: &[String]) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let mut lines_to_keep = HashSet::new();

    for pattern in str_patterns {
        if let Ok(regex) = Regex::new(pattern) {
            for (line_idx, line) in lines.iter().enumerate() {
                if regex.is_match(line) {
                    lines_to_keep.insert(line_idx);
                }
            }
        }
    }

    lines
        .iter()
        .enumerate()
        .map(|(i, line)| {
            if lines_to_keep.contains(&i) {
                *line
            } else {
                "[REDACTED]"
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Given: Individual printf format specifiers
    /// When: convert_entries_to_regex_str is called on each specifier  
    /// Then: Each specifier is converted to its regex equivalent
    #[rstest]
    #[case(
        "could not open file \"%s\" for reading: %m", 
        vec!["could not open file \"(\\S+)\" for reading: .*?"],
        "single pattern with %s and %m conversion"
    )]
    #[case(
        "error %d:\nprocessing %zu bytes",
        vec!["error (-?\\d+):", "processing (\\d+) bytes"],
        "multiple patterns with %d and %zu conversion"
    )]
    #[case(
        "# Comment line\nerror %d:\n  \n# Another comment\nfile \"%s\" not found",
        vec!["error (-?\\d+):", "file \"(\\S+)\" not found"],
        "patterns with comments filtered correctly"
    )]
    #[case(
        "",
        vec![],
        "empty dictionary produces no patterns"
    )]
    #[case(
        "# Only comments\n  \n# More comments  \n",
        vec![],
        "only comments and whitespace produce no patterns"
    )]
    #[case(
        "error code %lu\netween \"%f\" and \"%f\".\n(%.2f%% of total)\ncould not read two-phase state from WAL at %X/%X\npercentile value %g is not between 0 and 1", 
        vec![],
        "all invalid patterns should result in empty vector"
    )]
    fn test_convert_entries_to_regex_pattern_count(
        #[case] dictionary_content: &str,
        #[case] expected_regex: Vec<&str>,
        #[case] description: &str,
    ) {
        let regex_patterns = convert_entries_to_regex_str(dictionary_content);

        let actual_patterns: Vec<String> = regex_patterns
            .iter()
            .map(|regex| regex.as_str().to_string())
            .collect();
        for (i, expected_pattern) in expected_regex.iter().enumerate() {
            assert_eq!(
                actual_patterns[i], *expected_pattern,
                "Pattern mismatch in: {description}. Expected '{expected_pattern}', got '{}'",
                actual_patterns[i]
            );
        }
    }

    /// Given: content and list of regex patterns
    /// When: apply_redaction_to_content is called on each specifier  
    /// Then: All line that didn't should be redacted
    #[rstest]
    #[case(
        vec!["could not open file \".*?\" for reading: .*?".to_string()],
        "Normal log\ncould not open file \"test.txt\" for reading: Permission denied\nAnother log",
        "[REDACTED]\ncould not open file \"test.txt\" for reading: Permission denied\n[REDACTED]",
        "should preserve file operation patterns"
    )]
    #[case(
        vec!["error \\d+ occurred".to_string()],                   
        "Starting up\nerror 404 occurred\nShutting down",
        "[REDACTED]\nerror 404 occurred\n[REDACTED]", 
        "should preserve error code patterns"
    )]
    #[case(
        vec!["processing \\d+ bytes".to_string()],
        "Begin processing\nprocessing 2048 bytes\nCompleted",
        "[REDACTED]\nprocessing 2048 bytes\n[REDACTED]",
        "should preserve size patterns"
    )]
    fn test_apply_redaction_to_content_key_cases(
        #[case] regex_patterns: Vec<String>,
        #[case] input_content: &str,
        #[case] expected_output: &str,
        #[case] description: &str,
    ) {
        let result = redact_content_using_patterns(input_content, &regex_patterns);

        assert_eq!(result, expected_output, "Failed: {}", description);
    }
}
