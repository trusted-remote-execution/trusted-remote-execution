use derive_getters::Getters;
use regex::Regex;
use rex_cedar_auth::cedar_auth::CedarAuth;
use std::io::BufReader;

use super::common::ReadMode;
use crate::RcFileHandle;
use crate::errors::RustSafeIoError;
use crate::redaction::build_or_get_pattern_cache;
use crate::utils::search::search_lines;

#[derive(Debug, Clone, Getters)]
pub struct Match {
    pub line_number: usize,
    pub line_content: String,
}

impl RcFileHandle {
    /// Searches for regex patterns in file content using streaming.
    ///
    /// This method processes the file line-by-line without loading the entire
    /// file into memory, making it suitable for large files.
    ///
    /// # Regex Syntax
    /// Uses Rust's [`regex`](https://docs.rs/regex/1.11.1/regex/) crate (v1.11.1).
    /// See full syntax documentation: <https://docs.rs/regex/1.11.1/regex/#syntax>
    ///
    /// **Important**: This is **NOT** PCRE or JavaScript regex syntax.
    ///
    /// # Arguments
    /// * `cedar_auth` - Cedar authorization context for file access
    /// * `pattern` - Regex pattern to search for in the file content
    ///
    /// # Returns
    /// * `Result<Vec<Match>>` - Vector of matches containing line numbers and line content
    ///
    /// # Errors
    /// * Returns error if Cedar authorization fails
    /// * Returns error if file cannot be read
    /// * Returns error if regex pattern is invalid
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_safe_io::DirConfigBuilder;
    /// use rust_safe_io::options::{OpenDirOptionsBuilder, OpenFileOptionsBuilder};
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    ///
    /// let dir_path = "/tmp";
    /// let file_path = "data.txt";
    /// let dir_handle = DirConfigBuilder::default()
    ///     .path(dir_path.to_string())
    ///     .build().unwrap()
    ///     .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap())
    ///     .unwrap();
    /// let file_handle = dir_handle.safe_open_file(&cedar_auth, file_path, OpenFileOptionsBuilder::default().read(true).build().unwrap()).unwrap();
    ///
    /// let all_matches = file_handle.safe_search(&cedar_auth, "(?i)error").unwrap();
    /// ```
    pub fn safe_search(
        &self,
        cedar_auth: &CedarAuth,
        pattern: &str,
    ) -> Result<Vec<Match>, RustSafeIoError> {
        let read_mode = self.determine_read_mode(cedar_auth)?;

        let re =
            Regex::new(pattern).map_err(|e| RustSafeIoError::invalid_regex_err(pattern, &e))?;

        let redaction_patterns = match read_mode {
            ReadMode::Full => None,
            ReadMode::Redacted => Some(build_or_get_pattern_cache(cedar_auth)?.as_slice()),
        };

        let file = &self.file_handle.file;
        let reader = BufReader::new(file);

        let matches = search_lines(reader, &re, redaction_patterns)?;
        self.rewind()?;

        Ok(matches)
    }
}
