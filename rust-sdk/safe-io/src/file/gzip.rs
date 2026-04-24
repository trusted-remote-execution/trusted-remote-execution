use cap_std::fs::File;
use derive_getters::Getters;
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use regex::{Regex, RegexBuilder};
use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::fs::entities::FileEntity;
use serde::Serialize;
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, copy};

use crate::errors::RustSafeIoError;
use crate::file::Match;
use crate::file::common::{collect_last_n, stream_lines_range};
use crate::options::{CompressGzipOptions, ReadLinesOptions, SearchGzipOptions};
use crate::{RcFileHandle, is_authorized};

/// gzip metadata
#[derive(Debug, Clone, Copy, Getters, Serialize)]
pub struct GzipInfo {
    compressed_size_bytes: u64,
    uncompressed_size_bytes: u64,
    compression_ratio: f64,
}

fn build_search_regex(pattern: &str, case_insensitive: bool) -> Result<Regex, RustSafeIoError> {
    RegexBuilder::new(pattern)
        .case_insensitive(case_insensitive)
        .build()
        .map_err(|e| RustSafeIoError::invalid_regex_err(pattern, &e))
}

fn build_exclude_regex(exclude_pattern: Option<&String>) -> Result<Option<Regex>, RustSafeIoError> {
    exclude_pattern
        .as_ref()
        .map(|p| Regex::new(p).map_err(|e| RustSafeIoError::invalid_regex_err(p, &e)))
        .transpose()
}

/// Streams last N lines using a ring buffer to bound memory usage.
/// Must scan entire iterator since we don't know total count upfront.
fn stream_last_lines<I>(lines: I, count: usize) -> Result<Vec<String>, RustSafeIoError>
where
    I: Iterator<Item = Result<String, std::io::Error>>,
{
    let collected: Result<Vec<String>, _> = lines.collect();
    let all_lines = collected?;
    Ok(collect_last_n(all_lines.into_iter(), count, None))
}

/// Streams last N lines up to and including line `end_line` (1-indexed, inclusive).
fn stream_last_lines_until<I>(
    lines: I,
    count: usize,
    end_line: usize,
) -> Result<Vec<String>, RustSafeIoError>
where
    I: Iterator<Item = Result<String, std::io::Error>>,
{
    let collected: Result<Vec<String>, _> = lines.collect();
    let all_lines = collected?;
    Ok(collect_last_n(all_lines.into_iter(), count, Some(end_line)))
}

impl RcFileHandle {
    /// Creates a buffered reader for streaming gzip decompression.
    fn create_gzip_reader(&self) -> Result<BufReader<GzDecoder<File>>, RustSafeIoError> {
        let file = self.file_handle.file.try_clone()?;
        let decoder = GzDecoder::new(file);
        Ok(BufReader::new(decoder))
    }

    /// Compresses file content to gzip format and writes to destination.
    ///
    /// Uses streaming to avoid loading entire file into memory. The source file
    /// must be opened with read permission and the destination file must be opened
    /// with write permission.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use rust_safe_io::DirConfigBuilder;
    /// # use rust_safe_io::options::{OpenDirOptionsBuilder, OpenFileOptionsBuilder, CompressGzipOptionsBuilder};
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    /// #
    /// # let dir = DirConfigBuilder::default()
    /// #    .path("/tmp".to_string())
    /// #    .build().unwrap()
    /// #    .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap())
    /// #    .unwrap();
    /// #
    /// # let source = dir.safe_open_file(
    /// #     &cedar_auth,
    /// #     "file.log",
    /// #     OpenFileOptionsBuilder::default().read(true).build().unwrap()
    /// # ).unwrap();
    /// #
    /// # let dest = dir.safe_open_file(
    /// #     &cedar_auth,
    /// #     "file.log.gz",
    /// #     OpenFileOptionsBuilder::default().create(true).build().unwrap()
    /// # ).unwrap();
    /// #
    /// let options = CompressGzipOptionsBuilder::default()
    ///     .level(6)
    ///     .build()
    ///     .unwrap();
    ///
    /// source.safe_compress_gzip(&cedar_auth, dest, options).unwrap();
    /// ```
    #[allow(clippy::needless_pass_by_value)]
    pub fn safe_compress_gzip(
        &self,
        cedar_auth: &CedarAuth,
        dest_file: RcFileHandle,
        options: CompressGzipOptions,
    ) -> Result<(), RustSafeIoError> {
        self.validate_read_open_option(cedar_auth)?;
        dest_file.validate_write_open_option()?;

        // Check Cedar authorization for writing to destination at call time
        let dest_entity = &FileEntity::from_string_path(&dest_file.full_path())?;
        is_authorized(cedar_auth, &FilesystemAction::Write, dest_entity)?;

        let compression_level = Compression::new(options.level);

        let mut source = self.file_handle.file.try_clone()?;
        let dest = dest_file.file_handle.file.try_clone()?;

        let mut encoder = GzEncoder::new(dest, compression_level);
        copy(&mut source, &mut encoder)?;
        encoder.finish()?;

        // Rewind source and dest to allow the FDs to be used again
        self.rewind()?;
        dest_file.rewind()?;

        Ok(())
    }

    /// Reads lines from a gzipped file using streaming decompression.
    ///
    /// This implementation streams lines directly without loading the entire file into memory:
    /// - Head (positive count): Reads only the first N lines, exits early
    /// - Tail (negative count): Uses a ring buffer to keep only the last N lines in memory
    /// - Start offset: Skips lines without storing them
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use rust_safe_io::DirConfigBuilder;
    /// # use rust_safe_io::options::{OpenDirOptionsBuilder, OpenFileOptionsBuilder, ReadLinesOptionsBuilder};
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    /// #
    /// # let dir = DirConfigBuilder::default()
    /// #    .path("/tmp".to_string())
    /// #    .build().unwrap()
    /// #    .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap())
    /// #    .unwrap();
    /// #
    /// # let file = dir.safe_open_file(
    /// #     &cedar_auth,
    /// #     "file.log.gz",
    /// #     OpenFileOptionsBuilder::default().read(true).build().unwrap()
    /// # ).unwrap();
    ///
    /// // Read first 10 lines (equivalent of `zcat file.gz | head -n 10`)
    /// let options = ReadLinesOptionsBuilder::default().count(10).build().unwrap();
    /// let lines = file.safe_read_gzip_lines(&cedar_auth, options).unwrap();
    /// ```
    #[allow(clippy::needless_pass_by_value)]
    pub fn safe_read_gzip_lines(
        &self,
        cedar_auth: &CedarAuth,
        options: ReadLinesOptions,
    ) -> Result<Vec<String>, RustSafeIoError> {
        self.validate_read_open_option(cedar_auth)?;

        let reader = self.create_gzip_reader()?;

        let result = match (options.count, options.start) {
            (Some(n), None) if n < 0 => stream_last_lines(reader.lines(), n.unsigned_abs())?,
            (Some(n), Some(s)) if n < 0 => {
                stream_last_lines_until(reader.lines(), n.unsigned_abs(), s)?
            }
            (Some(n), None) => stream_lines_range(reader.lines(), 0, Some(n.unsigned_abs()))?,
            (Some(n), Some(s)) => {
                stream_lines_range(reader.lines(), s.saturating_sub(1), Some(n.unsigned_abs()))?
            }
            (None, Some(s)) => stream_lines_range(reader.lines(), s.saturating_sub(1), None)?,
            (None, None) => {
                return Err(RustSafeIoError::ValidationError {
                    reason: "Must specify count or start option".to_string(),
                });
            }
        };

        self.rewind()?;
        Ok(result)
    }

    /// Gets gzip file metadata
    ///
    /// Reads the gzip header and trailer to get compressed and uncompressed sizes.
    /// Note: The uncompressed size is stored as a 32-bit value in the gzip trailer,
    /// so for files larger than 4GB, the value wraps around (mod 2^32).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use rust_safe_io::DirConfigBuilder;
    /// # use rust_safe_io::options::{OpenDirOptionsBuilder, OpenFileOptionsBuilder};
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    /// #
    /// # let dir = DirConfigBuilder::default()
    /// #    .path("/tmp".to_string())
    /// #    .build().unwrap()
    /// #    .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap())
    /// #    .unwrap();
    /// #
    /// # let file = dir.safe_open_file(
    /// #     &cedar_auth,
    /// #     "file.log.gz",
    /// #     OpenFileOptionsBuilder::default().read(true).build().unwrap()
    /// # ).unwrap();
    ///
    /// let info = file.safe_gzip_info(&cedar_auth).unwrap();
    /// println!("Compressed: {} bytes", info.compressed_size_bytes());
    /// println!("Uncompressed: {} bytes", info.uncompressed_size_bytes());
    /// println!("Ratio: {:.1}%", info.compression_ratio() * 100.0);
    /// ```
    #[allow(clippy::cast_precision_loss)]
    pub fn safe_gzip_info(&self, cedar_auth: &CedarAuth) -> Result<GzipInfo, RustSafeIoError> {
        self.validate_read_open_option(cedar_auth)?;

        let mut file = self.file_handle.file.try_clone()?;

        // Get compressed file size
        let compressed_size = file.seek(SeekFrom::End(0))?;

        // Read the last 4 bytes which contain the uncompressed size (mod 2^32)
        file.seek(SeekFrom::End(-4))?;
        let mut size_buf = [0u8; 4];
        file.read_exact(&mut size_buf)?;
        let uncompressed_size = u64::from(u32::from_le_bytes(size_buf));

        let compression_ratio = if compressed_size > 0 {
            uncompressed_size as f64 / compressed_size as f64
        } else {
            0.0
        };

        self.rewind()?;

        Ok(GzipInfo {
            compressed_size_bytes: compressed_size,
            uncompressed_size_bytes: uncompressed_size,
            compression_ratio,
        })
    }

    /// Searches for a pattern within a gzipped file.
    ///
    /// Streams the decompressed content line-by-line, applying regex matching
    /// and optional exclude patterns. Supports limiting results with head/tail behavior.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use rust_safe_io::DirConfigBuilder;
    /// # use rust_safe_io::options::{OpenDirOptionsBuilder, OpenFileOptionsBuilder, SearchGzipOptionsBuilder};
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    /// #
    /// # let dir = DirConfigBuilder::default()
    /// #     .path("/tmp".to_string())
    /// #     .build().unwrap()
    /// #     .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap())
    /// #     .unwrap();
    /// #
    /// # let file = dir.safe_open_file(
    /// #     &cedar_auth,
    /// #     "file.log.gz",
    /// #     OpenFileOptionsBuilder::default().read(true).build().unwrap()
    /// # ).unwrap();
    ///
    /// // Search for ERROR, excluding debug lines, limit to first 100 matches
    /// let options = SearchGzipOptionsBuilder::default()
    ///     .exclude_pattern("debug".to_string())
    ///     .max_results(100)
    ///     .build()
    ///     .unwrap();
    /// let matches = file.safe_search_gzip(&cedar_auth, "ERROR", options).unwrap();
    /// ```
    #[allow(clippy::needless_pass_by_value)]
    #[allow(clippy::cast_sign_loss)]
    pub fn safe_search_gzip(
        &self,
        cedar_auth: &CedarAuth,
        pattern: &str,
        options: SearchGzipOptions,
    ) -> Result<Vec<Match>, RustSafeIoError> {
        self.validate_read_open_option(cedar_auth)?;

        let main_regex = build_search_regex(pattern, options.case_insensitive)?;
        let exclude_regex = build_exclude_regex(options.exclude_pattern.as_ref())?;
        let reader = self.create_gzip_reader()?;

        // For negative max_results (tail behavior), we use a ring buffer to bound memory usage.
        // Unlike positive max_results (head) which can exit early after finding N matches,
        // tail must scan the entire file since we don't know which matches will be in the
        // final result until we've seen all of them. The ring buffer ensures we only keep
        // the last N matches in memory, avoiding unbounded growth for large files.
        let tail_limit = if options.max_results < 0 {
            (-options.max_results) as usize
        } else {
            0
        };
        let mut matches: VecDeque<Match> = VecDeque::new();

        for (line_idx, line_result) in reader.lines().enumerate() {
            let Ok(line) = line_result else {
                break;
            };
            let line_number = line_idx + 1; // 1-indexed

            if !main_regex.is_match(&line) {
                continue;
            }

            if let Some(ref exclude_re) = exclude_regex
                && exclude_re.is_match(&line)
            {
                continue;
            }

            // Ring buffer: evict oldest match when at capacity (tail behavior)
            if tail_limit > 0 && matches.len() >= tail_limit {
                matches.pop_front();
            }

            matches.push_back(Match {
                line_number,
                line_content: line,
            });

            // Early exit for positive max_results (head behavior)
            if options.max_results > 0 && matches.len() >= options.max_results as usize {
                break;
            }
        }

        self.rewind()?;
        Ok(matches.into_iter().collect())
    }

    /// Checks if a pattern exists within a gzipped file (equivalent to `zgrep -q`).
    ///
    /// Returns `true` immediately when the first match is found, providing
    /// efficient existence checking without scanning the entire file.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use rust_safe_io::DirConfigBuilder;
    /// # use rust_safe_io::options::{OpenDirOptionsBuilder, OpenFileOptionsBuilder, SearchGzipOptionsBuilder};
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    /// #
    /// # let dir = DirConfigBuilder::default()
    /// #     .path("/tmp".to_string())
    /// #     .build().unwrap()
    /// #     .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap())
    /// #     .unwrap();
    /// #
    /// # let file = dir.safe_open_file(
    /// #     &cedar_auth,
    /// #     "file.log.gz",
    /// #     OpenFileOptionsBuilder::default().read(true).build().unwrap()
    /// # ).unwrap();
    /// #
    /// let options = SearchGzipOptionsBuilder::default().build().unwrap();
    /// if file.safe_search_gzip_exists(&cedar_auth, "CRITICAL_ERROR", options).unwrap() {
    ///     println!("Critical error found!");
    /// }
    /// ```
    #[allow(clippy::needless_pass_by_value)]
    pub fn safe_search_gzip_exists(
        &self,
        cedar_auth: &CedarAuth,
        pattern: &str,
        options: SearchGzipOptions,
    ) -> Result<bool, RustSafeIoError> {
        // exit on first match
        let search_options = SearchGzipOptions {
            exclude_pattern: options.exclude_pattern,
            case_insensitive: options.case_insensitive,
            max_results: 1,
        };

        let matches = self.safe_search_gzip(cedar_auth, pattern, search_options)?;
        Ok(!matches.is_empty())
    }
}
