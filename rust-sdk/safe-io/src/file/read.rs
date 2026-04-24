use cap_std::fs::File;
use rex_cedar_auth::cedar_auth::CedarAuth;

use super::common::{ReadMode, stream_lines_range, zeros};
use crate::error_constants::NO_READ_LINE_MODE_SPECIFIED_ERR;
use crate::errors::RustSafeIoError;
use crate::options::{ReadLinesOptions, ReadPageOptions};
use crate::redaction::redact_content;
use crate::{CHUNK_SIZE, RcFileHandle};
use std::cmp;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};

impl RcFileHandle {
    /// Reads the contents of an open file.
    ///
    /// # Arguments
    ///
    /// * `cedar_auth` - The Cedar authorization instance
    ///
    /// # Returns
    ///
    /// * `Result<String>` - The contents of the file as a string if successful
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The principal doesn't have permission to read the file
    /// * The file was not opened with read permissions (i.e., the `read` flag was not set to `true` in `OpenFileOptions`)
    /// * The file cannot be read
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
    /// let file_path = "file.txt";
    /// let dir_handle = DirConfigBuilder::default()
    ///     .path(dir_path.to_string())
    ///     .build().unwrap()
    ///     .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap())
    ///     .unwrap();
    /// let file_handle = dir_handle.safe_open_file(
    ///     &cedar_auth,
    ///     file_path,
    ///     OpenFileOptionsBuilder::default().read(true).build().unwrap()
    /// ).unwrap();
    /// let actual_content = file_handle.safe_read(&cedar_auth).unwrap();
    /// ```
    pub fn safe_read(&self, cedar_auth: &CedarAuth) -> Result<String, RustSafeIoError> {
        // Check if the user opened the file with the read flag. This addresses an issue
        // where a file opened without read permissions could still be read after safe_write. The issue
        // occurred because TempFile::new() created a temporary file with hardcoded default permissions in capstd
        // (including read), and after safe_write returned a new handle to this file, that handle inherited those
        // permissions rather than the original. This check ensures permission
        // constraints are preserved across write operations.
        match self.determine_read_mode(cedar_auth)? {
            ReadMode::Full => read_file_content(&self.file_handle.file),
            ReadMode::Redacted => {
                let content = read_file_content(&self.file_handle.file)?;
                redact_content(cedar_auth, &content)
            }
        }
    }

    /// Reads lines from the start or the end of a file.
    ///
    /// # Arguments
    /// * `cedar_auth` - The Cedar authorization instance
    /// * `read_file_options`
    ///     * `count`: the number of lines to read. When this number is negative, this function will read lines starting from the end of the file.
    ///     * `start`: the line to start from (1-indexed). The start line is included in the results. For example,
    ///         * `start(5)` skips 4 lines and starts from the 5th line (1-indexed)
    ///         * `start(1)` with no count specified returns the whole file
    ///
    /// Note that a negative or 0 start value is not supported.
    ///
    /// This API resets the read position at the end of the call, so subsequent calls will always start from
    /// the beginning of the file. If you need to read multiple pages quickly without resetting the read position
    /// on every call, use the [`RcFileHandle::safe_read_page`] API instead.
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
    ///
    /// let dir_handle = DirConfigBuilder::default()
    ///     .path("/tmp".to_string())
    ///     .build().unwrap()
    ///     .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap())
    ///     .unwrap();
    ///
    /// let file_handle = dir_handle.safe_open_file(
    ///     &cedar_auth,
    ///     "data.txt",
    ///     OpenFileOptionsBuilder::default().read(true).build().unwrap()
    /// ).unwrap();
    ///
    /// let head_options = ReadLinesOptionsBuilder::default().count(10).build().unwrap();
    /// let lines = file_handle.safe_read_lines(&cedar_auth, head_options).unwrap();
    /// for line in lines {
    ///     println!("{}", line);
    /// }
    ///
    /// let tail_options = ReadLinesOptionsBuilder::default().count(-10).build().unwrap();
    /// let lines = file_handle.safe_read_lines(&cedar_auth, tail_options).unwrap();
    /// for line in lines {
    ///     println!("{}", line);
    /// }
    ///
    /// let start_options = ReadLinesOptionsBuilder::default().start(10).build().unwrap();
    /// let lines = file_handle.safe_read_lines(&cedar_auth, start_options).unwrap();
    /// for line in lines {
    ///     println!("{}", line);
    /// }
    ///
    /// let options = ReadLinesOptionsBuilder::default().count(10).start(10).build().unwrap();
    /// let lines = file_handle.safe_read_lines(&cedar_auth, options).unwrap();
    /// for line in lines {
    ///     println!("{}", line);
    /// }
    /// ```
    pub fn safe_read_lines(
        &self,
        cedar_auth: &CedarAuth,
        read_file_options: ReadLinesOptions,
    ) -> Result<Vec<String>, RustSafeIoError> {
        self.validate_read_open_option(cedar_auth)?;

        let file = &self.file_handle.file;

        let lines: Vec<String> = match (read_file_options.count, read_file_options.start) {
            // Count is negative -> read backwards
            (Some(count), start_line) if count < 0 => {
                read_lines_from_end(file, count.unsigned_abs(), start_line)?
            }

            // Count is not provided but start_line is - read file to end after skipping the first lines
            (None, Some(start_line)) => {
                let reader = BufReader::new(file);
                reader
                    .lines()
                    .skip(start_line - 1)
                    .collect::<std::io::Result<Vec<String>>>()?
            }

            // Count is positive -> read forwards
            (Some(count), start_line) => {
                let reader = BufReader::new(file);
                let skip = start_line.map_or(0, |s| s.saturating_sub(1));
                stream_lines_range(reader.lines(), skip, Some(count.unsigned_abs()))?
            }

            (None, None) => {
                return Err(RustSafeIoError::InvalidArguments {
                    reason: NO_READ_LINE_MODE_SPECIFIED_ERR.to_string(),
                });
            }
        };

        self.rewind()?;
        Ok(lines)
    }

    /// Reads the next page of lines from an open file.
    ///
    /// This method reads a page of lines from the file without rewinding the file position,
    /// allowing for sequential reading of pages through multiple calls. If you need to read a specific page,
    /// or read lines from the end of the file, use the [`RcFileHandle::safe_read_lines`] API instead.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use rust_safe_io::DirConfigBuilder;
    /// # use rust_safe_io::options::{OpenDirOptionsBuilder, OpenFileOptionsBuilder, ReadPageOptionsBuilder};
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    /// #
    /// # let dir_handle = DirConfigBuilder::default()
    /// #     .path("/tmp".to_string())
    /// #     .build().unwrap()
    /// #     .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap())
    /// #     .unwrap();
    /// #
    /// # let file_handle = dir_handle.safe_open_file(
    /// #     &cedar_auth,
    /// #     "data.txt",
    /// #     OpenFileOptionsBuilder::default().read(true).build().unwrap()
    /// # ).unwrap();
    /// #
    /// // Read multiple pages of 50 lines each
    /// let page_options = ReadPageOptionsBuilder::default()
    ///     .num_lines(50)
    ///     .build()
    ///     .unwrap();
    ///
    /// // Read first page
    /// let mut lines;
    /// loop {
    ///     lines = file_handle.safe_read_page(&cedar_auth, page_options).unwrap();
    ///     if lines.is_empty() {
    ///         break;
    ///     }
    ///     for line in &lines {
    ///         println!("{}", line);
    ///     }
    /// }
    /// ```
    pub fn safe_read_page(
        &self,
        cedar_auth: &CedarAuth,
        options: ReadPageOptions,
    ) -> Result<Vec<String>, RustSafeIoError> {
        self.validate_read_open_option(cedar_auth)?;

        let mut file = &self.file_handle.file;
        let mut reader = BufReader::new(file);
        let lines = stream_lines_range(reader.by_ref().lines(), 0, Some(options.num_lines))?;

        // Since the reader may greedily read extra lines, we need to manually set the file to the
        // appropriate position to read the next page
        file.seek(SeekFrom::Start(reader.stream_position()?))?;
        Ok(lines)
    }
}

/// This method locates the appropriate start position to read the file from, such that `count` lines are returned
/// from the end of the file. It goes to the end of the file with `seek()`, iterates backwards in chunks of `CHUNK_SIZE` bytes,
/// and counts the new line characters processed.
#[allow(clippy::cast_possible_truncation)]
fn read_lines_from_end(
    mut file: &File,
    count: usize,
    start_line: Option<usize>,
) -> Result<Vec<String>, RustSafeIoError> {
    let start_pos = match start_line {
        Some(start_line) => find_start_position(file, start_line)?,
        None => SeekFrom::End(0),
    };

    let mut buffer = zeros!(CHUNK_SIZE);
    let mut newlines_found = 0;
    let mut current_pos = file.seek(start_pos)?;

    // latches to true as soon as we read our first character. Used to ignore any trailing newlines
    let mut read_first_character = false;

    while current_pos > 0 && newlines_found < count {
        let chunk_size = usize::try_from(cmp::min(CHUNK_SIZE as u64, current_pos))?;
        current_pos -= chunk_size as u64;

        file.seek(SeekFrom::Start(current_pos))?;
        #[allow(clippy::indexing_slicing)]
        file.read_exact(&mut buffer[0..chunk_size])?;

        for i in (0..chunk_size).rev() {
            #[allow(clippy::indexing_slicing)]
            if buffer[i] == b'\n' && read_first_character {
                newlines_found += 1;
                if newlines_found == count {
                    current_pos += (i + 1) as u64;
                    break;
                }
            }
            read_first_character = true;
        }
    }

    let start_pos = if newlines_found < count {
        0
    } else {
        current_pos
    };

    file.seek(SeekFrom::Start(start_pos))?;

    let reader = BufReader::new(file);
    reader
        .lines()
        .take(cmp::min(count, start_line.unwrap_or(usize::MAX)))
        .collect::<std::io::Result<Vec<String>>>()
        .map_err(RustSafeIoError::from)
}

// The start position will be the last character in the start line, so that we include the start line in the result
fn find_start_position(file: &File, start_line: usize) -> Result<SeekFrom, RustSafeIoError> {
    let mut reader = BufReader::new(file);
    let mut start_pos: u64 = 0;
    let mut line_counter: usize = 1; // start_line is 1-indexed so we 1-index our loop as well for simplicity.

    while line_counter <= start_line {
        let mut buffer = vec![];

        let chars_read = reader.read_until(b'\n', &mut buffer)?;
        if chars_read == 0 || buffer.last() != Some(&b'\n') {
            // we hit EOF, just seek from the end of the file
            return Ok(SeekFrom::End(0));
        }

        start_pos += chars_read as u64; // chars_read includes the newline character
        line_counter += 1;
    }

    Ok(SeekFrom::Start(start_pos - 1)) // subtract 1 character to account for the last newline read
}

fn read_file_content(mut file: &File) -> Result<String, RustSafeIoError> {
    let mut s = String::new();
    file.read_to_string(&mut s)?;
    file.rewind()?;
    Ok(s)
}
