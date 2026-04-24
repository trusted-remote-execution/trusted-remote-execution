use derive_getters::Getters;
use rex_cedar_auth::cedar_auth::CedarAuth;
use serde::Serialize;

use std::io::{Read, Seek};

use crate::errors::RustSafeIoError;
use crate::{CHUNK_SIZE, RcFileHandle};

impl RcFileHandle {
    /// Counts lines, words, and bytes in a file.
    ///
    /// This method performs a word count operation similar to the Unix `wc` command.
    ///
    /// # Returns
    /// * `Result<WordCount>` - The count results if successful
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
    /// # let dir_path = "/tmp";
    /// # let file_path = "file.txt";
    /// # let dir_handle = DirConfigBuilder::default()
    /// #     .path(dir_path.to_string())
    /// #     .build().unwrap()
    /// #     .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap())
    /// #     .unwrap();
    /// let file_handle = dir_handle.safe_open_file(
    ///     &cedar_auth,
    ///     file_path,
    ///     OpenFileOptionsBuilder::default().read(true).build().unwrap()
    /// ).unwrap();
    ///
    /// let counts = file_handle.counts(&cedar_auth).unwrap();
    /// println!("Lines: {}, Words: {}, Bytes: {}",
    ///     counts.line_count(),
    ///     counts.word_count(),
    ///     counts.byte_count()
    /// );
    /// ```
    pub fn counts(&self, cedar_auth: &CedarAuth) -> Result<WordCount, RustSafeIoError> {
        self.validate_read_open_option(cedar_auth)?;

        let mut result = WordCount::default();

        let mut reader = &self.file_handle.file;
        let mut buffer = [0u8; CHUNK_SIZE];
        let mut in_word = false;

        loop {
            let bytes_read = reader.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }

            result.bytes += bytes_read;

            #[allow(clippy::indexing_slicing)]
            for &byte in &buffer[..bytes_read] {
                if byte == b'\n' {
                    result.lines += 1;
                }

                let is_space = byte.is_ascii_whitespace() || byte == b'\x0B'; // '\x0B is for the vertical tab character \v which is not covered in is_ascii_whitespace()
                if !in_word && !is_space {
                    result.words += 1;
                    in_word = true;
                } else if is_space {
                    in_word = false;
                }
            }
        }

        reader.rewind()?;
        Ok(result)
    }
}

/// Represents the result of a word count operation.
///
/// This struct contains the counts for lines, words, and bytes in a file.
///
/// # Fields
/// * `lines` - The number of lines in the file
/// * `words` - The number of words in the file
/// * `bytes` - The number of bytes in the file
///
/// # Example
///
/// ```no_run
/// # use rust_safe_io::{DirConfigBuilder, WordCount};
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
/// # let dir_handle = DirConfigBuilder::default()
/// #     .path("/tmp".to_string())
/// #     .build().unwrap()
/// #     .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap())
/// #     .unwrap();
/// #
/// let file_handle = dir_handle.safe_open_file(
///     &cedar_auth,
///     "file.txt",
///     OpenFileOptionsBuilder::default().read(true).build().unwrap()
/// ).unwrap();
///
/// let counts = file_handle.counts(&cedar_auth).unwrap();
///
/// println!("Lines: {}", counts.line_count());
/// println!("Words: {}", counts.word_count());
/// println!("Bytes: {}", counts.byte_count());
/// ```
#[derive(Debug, Default, Clone, Copy, Getters, Serialize)]
pub struct WordCount {
    #[getter(rename = "line_count")]
    #[serde(rename = "line_count")]
    lines: usize,
    #[getter(rename = "word_count")]
    #[serde(rename = "word_count")]
    words: usize,
    #[getter(rename = "byte_count")]
    #[serde(rename = "byte_count")]
    bytes: usize,
}
