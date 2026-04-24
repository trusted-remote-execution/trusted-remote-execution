use rex_cedar_auth::cedar_auth::CedarAuth;

use super::common::zeros;

use crate::errors::RustSafeIoError;
use crate::{CHUNK_SIZE, RcFileHandle};

use std::io::{BufReader, Read};

impl RcFileHandle {
    /// Extract printable strings from a file. This is generally intended to extract the strings from a binary or other non-UTF8 file.
    ///
    /// For now there are some hardcoded assumptions in place that we may change later:
    /// - Only ASCII characters are extracted from the file. Other encodings are not supported.
    /// - Only strings that are at least 4 characters long are returned. There is currently no input option to change this.
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
    /// # let dir_handle = DirConfigBuilder::default()
    /// #    .path("/tmp".to_string())
    /// #    .build().unwrap()
    /// #    .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap())
    /// #    .unwrap();
    ///
    /// let file_handle = dir_handle.safe_open_file(
    ///     &cedar_auth,
    ///     "data.txt",
    ///     OpenFileOptionsBuilder::default().read(true).build().unwrap()
    /// ).unwrap();
    ///
    /// let strings = file_handle.extract_strings(&cedar_auth).unwrap();
    /// for string in strings {
    ///     println!("{string}");
    /// }
    /// ```
    pub fn extract_strings(&self, cedar_auth: &CedarAuth) -> Result<Vec<String>, RustSafeIoError> {
        self.validate_read_open_option(cedar_auth)?;

        let file = &self.file_handle.file;
        let reader = BufReader::new(file);

        let strings = extract_strings_generic(reader, CHUNK_SIZE)?;

        self.rewind()?;
        Ok(strings)
    }
}

/// Loop through any reader and extract the printable strings that are longer than `MIN_STRING_LENGTH` from it.
fn extract_strings_generic(
    mut reader: impl Read,
    buffer_size: usize,
) -> Result<Vec<String>, RustSafeIoError> {
    const MIN_STRING_LENGTH: usize = 4;

    let mut buf: Vec<u8> = zeros!(buffer_size);
    let mut extracted_strings = Vec::new();
    let mut current_string = Vec::new();

    /*
     * Overall algorithm steps:
     * 1. Read a chunk from the reader and store it into `buf`
     * 2. Loop through the chunk and add any consecutive printable characters to a temporary vector
     * 3. When an unprintable character is reached, check if the temp vector is long enough to include in the return value.
     *    If so, convert it to a string and push it to the overall list of printable strings.
     * 4. Continue doing steps 1-3 until we've reached EOF
     */
    while let Ok(n_bytes) = reader.read(&mut buf) {
        if n_bytes == 0 {
            // Reached "EOF". nothing left to do except push the last string and exit
            if current_string.len() >= MIN_STRING_LENGTH {
                extracted_strings
                    .push(String::from_utf8(current_string).map_err(RustSafeIoError::from)?);
            }
            break;
        }

        // Clippy's suggestion was to get an iter from the vec, but generally it's not a good idea to have an iter open to a mutable vector
        #[allow(clippy::needless_range_loop)]
        for i in 0..n_bytes {
            // We assume that n_bytes returned from the reader is less than buffer_size, so we won't try to index out of bounds.
            #[allow(clippy::indexing_slicing)]
            let c = buf[i];
            if is_printable_ascii(c) {
                current_string.push(c);
            } else {
                if current_string.len() >= MIN_STRING_LENGTH {
                    extracted_strings
                        .push(String::from_utf8(current_string).map_err(RustSafeIoError::from)?);
                }
                current_string = vec![];
            }
        }
    }

    Ok(extracted_strings)
}

const fn is_printable_ascii(c: u8) -> bool {
    const TAB: u8 = 0x09;
    // everything between 0x20 (SPACE) and 0x7e (TILDE) is printable
    c >= 0x20 && c <= 0x7e || c == TAB
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use rstest::rstest;
    use std::io::Cursor;

    /// Given: A Read of bytes
    /// When: extract_strings_generic is called
    /// Then: A vector of strings is returned that only includes the printable characters
    #[rstest]
    #[case::input_no_data(b"", vec![])]
    #[case::special_characters(b"\x09!@#$%^&*()_+-=[]{}|\\'\",./<>?~` ;:", vec!["\t!@#$%^&*()_+-=[]{}|\\'\",./<>?~` ;:"])]
    #[case::single_buffer_starts_and_ends_with_unprintable(b"\x01abcde\x01f\x02defgh\x03", vec!["abcde", "defgh"])]
    #[case::single_buffer_starts_and_ends_with_printable(b"abcde\x01o\x02defgh", vec!["abcde", "defgh"])]
    #[case::single_buffer_all_chars_are_printable(b"abcdedefgh", vec!["abcdedefgh"])]
    #[case::single_buffer_all_chars_are_unprintable(b"\x01\x02\x03\x04\x05", vec![])]
    #[case::single_buffer_strings_too_small(b"\x01abc\x01\x02def\x03ghi", vec![])]
    #[case::multiple_buffer_no_word_split_across_buffers(b"abcde\x01\x02defgh\x04\x04\x04\x04\x04v\x03ghijk\x04jklmn", vec!["abcde", "defgh", "ghijk", "jklmn"])]
    #[case::multiple_buffer_word_split_across_buffers(b"abcde\x01\x02defgh\x03ghijk\x04jklmn", vec!["abcde", "defgh", "ghijk", "jklmn"])]
    #[case::multiple_buffer_all_chars_printable(b"abcdefghijklmnopqrstuvwxyz", vec!["abcdefghijklmnopqrstuvwxyz"])]
    #[case::multiple_buffer_all_chars_unprintable(b"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01", vec![])]
    #[case::multiple_buffer_strings_too_small(b"\x01\x01\x01a\x01\x01\x01\x01\x01\x01a\x01aaa\x01\x01\x01\x01\x01\x01\x01\x01a\x01\x01aa", vec![])]
    fn test_extract_strings_generic(
        #[case] input: &[u8],
        #[case] expected_output: Vec<&str>,
    ) -> Result<()> {
        let test_buffer_size = 16;
        let reader = Cursor::new(input);
        let result = extract_strings_generic(reader, test_buffer_size)?;
        assert_eq!(result, expected_output);
        Ok(())
    }
}
