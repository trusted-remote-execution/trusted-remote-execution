//! `cat` - Read entire file contents from a path
//!
//! # Example (Rhai)
//! ```rhai
//! // Simple usage
//! let content = cat("/path/to/file.txt");
//!
//! // With flags
//! let content = cat([Cat::NUMBER], "/path/to/file.txt");
//! ```

use super::open_file_from_path;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::Array;
use rhai_sdk_common_utils::args::{extract_flags, has_flag};
use rust_safe_io::errors::RustSafeIoError;

/// Flags for the `cat` command, registered as a Rhai custom type.
///
/// Available flags:
/// - `Cat::NUMBER` — number output lines
/// - `Cat::N` — short form alias for `NUMBER`
#[derive(Debug, Clone)]
pub(crate) enum CatFlag {
    Number,
}

/// Parse flags from a Rhai Array of `CatFlag` values.
pub(crate) struct CatOptions {
    pub number: bool,
}

impl CatOptions {
    pub(crate) fn from_flags(flags: &[CatFlag]) -> Self {
        Self {
            number: has_flag(flags, |f| matches!(f, CatFlag::Number)),
        }
    }
}

/// Read file contents with default options
pub(crate) fn cat(path: &str, cedar_auth: &CedarAuth) -> Result<String, RustSafeIoError> {
    cat_with_flags(path, &Array::new(), cedar_auth)
}

/// Read file contents with user-provided flags
pub(crate) fn cat_with_flags(
    path: &str,
    flags_arr: &Array,
    cedar_auth: &CedarAuth,
) -> Result<String, RustSafeIoError> {
    let flags = extract_flags::<CatFlag>(flags_arr)?;
    let opts = CatOptions::from_flags(&flags);
    let file_handle = open_file_from_path(path, cedar_auth)?;
    let content = file_handle.safe_read(cedar_auth)?;

    if opts.number {
        Ok(content
            .lines()
            .enumerate()
            .map(|(i, line)| format!("{:>6}\t{line}", i + 1))
            .collect::<Vec<_>>()
            .join("\n"))
    } else {
        Ok(content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rex_test_utils::rhai::common::{create_default_test_cedar_auth, create_test_file};
    use rhai::Dynamic;

    /// Given: A valid file path
    /// When: Calling cat with the path
    /// Then: The file contents are returned
    #[test]
    fn test_cat_valid_file() {
        let (_temp, path) = create_test_file("test content");
        let cedar_auth = create_default_test_cedar_auth();

        let result = cat(&path, &cedar_auth);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test content");
    }

    /// Given: A file with multiple lines
    /// When: Calling cat with CatFlag::Number
    /// Then: Lines are numbered
    #[test]
    fn test_cat_number_lines() {
        let (_temp, path) = create_test_file("line1\nline2\nline3");
        let cedar_auth = create_default_test_cedar_auth();
        let flags: Array = vec![Dynamic::from(CatFlag::Number)];

        let result = cat_with_flags(&path, &flags, &cedar_auth).unwrap();
        assert!(result.contains("     1\tline1"));
        assert!(result.contains("     2\tline2"));
        assert!(result.contains("     3\tline3"));
    }

    /// Given: An array with a non-CatFlag element
    /// When: Calling cat_with_flags
    /// Then: An error is returned
    #[test]
    fn test_cat_rejects_wrong_flag_type() {
        let (_temp, path) = create_test_file("content");
        let cedar_auth = create_default_test_cedar_auth();
        let flags: Array = vec![Dynamic::from("not_a_flag")];

        let result = cat_with_flags(&path, &flags, &cedar_auth);
        assert!(result.is_err());
    }
}
