//! `awk` - Field processing and text extraction
//!
//! Unlike the monolithic UNIX `awk`, this exposes individual operations as
//! separate functions for clarity and composability.
//!
//! # Example (Rhai)
//! ```rhai
//! // Split a line into fields
//! let fields = awk_split("hello world foo", " ");  // ["hello", "world", "foo"]
//!
//! // Print specific field from each line of a file
//! let col2 = awk_field(2, " ", "/path/to/file.txt");
//!
//! // Filter lines matching a pattern
//! let lines = awk_filter("ERROR", "/path/to/file.txt");
//!
//! // Sum a numeric field
//! let total = awk_sum(3, " ", "/path/to/file.txt");
//!
//! // Count unique values in a field
//! let counts = awk_count_unique(1, " ", "/path/to/file.txt");
//! ```

use super::open_file_from_path;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rust_safe_io::errors::RustSafeIoError;
use std::collections::HashMap;

/// Split a string into fields by delimiter (pure computation, no I/O)
pub(crate) fn awk_split(text: &str, delimiter: &str) -> Vec<String> {
    text.split(delimiter).map(str::to_string).collect()
}

/// Extract a specific field (1-indexed) from each line of a file
pub(crate) fn awk_field(
    field_num: i64,
    delimiter: &str,
    path: &str,
    cedar_auth: &CedarAuth,
) -> Result<Vec<String>, RustSafeIoError> {
    if field_num < 1 {
        return Err(RustSafeIoError::InvalidArguments {
            reason: "awk: field number must be >= 1".to_string(),
        });
    }
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let idx = (field_num - 1) as usize;

    let file_handle = open_file_from_path(path, cedar_auth)?;
    let content = file_handle.safe_read(cedar_auth)?;

    Ok(content
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(delimiter).collect();
            fields.get(idx).map(|f| (*f).to_string())
        })
        .collect())
}

/// Filter lines from a file that contain a pattern (simple string match)
pub(crate) fn awk_filter(
    pattern: &str,
    path: &str,
    cedar_auth: &CedarAuth,
) -> Result<Vec<String>, RustSafeIoError> {
    let file_handle = open_file_from_path(path, cedar_auth)?;
    let content = file_handle.safe_read(cedar_auth)?;

    Ok(content
        .lines()
        .filter(|line| line.contains(pattern))
        .map(str::to_string)
        .collect())
}

/// Filter lines where a specific field matches a pattern
pub(crate) fn awk_filter_field(
    field_num: i64,
    delimiter: &str,
    pattern: &str,
    path: &str,
    cedar_auth: &CedarAuth,
) -> Result<Vec<String>, RustSafeIoError> {
    if field_num < 1 {
        return Err(RustSafeIoError::InvalidArguments {
            reason: "awk: field number must be >= 1".to_string(),
        });
    }
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let idx = (field_num - 1) as usize;

    let file_handle = open_file_from_path(path, cedar_auth)?;
    let content = file_handle.safe_read(cedar_auth)?;

    Ok(content
        .lines()
        .filter(|line| {
            let fields: Vec<&str> = line.split(delimiter).collect();
            fields.get(idx).is_some_and(|f| f.contains(pattern))
        })
        .map(str::to_string)
        .collect())
}

/// Sum a numeric field (1-indexed) across all lines
pub(crate) fn awk_sum(
    field_num: i64,
    delimiter: &str,
    path: &str,
    cedar_auth: &CedarAuth,
) -> Result<f64, RustSafeIoError> {
    if field_num < 1 {
        return Err(RustSafeIoError::InvalidArguments {
            reason: "awk: field number must be >= 1".to_string(),
        });
    }
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let idx = (field_num - 1) as usize;

    let file_handle = open_file_from_path(path, cedar_auth)?;
    let content = file_handle.safe_read(cedar_auth)?;

    let total: f64 = content
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(delimiter).collect();
            fields.get(idx).and_then(|f| f.trim().parse::<f64>().ok())
        })
        .sum();

    Ok(total)
}

/// Count unique values in a field (1-indexed), returns a map of value -> count
pub(crate) fn awk_count_unique(
    field_num: i64,
    delimiter: &str,
    path: &str,
    cedar_auth: &CedarAuth,
) -> Result<HashMap<String, i64>, RustSafeIoError> {
    if field_num < 1 {
        return Err(RustSafeIoError::InvalidArguments {
            reason: "awk: field number must be >= 1".to_string(),
        });
    }
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let idx = (field_num - 1) as usize;

    let file_handle = open_file_from_path(path, cedar_auth)?;
    let content = file_handle.safe_read(cedar_auth)?;

    let mut counts: HashMap<String, i64> = HashMap::new();
    for line in content.lines() {
        let fields: Vec<&str> = line.split(delimiter).collect();
        if let Some(val) = fields.get(idx) {
            *counts.entry((*val).to_string()).or_insert(0) += 1;
        }
    }

    Ok(counts)
}

/// Filter lines within a range (1-indexed, inclusive)
pub(crate) fn awk_filter_range(
    start: i64,
    end: i64,
    path: &str,
    cedar_auth: &CedarAuth,
) -> Result<Vec<String>, RustSafeIoError> {
    if start < 1 || end < start {
        return Err(RustSafeIoError::InvalidArguments {
            reason: format!("awk: invalid range {start}..{end}"),
        });
    }

    let file_handle = open_file_from_path(path, cedar_auth)?;
    let content = file_handle.safe_read(cedar_auth)?;

    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let (s, e) = ((start - 1) as usize, end as usize);

    Ok(content
        .lines()
        .skip(s)
        .take(e - s)
        .map(str::to_string)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rex_test_utils::rhai::common::{create_default_test_cedar_auth, create_test_file};

    /// Given: A string with spaces
    /// When: Calling awk_split
    /// Then: Fields are returned
    #[test]
    fn test_awk_split() {
        let result = awk_split("hello world foo", " ");
        assert_eq!(result, vec!["hello", "world", "foo"]);
    }

    /// Given: A file with space-delimited fields
    /// When: Calling awk_field for column 2
    /// Then: The second field from each line is returned
    #[test]
    fn test_awk_field() {
        let (_temp, path) = create_test_file("a 10 x\nb 20 y\nc 30 z");
        let cedar_auth = create_default_test_cedar_auth();

        let result = awk_field(2, " ", &path, &cedar_auth).unwrap();
        assert_eq!(result, vec!["10", "20", "30"]);
    }

    /// Given: A field number of 0
    /// When: Calling awk_field
    /// Then: An error is returned
    #[test]
    fn test_awk_field_invalid_index() {
        let (_temp, path) = create_test_file("a b c");
        let cedar_auth = create_default_test_cedar_auth();

        let result = awk_field(0, " ", &path, &cedar_auth);
        assert!(result.is_err());
    }

    /// Given: A file with numeric data
    /// When: Calling awk_sum on column 2
    /// Then: The sum is returned
    #[test]
    fn test_awk_sum() {
        let (_temp, path) = create_test_file("a 10\nb 20\nc 30");
        let cedar_auth = create_default_test_cedar_auth();

        let result = awk_sum(2, " ", &path, &cedar_auth).unwrap();
        assert!((result - 60.0).abs() < f64::EPSILON);
    }

    /// Given: A file with repeated values
    /// When: Calling awk_count_unique on column 1
    /// Then: Counts per unique value are returned
    #[test]
    fn test_awk_count_unique() {
        let (_temp, path) = create_test_file("a 1\nb 2\na 3\nb 4\nc 5");
        let cedar_auth = create_default_test_cedar_auth();

        let result = awk_count_unique(1, " ", &path, &cedar_auth).unwrap();
        assert_eq!(result.get("a"), Some(&2));
        assert_eq!(result.get("b"), Some(&2));
        assert_eq!(result.get("c"), Some(&1));
    }
}
