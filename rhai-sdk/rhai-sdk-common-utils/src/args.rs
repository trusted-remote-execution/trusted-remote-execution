//! Common utilities for command flag parsing.
//!
//! Each command defines its own flag enum registered as a Rhai custom type.
//! Commands accept an `Array` of their flag type from Rhai scripts.
//!
//! # Example (Rhai)
//! ```rhai
//! ls("/tmp", [Ls::ALL, Ls::LONG])
//! cat("/path", [Cat::NUMBER])
//! grep("pat", "/path", [Grep::IGNORE_CASE, Grep::MAX_COUNT(5)])
//! ```

use rhai::Array;

/// Extract all flags of a specific type from a Rhai Array.
///
/// Each element is downcast to `T`. Returns an error if any element
/// is not the expected flag type. The command and type names for error
/// messages are derived automatically from `T`.
pub fn extract_flags<T: Clone + 'static>(arr: &Array) -> Result<Vec<T>, String> {
    let full = std::any::type_name::<T>();
    let type_label = full.rsplit("::").next().unwrap_or(full);
    let command_label = type_label
        .strip_suffix("Flag")
        .unwrap_or(type_label)
        .to_lowercase();

    arr.iter()
        .map(|item| {
            item.clone().try_cast::<T>().ok_or_else(|| {
                format!(
                    "{command_label}: expected {type_label} flag, got {}",
                    item.type_name()
                )
            })
        })
        .collect()
}

/// Check if a specific flag is present in a list (by predicate).
pub fn has_flag<T, F: Fn(&T) -> bool>(flags: &[T], predicate: F) -> bool {
    flags.iter().any(predicate)
}

/// Find a flag and extract its inner value (for value-carrying variants).
pub fn find_flag_value<T, V, F: Fn(&T) -> Option<V>>(flags: &[T], extractor: F) -> Option<V> {
    flags.iter().find_map(extractor)
}

/// Return an empty Rhai Array (used as default when no flags are provided).
pub fn empty_array() -> Array {
    Array::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rhai::Dynamic;

    /// Given: An array with elements of the correct type
    /// When: Extracting flags
    /// Then: All values are returned
    #[test]
    fn test_extract_flags_correct_type() {
        let arr: Array = vec![Dynamic::from(42_i64), Dynamic::from(99_i64)];
        let result = extract_flags::<i64>(&arr);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![42, 99]);
    }

    /// Given: An array with a wrong type element
    /// When: Extracting flags
    /// Then: An error is returned
    #[test]
    fn test_extract_flags_wrong_type() {
        let arr: Array = vec![Dynamic::from("not_a_number")];
        let result = extract_flags::<i64>(&arr);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expected"));
    }

    /// Given: A list of integers
    /// When: Checking for a specific value with has_flag
    /// Then: Returns true if present
    #[test]
    fn test_has_flag() {
        let flags = vec![1, 2, 3];
        assert!(has_flag(&flags, |f| *f == 2));
        assert!(!has_flag(&flags, |f| *f == 5));
    }

    /// Given: A list of Option values
    /// When: Using find_flag_value
    /// Then: The first matching value is returned
    #[test]
    fn test_find_flag_value() {
        let flags = vec![None, Some(42_i64), Some(99)];
        let result = find_flag_value(&flags, |f| *f);
        assert_eq!(result, Some(42));
    }
}
