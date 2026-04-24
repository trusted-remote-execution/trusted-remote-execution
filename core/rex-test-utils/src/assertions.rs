use core::fmt::{Debug, Display};

use assertables::assert_contains;

/// Helper function to assert that a Result is an error and contains the expected error message
/// in either its Display or Debug representation.
///
/// This function checks if:
/// 1. The result is an error (panics if it's Ok)
/// 2. The error message contains the expected string in either Display or Debug format
///
/// # Panics
///
/// This function will panic if:
/// - The result is Ok but an error was expected
/// - The error message doesn't contain the expected string in either Display or Debug format
///
/// # Examples
///
/// ```
/// use rex_test_utils::assertions::assert_error_contains;
///
/// let result: Result<(), &str> = Err("something went wrong");
/// assert_error_contains(result, "went wrong");
/// ```
pub fn assert_error_contains<T, E: Display + Debug>(result: Result<T, E>, expected_error: &str) {
    assert!(result.is_err(), "Expected an error but got Ok");

    if let Err(error) = result {
        let display_string = error.to_string();
        if display_string.contains(expected_error) {
            return;
        }

        // If not found in Display, try Debug format
        let debug_string = format!("{error:?}");
        if debug_string.contains(expected_error) {
            return;
        }

        assert_contains!(
            display_string.clone(),
            expected_error,
            "Expected error to contain '{}', but got Display: '{}', Debug: '{:?}'",
            expected_error,
            display_string,
            error
        );
    }
}

/// Asserts that the percentage difference between two numbers is below a specified threshold.
///
/// This function calculates the relative error percentage between `actual` and `expected` values
/// and asserts that this error is below the given `max_error_percentage` threshold.
///
/// # Arguments
///
/// * `actual` - The actual measured value
/// * `expected` - The expected reference value
/// * `max_error_percentage` - Maximum allowed error percentage (e.g., 20.0 for 20%)
///
/// # Panics
///
/// This function will panic if the calculated error percentage exceeds the threshold.
/// For near-zero expected values (< 0.1), the error percentage is treated as 0.0.
///
pub fn assert_percentage_difference(actual: f64, expected: f64, max_error_percentage: f64) {
    let error_percent = if expected.abs() > 0.1 {
        ((actual - expected).abs() / expected.abs()) * 100.0
    } else {
        0.0
    };

    assert!(
        error_percent <= max_error_percentage,
        "Validation failed: actual={actual:.1}, expected={expected:.1}, error={error_percent:.1}% (max allowed: {max_error_percentage:.1}%)"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt;

    struct DebugOnlyError(String);

    impl Debug for DebugOnlyError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "DebugOnlyError({})", self.0)
        }
    }

    impl Display for DebugOnlyError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "Error occurred")
        }
    }

    /// Given: A Result with an error that has the message in Display format
    /// When: assert_error_contains is called with the expected message
    /// Then: The function succeeds without panicking
    #[test]
    fn test_assert_error_contains_display_format() {
        let result: Result<(), String> = Err("display error message".to_string());
        assert_error_contains(result, "display error");
    }

    /// Given: A Result with an error that has the message only in Debug format
    /// When: assert_error_contains is called with the expected message
    /// Then: The function succeeds without panicking
    #[test]
    fn test_assert_error_contains_debug_format() {
        let result: Result<(), DebugOnlyError> =
            Err(DebugOnlyError("debug error message".to_string()));
        assert_error_contains(result, "debug error");
    }

    /// Given: An Ok Result
    /// When: assert_error_contains is called
    /// Then: The function panics with the expected message
    #[test]
    #[should_panic(expected = "Expected an error but got Ok")]
    fn test_assert_error_contains_panics_on_ok() {
        let result: Result<(), &str> = Ok(());
        assert_error_contains(result, "any message");
    }

    /// Given: A Result with an error that doesn't contain the expected message
    /// When: assert_error_contains is called with a message not in the error
    /// Then: The function panics
    #[test]
    #[should_panic]
    fn test_assert_error_contains_panics_on_missing_message() {
        let result: Result<(), &str> = Err("actual error");
        assert_error_contains(result, "different error");
    }

    /// Given: Two numbers with difference below the threshold
    /// When: assert_percentage_difference is called
    /// Then: The function succeeds without panicking
    #[test]
    fn test_assert_percentage_difference_within_threshold() {
        assert_percentage_difference(105.0, 100.0, 10.0);
        assert_percentage_difference(95.0, 100.0, 10.0);
    }

    /// Given: Two numbers with difference above the threshold
    /// When: assert_percentage_difference is called
    /// Then: The function panics with detailed error message
    #[test]
    #[should_panic(expected = "Validation failed")]
    fn test_assert_percentage_difference_exceeds_threshold() {
        assert_percentage_difference(130.0, 100.0, 20.0);
    }
}
