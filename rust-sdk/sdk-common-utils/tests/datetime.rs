use assertables::assert_contains;
use rex_test_utils::assertions::assert_error_contains;
use rust_sdk_common_utils::types::datetime::{DateTime, DateTimeFormat};

// 2024-10-21 14:34:28 UTC
const TEST_TIMESTAMP: i64 = 1729521268;
const TEST_NANOS: i64 = 123_456_789;

/// Given: Unix epoch timestamps
/// When: Converting from epoch seconds to DateTime
/// Then: DateTime should represent the correct date and time
#[test]
fn test_datetime_from_epoch_seconds() {
    // Unix epoch
    let dt = DateTime::from_epoch_seconds(0).unwrap();
    assert_eq!(*dt.year(), 1970);
    assert_eq!(*dt.month(), 1);
    assert_eq!(*dt.day(), 1);
    assert_eq!(*dt.hour(), 0);
    assert_eq!(*dt.minute(), 0);
    assert_eq!(*dt.second(), 0);

    let dt = DateTime::from_epoch_seconds(TEST_TIMESTAMP).unwrap();
    assert_eq!(*dt.year(), 2024);
    assert_eq!(*dt.month(), 10);
    assert_eq!(*dt.day(), 21);
}

/// Given: Epoch time split into seconds and nanoseconds
/// When: Creating DateTime from epoch nanos with valid and invalid nanosecond values
/// Then: Valid nanos should be stored, invalid nanos should error
#[test]
fn test_datetime_from_epoch_nanos() {
    let valid_dt = DateTime::from_epoch_nanos(TEST_TIMESTAMP, TEST_NANOS).unwrap();
    assert_eq!(valid_dt.epoch_seconds().unwrap(), TEST_TIMESTAMP);
    assert_eq!(valid_dt.nanos(), TEST_NANOS);

    let invalid_dt = DateTime::from_epoch_nanos(TEST_TIMESTAMP, -1);
    assert!(invalid_dt.is_err());
}

/// Given: Current system time
/// When: Calling DateTime::now()
/// Then: DateTime should represent a valid current time in UTC truncated to seconds
#[test]
fn test_datetime_now() {
    let dt = DateTime::now().unwrap();

    // Basic sanity checks
    assert!(*dt.year() >= 2025);
    assert!(*dt.month() >= 1 && *dt.month() <= 12);
    assert!(*dt.day() >= 1 && *dt.day() <= 31);
    assert!(*dt.hour() <= 23);
    assert!(*dt.minute() <= 59);
    assert!(*dt.second() <= 59);
    assert!(dt.nanos() == 0);
}

/// Given: Current system time
/// When: Calling DateTime::now_nanos()
/// Then: DateTime should represent a valid current time in UTC with nanosecond level precision
#[test]
fn test_datetime_now_nanos() {
    let dt = DateTime::now_nanos();

    // Basic sanity checks
    assert!(*dt.year() >= 2025);
    assert!(*dt.month() >= 1 && *dt.month() <= 12);
    assert!(*dt.day() >= 1 && *dt.day() <= 31);
    assert!(*dt.hour() <= 23);
    assert!(*dt.minute() <= 59);
    assert!(*dt.second() <= 59);
    assert!(dt.nanos() != 0);
}

/// Given: A DateTime instance with a valid month (March)
/// When: Calling month_str() and month_str_short()
/// Then: Both functions should return the correct month strings
#[test]
fn test_datetime_month_str_valid() {
    let dt = DateTime::new(2025, 3, 15, 12, 30, 0, 0);

    let month_result = dt.month_str();
    assert!(month_result.is_ok());
    assert_eq!(month_result.unwrap(), "March");

    let month_short_result = dt.month_str_short();
    assert!(month_short_result.is_ok());
    assert_eq!(month_short_result.unwrap(), "Mar");
}

/// Given: A DateTime instance with an invalid month (13)
/// When: Calling month_str() and month_str_short()
/// Then: Both functions should return an error with descriptive message
#[test]
fn test_datetime_month_str_invalid() {
    let dt = DateTime::new(2025, 13, 15, 12, 30, 0, 0);

    let month_result = dt.month_str();
    assert!(month_result.is_err());
    assert_error_contains(month_result, "Invalid month: 13. Must be 1-12");

    let month_short_result = dt.month_str_short();
    assert!(month_short_result.is_err());
    assert_error_contains(month_short_result, "Invalid month: 13. Must be 1-12");
}

/// Given: A valid RFC3339 datetime string
/// When: Parsing the string to DateTime
/// Then: DateTime should correctly represent the parsed time
#[test]
fn test_datetime_parse_rfc3339_success() {
    let result = DateTime::parse("2025-10-21T14:34:28.123456789Z", DateTimeFormat::Rfc3339);
    assert!(result.is_ok());

    let dt = result.unwrap();
    assert_eq!(*dt.year(), 2025);
    assert_eq!(*dt.month(), 10);
    assert_eq!(*dt.day(), 21);
    assert_eq!(*dt.hour(), 14);
    assert_eq!(*dt.minute(), 34);
    assert_eq!(*dt.second(), 28);
    assert_eq!(dt.nanos(), TEST_NANOS);
}

/// Given: a valid RFC2822 datetime string
/// When: Parsing the string to DateTime
/// Then: DateTime should correctly represent the parsed time
#[test]
fn test_datetime_parse_rfc2822_success() {
    let result = DateTime::parse("21 Oct 2025 14:34:28 +0000", DateTimeFormat::Rfc2822);
    assert!(result.is_ok());

    let dt = result.unwrap();
    assert_eq!(*dt.year(), 2025);
    assert_eq!(*dt.month(), 10);
    assert_eq!(*dt.day(), 21);
    assert_eq!(*dt.hour(), 14);
    assert_eq!(*dt.minute(), 34);
    assert_eq!(*dt.second(), 28);
}

/// Given: An invalid datetime string
/// When: Attempting to parse as RFC3339
/// Then: Should return a ParseError with descriptive message
#[test]
fn test_datetime_parse_rfc3339_invalid() {
    let result = DateTime::parse("invalid-datetime", DateTimeFormat::Rfc3339);
    assert!(result.is_err());
    assert_error_contains(result, "Failed to parse RFC3339");
}

/// Given: An invalid datetime string
/// When: Attempting to parse as RFC2822
/// Then: Should return a ParseError with descriptive message
#[test]
fn test_datetime_parse_rfc2822_invalid() {
    let result = DateTime::parse("invalid-datetime", DateTimeFormat::Rfc2822);
    assert!(result.is_err());
    assert_error_contains(result, "Failed to parse RFC2822");
}

/// Given: A DateTime instance
/// When: Formatting to RFC3339 string
/// Then: Should produce a valid RFC3339 formatted string
#[test]
fn test_datetime_to_string_format_rfc3339() {
    let dt = DateTime::new(2025, 10, 21, 14, 34, 28, 0);
    let result = dt.to_string(DateTimeFormat::Rfc3339);

    assert!(result.is_ok());
    let formatted = result.unwrap();
    assert!(formatted.contains("2025-10-21"));
    assert!(formatted.contains("14:34:28"));
}

/// Given: A DateTime instance
/// When: Formatting to RFC2822
/// Then: Should produce a valid RFC2822 formatted string
#[test]
fn test_datetime_to_string_format_rfc2822() {
    let dt = DateTime::new(2025, 10, 21, 14, 34, 28, 0);
    let result = dt.to_string(DateTimeFormat::Rfc2822);

    assert!(result.is_ok());
    let formatted = result.unwrap();
    assert_contains!(formatted, "21 Oct 2025");
    assert_contains!(formatted, "14:34:28");
}

/// Given: A DateTime instance
/// When: Formatting an invalid date
/// Then: Should return a FormatError
#[test]
fn test_datetime_to_string_invalid_date() {
    let dt = DateTime::new(-999999, 1, 1, 0, 0, 0, 0);

    let result3339 = dt.to_string(DateTimeFormat::Rfc3339);
    assert!(result3339.is_err());
    assert_error_contains(result3339, "Invalid time component");

    let result2822 = dt.to_string(DateTimeFormat::Rfc2822);
    assert!(result2822.is_err());
    assert_error_contains(result2822, "Invalid time component");
}

/// Given: A DateTime instance
/// When: Formatting an invalid time
/// Then: Should return a FormatError
#[test]
fn test_datetime_to_string_invalid_time() {
    let dt = DateTime::new(2020, 1, 1, 25, 0, 0, 0);

    let result3339 = dt.to_string(DateTimeFormat::Rfc3339);
    assert!(result3339.is_err());
    assert_error_contains(result3339, "Invalid time component");

    let result2822 = dt.to_string(DateTimeFormat::Rfc2822);
    assert!(result2822.is_err());
    assert_error_contains(result2822, "Invalid time component");
}

/// Given: Multiple DateTime instances with same and different values
/// When: Comparing using equality operators
/// Then: Equal times should be equal, different times should not be equal
#[test]
fn test_datetime_equality() {
    let dt1 = DateTime::new(2025, 10, 21, 14, 34, 28, TEST_NANOS);
    let dt2 = DateTime::new(2025, 10, 21, 14, 34, 28, TEST_NANOS);
    let dt3 = DateTime::new(2025, 10, 21, 14, 34, 29, 0);

    assert_eq!(dt1, dt2);
    assert_ne!(dt1, dt3);
}

/// Given: Two DateTime instances with one second apart
/// When: Comparing using ordering operators
/// Then: Earlier time should be less than later time
#[test]
fn test_datetime_ordering() {
    let earlier = DateTime::new(2025, 10, 21, 14, 34, 28, 0);
    let later = DateTime::new(2025, 10, 21, 14, 34, 29, 0);

    assert!(earlier < later);
    assert!(later > earlier);
    assert!(earlier <= later);
    assert!(later >= earlier);
}

/// Given: A negative epoch timestamp (before 1970)
/// When: Creating DateTime from negative epoch seconds
/// Then: Should represent the correct date before Unix epoch
#[test]
fn test_datetime_negative_epoch() {
    let dt = DateTime::from_epoch_seconds(-315619200).unwrap();
    assert_eq!(*dt.year(), 1960);
    assert_eq!(*dt.month(), 1);
    assert_eq!(*dt.day(), 1);
}

/// Given: Valid and invalid format strings
/// When: Parsing DateTimeFormat from string
/// Then: Valid formats should succeed, invalid should error
#[test]
fn test_datetime_format_from_string() {
    let format = DateTimeFormat::from_string("RFC3339");
    assert!(format.is_ok());

    let format = DateTimeFormat::from_string("RFC2822");
    assert!(format.is_ok());

    let invalid = DateTimeFormat::from_string("INVALID");
    assert!(invalid.is_err());
}

/// Given: DateTime instances and epoch second values
/// When: Performing arithmetic operations (addition, subtraction, difference)
/// Then: Results should correctly represent time calculations
#[test]
fn test_datetime_arithmetic_operations() {
    let base_dt = DateTime::from_epoch_seconds(TEST_TIMESTAMP).unwrap();

    let future = base_dt.clone() + 3600; // Add 1 hour
    assert_eq!(future.epoch_seconds().unwrap(), TEST_TIMESTAMP + 3600);
    assert_eq!(*future.hour(), 15); // Should be 15:34:28

    let future_ref = &base_dt + 7200; // Add 2 hours
    assert_eq!(future_ref.epoch_seconds().unwrap(), TEST_TIMESTAMP + 7200);
    assert_eq!(*future_ref.hour(), 16); // Should be 16:34:28

    let past = base_dt.clone() - 86400; // Subtract 1 day
    assert_eq!(past.epoch_seconds().unwrap(), TEST_TIMESTAMP - 86400);
    assert_eq!(*past.day(), 20); // Should be October 20

    let past_ref = &base_dt - 3600; // Subtract 1 hour
    assert_eq!(past_ref.epoch_seconds().unwrap(), TEST_TIMESTAMP - 3600);
    assert_eq!(*past_ref.hour(), 13); // Should be 13:34:28

    let dt1 = DateTime::from_epoch_seconds(TEST_TIMESTAMP).unwrap();
    let dt2 = DateTime::from_epoch_seconds(1729607668).unwrap(); // 24 hours later
    let diff = dt2.clone() - dt1.clone();
    assert_eq!(diff, 86400); // 24 hours

    let diff_ref = &dt2 - &dt1;
    assert_eq!(diff_ref, 86400);
}
