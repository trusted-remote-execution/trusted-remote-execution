use rstest::rstest;
use rust_sdk_common_utils::random::random_alphanumeric;

/// Given: Various length values (positive, zero, negative)
/// When: Calling random_alphanumeric
/// Then: Should return a string of the expected length containing only alphanumeric characters
#[rstest]
#[case(5, 5)]
#[case(0, 0)] // Zero length should return empty string
#[case(-1, 16)] // Negative should default to 16
#[case(1, 1)] // Single character
fn test_random_alphanumeric_length(#[case] input: i64, #[case] expected_len: usize) {
    let result = random_alphanumeric(input);
    assert_eq!(
        result.len(),
        expected_len,
        "Input: {}, Expected length: {}, Got: {}",
        input,
        expected_len,
        result.len()
    );
    assert!(
        result.chars().all(|c| c.is_ascii_alphanumeric()),
        "Result contains non-alphanumeric characters"
    );
}
