use rex_test_utils::rhai::common::create_test_engine_and_register;
use rhai::EvalAltResult;
use rstest::rstest;

/// Given: A call to random_alphanumeric
/// When: Checking the output characters
/// Then: All characters should be alphanumeric (A-Z, a-z, 0-9)
#[test]
fn test_random_alphanumeric_contains_only_valid_chars() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let result = engine.eval::<String>(r#"random_alphanumeric(100)"#)?;

    for ch in result.chars() {
        assert!(
            ch.is_ascii_alphanumeric(),
            "Found non-alphanumeric character: '{}'",
            ch
        );
    }
    Ok(())
}

/// Given: A string prefix and random suffix
/// When: Concatenating in Rhai
/// Then: Should create valid combined string with correct format
#[test]
fn test_random_alphanumeric_string_concatenation() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let result = engine.eval::<String>(
        r#"
            let tmp_filename = "tmp." + random_alphanumeric(10);
            tmp_filename
        "#,
    )?;

    assert!(result.starts_with("tmp."), "Should start with 'tmp.'");
    assert_eq!(result.len(), 14, "Should be 'tmp.' (4) + 10 chars = 14");
    assert!(
        result[4..].chars().all(|c| c.is_ascii_alphanumeric()),
        "Random portion should be alphanumeric"
    );
    Ok(())
}

/// Given: Edge case length values
/// When: Calling random_alphanumeric with unusual lengths
/// Then: Should handle edge cases appropriately
#[rstest]
#[case(5, 5)]
#[case(0, 0)] // Zero length should return empty string
#[case(-1, 16)] // Negative should default to 16
#[case(1, 1)] // Single character
fn test_random_alphanumeric_edge_cases(
    #[case] input_length: i64,
    #[case] expected_length: usize,
) -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let result = engine.eval::<String>(&format!(r#"random_alphanumeric({})"#, input_length))?;

    assert_eq!(
        result.len(),
        expected_length,
        "For input {}, expected length {}, got {}",
        input_length,
        expected_length,
        result.len()
    );
    Ok(())
}
