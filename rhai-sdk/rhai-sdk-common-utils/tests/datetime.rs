use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::rhai::common::create_test_engine_and_register;
use rhai::EvalAltResult;
use rstest::rstest;

/// Given: A DateTime object created with current time
/// When: Creating another DateTime object with the current time after a delay
/// Then: The second DateTime object should be later than the first one
#[test]
fn test_datetime_now() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let result = engine.eval::<bool>(
        r#"
            let dt1 = now();
            sleep(3);
            let dt2 = now();
            dt2 > dt1
        "#,
    );

    assert!(result.unwrap());
    Ok(())
}

/// Given: An epoch seconds value
/// When: Creating a DateTime object from the epoch seconds value then converting it back to epoch seconds
/// Then: It should return the original epoch seconds value
#[test]
fn test_datetime_to_and_from_epoch_seconds() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let result = engine.eval::<i64>(
        r#"
            let dt = from_epoch_seconds(1730033580);
            dt.epoch_seconds();
        "#,
    );

    assert_eq!(result.unwrap(), 1730033580);
    Ok(())
}

/// Given: An epoch seconds and nanoseconds value
/// When: Creating a DateTime object from the epoch seconds and nanoseconds components then converting it back to epoch
/// Then: It should return the original epoch seconds and nanoseconds value
#[test]
fn test_datetime_to_and_from_epoch_nanoseconds() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = rhai::Scope::new();

    let _ = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dt = from_epoch_nanos(1730033580, 123456789);
            let seconds = dt.epoch_seconds();
            let nanos = dt.nanos();
        "#,
    )?;

    let seconds: i64 = scope.get_value("seconds").unwrap();
    let nanos: i64 = scope.get_value("nanos").unwrap();

    assert_eq!((seconds, nanos), (1730033580, 123456789));

    Ok(())
}

/// Given: A DateTime object created with current time
/// When: Accessing the getters in the Rhai engine
/// Then: It should return the correct values
#[test]
fn test_datetime_getters() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = rhai::Scope::new();

    let _ = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dt = now_nanos();
            let year = dt.year;
            let month = dt.month;
            let day = dt.day;
            let hour = dt.hour;
            let minute = dt.minute;
            let second = dt.second;
            let nanosecond = dt.nanosecond;
        "#,
    )?;

    let year: i64 = scope.get_value("year").unwrap();
    let month: i64 = scope.get_value("month").unwrap();
    let day: i64 = scope.get_value("day").unwrap();

    assert!(year >= 2025);
    assert_eq!(month >= 1 && month <= 12, true);
    assert_eq!(day >= 1 && day <= 31, true);
    Ok(())
}

/// Given: A DateTime object
/// When: Calling getters to retrieve the month name as a string
/// Then: The correct month is displayed as a string
#[test]
fn test_get_month_as_string() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();

    let mut scope = rhai::Scope::new();

    let _ = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dt = DateTime(2025, 8, 1, 12, 0, 0, 0);
            let full_month = dt.month_str();
            let short_month = dt.month_str_short();
        "#,
    )?;

    let full_month: String = scope.get_value("full_month").unwrap();
    let short_month: String = scope.get_value("short_month").unwrap();

    assert_eq!(full_month, "August");
    assert_eq!(short_month, "Aug");
    Ok(())
}

/// Given: Two DateTime objects with different times
/// When: Comparing them using the < operator in the Rhai engine
/// Then: The earlier DateTime should be less than the later DateTime
#[test]
fn test_datetime_comparison() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let result = engine.eval::<bool>(
        r#"
            let dt1 = DateTime(2025, 1, 1, 12, 0, 0, 0);
            let dt2 = DateTime(2025, 1, 1, 13, 0, 0, 0);
            dt1 < dt2
            "#,
    );
    assert!(result.unwrap());
    Ok(())
}

/// Given: A DateTime and a format  
/// When: Formatting the DateTime using to_string in the Rhai engine
/// Then: Valid DateTimes should format successfully, invalid DateTimes should error
#[rstest]
#[case(
    2025,
    14,
    21,
    10,
    30,
    0,
    "DateTimeFormat::RFC3339",
    false,
    "Invalid time component"
)]
#[case(2025, 10, 21, 14, 30, 0, "DateTimeFormat::RFC3339", true, "")]
#[case(2025, 10, 21, 14, 30, 0, "DateTimeFormat::RFC2822", true, "")]
fn test_datetime_to_string_formats(
    #[case] year: i64,
    #[case] month: i64,
    #[case] day: i64,
    #[case] hour: i64,
    #[case] minute: i64,
    #[case] second: i64,
    #[case] format: &str,
    #[case] should_succeed: bool,
    #[case] expected_error_msg: &str,
) -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let script = format!(
        r#"
            let dt = DateTime({}, {}, {}, {}, {}, {}, 0);
            dt.to_string({})
        "#,
        year, month, day, hour, minute, second, format
    );

    let result = engine.eval::<String>(&script);

    if should_succeed {
        assert!(
            result.is_ok(),
            "Expected formatting to succeed but got error: {:?}",
            result.unwrap_err()
        );

        let formatted = result.unwrap();
        if format.contains("RFC3339") {
            assert!(
                formatted.contains("2025-10-21"),
                "RFC3339 should contain date in YYYY-MM-DD format"
            );
        }
    } else {
        assert!(
            result.is_err(),
            "Expected formatting to fail but it succeeded"
        );
        assert_error_contains(result, expected_error_msg);
    }

    Ok(())
}

/// Given: A datetime string and a format
/// When: Parsing the datetime using parse_datetime
/// Then: Valid strings should parse successfully, invalid strings should error
#[rstest]
#[case(
    "invalid-datetime",
    "DateTimeFormat::RFC2822",
    false,
    "Failed to parse RFC2822"
)]
#[case("2025-10-21T14:30:00Z", "DateTimeFormat::RFC3339", true, "")]
#[case("Tue, 21 Oct 2025 14:30:00 +0000", "DateTimeFormat::RFC2822", true, "")]
fn test_parse_datetime(
    #[case] datetime_str: &str,
    #[case] format: &str,
    #[case] should_succeed: bool,
    #[case] expected_error_msg: &str,
) -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let script = format!(
        r#"
            let dt = parse_datetime("{}", {});
        "#,
        datetime_str, format
    );

    let result = engine.eval::<()>(&script);

    if should_succeed {
        assert!(
            result.is_ok(),
            "Expected parsing to succeed but got error: {:?}",
            result.unwrap_err()
        );
    } else {
        assert!(result.is_err(), "Expected parsing to fail but it succeeded");
        assert_error_contains(result, expected_error_msg);
    }

    Ok(())
}

/// Given: Two DateTimes and an operation
/// When: Performing arithmetic operations (addition/subtraction)
/// Then: The result should match expected behavior
#[rstest]
// Addition with positive seconds
#[case(2025, 1, 1, 12, 0, 0, 3600, "add", 2025, 1, 1, 13, 0, 0)]
#[case(2025, 1, 1, 12, 0, 0, -3600, "add", 2025, 1, 1, 11, 0, 0)]
#[case(2025, 1, 1, 12, 0, 0, 3600, "sub", 2025, 1, 1, 11, 0, 0)]
#[case(2025, 1, 1, 12, 0, 0, -3600, "sub", 2025, 1, 1, 13, 0, 0)]
#[case(2025, 1, 1, 0, 0, 0, 86400 * 7, "add", 2025, 1, 8, 0, 0, 0)]
#[case(2025, 1, 1, 12, 30, 45, 0, "add", 2025, 1, 1, 12, 30, 45)]
fn test_datetime_arithmetic_operations(
    #[case] year1: i64,
    #[case] month1: i64,
    #[case] day1: i64,
    #[case] hour1: i64,
    #[case] minute1: i64,
    #[case] second1: i64,
    #[case] seconds_delta: i64,
    #[case] operation: &str,
    #[case] expected_year: i64,
    #[case] expected_month: i64,
    #[case] expected_day: i64,
    #[case] expected_hour: i64,
    #[case] expected_minute: i64,
    #[case] expected_second: i64,
) -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = rhai::Scope::new();

    let op_symbol = match operation {
        "add" => "+",
        "sub" => "-",
        _ => panic!("Invalid operation"),
    };

    let script = format!(
        r#"
            let dt1 = DateTime({}, {}, {}, {}, {}, {}, 0);
            let dt2 = dt1 {} {};
            let year = dt2.year;
            let month = dt2.month;
            let day = dt2.day;
            let hour = dt2.hour;
            let minute = dt2.minute;
            let second = dt2.second;
        "#,
        year1, month1, day1, hour1, minute1, second1, op_symbol, seconds_delta
    );

    engine.eval_with_scope::<()>(&mut scope, &script)?;

    let year: i64 = scope.get_value("year").unwrap();
    let month: i64 = scope.get_value("month").unwrap();
    let day: i64 = scope.get_value("day").unwrap();
    let hour: i64 = scope.get_value("hour").unwrap();
    let minute: i64 = scope.get_value("minute").unwrap();
    let second: i64 = scope.get_value("second").unwrap();

    assert_eq!(year, expected_year, "Year mismatch");
    assert_eq!(month, expected_month, "Month mismatch");
    assert_eq!(day, expected_day, "Day mismatch");
    assert_eq!(hour, expected_hour, "Hour mismatch");
    assert_eq!(minute, expected_minute, "Minute mismatch");
    assert_eq!(second, expected_second, "Second mismatch");

    Ok(())
}

/// Given: Two DateTimes
/// When: Calculating the difference between them
/// Then: The result should be the correct number of seconds
#[rstest]
#[case(2025, 1, 1, 12, 0, 0, 2025, 1, 1, 13, 0, 0, 3600)]
#[case(2025, 1, 1, 13, 0, 0, 2025, 1, 1, 12, 0, 0, -3600)]
#[case(2024, 12, 31, 23, 59, 59, 2025, 1, 1, 0, 0, 0, 1)]
#[case(2025, 1, 1, 12, 0, 0, 2025, 1, 1, 12, 0, 0, 0)]
fn test_datetime_difference(
    #[case] year1: i64,
    #[case] month1: i64,
    #[case] day1: i64,
    #[case] hour1: i64,
    #[case] minute1: i64,
    #[case] second1: i64,
    #[case] year2: i64,
    #[case] month2: i64,
    #[case] day2: i64,
    #[case] hour2: i64,
    #[case] minute2: i64,
    #[case] second2: i64,
    #[case] expected_diff: i64,
) -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let result = engine.eval::<i64>(&format!(
        r#"
                let dt1 = DateTime({}, {}, {}, {}, {}, {}, 0);
                let dt2 = DateTime({}, {}, {}, {}, {}, {}, 0);
                dt2 - dt1
            "#,
        year1, month1, day1, hour1, minute1, second1, year2, month2, day2, hour2, minute2, second2
    ))?;
    assert_eq!(result, expected_diff);
    Ok(())
}

/// Given: Two DateTimes and a comparison operator
/// When: Comparing them
/// Then: The result should match expected behavior
#[rstest]
#[case(2025, 1, 1, 12, 0, 0, 2025, 1, 1, 12, 0, 0, "==", true)]
#[case(2025, 1, 1, 12, 0, 0, 2025, 1, 1, 13, 0, 0, "==", false)]
#[case(2025, 1, 1, 12, 0, 0, 2025, 1, 1, 13, 0, 0, "!=", true)]
#[case(2025, 1, 1, 12, 0, 0, 2025, 1, 1, 12, 0, 0, "!=", false)]
#[case(2025, 1, 1, 12, 0, 0, 2025, 1, 1, 13, 0, 0, "<", true)]
#[case(2025, 1, 1, 13, 0, 0, 2025, 1, 1, 12, 0, 0, "<", false)]
#[case(2025, 1, 1, 12, 0, 0, 2025, 1, 1, 12, 0, 0, "<", false)]
#[case(2025, 1, 1, 12, 0, 0, 2025, 1, 1, 13, 0, 0, "<=", true)]
#[case(2025, 1, 1, 12, 0, 0, 2025, 1, 1, 12, 0, 0, "<=", true)]
#[case(2025, 1, 1, 13, 0, 0, 2025, 1, 1, 12, 0, 0, "<=", false)]
#[case(2025, 1, 1, 13, 0, 0, 2025, 1, 1, 12, 0, 0, ">", true)]
#[case(2025, 1, 1, 12, 0, 0, 2025, 1, 1, 13, 0, 0, ">", false)]
#[case(2025, 1, 1, 12, 0, 0, 2025, 1, 1, 12, 0, 0, ">", false)]
#[case(2025, 1, 1, 13, 0, 0, 2025, 1, 1, 12, 0, 0, ">=", true)]
#[case(2025, 1, 1, 12, 0, 0, 2025, 1, 1, 12, 0, 0, ">=", true)]
#[case(2025, 1, 1, 12, 0, 0, 2025, 1, 1, 13, 0, 0, ">=", false)]
#[case(2025, 1, 31, 23, 59, 59, 2025, 2, 1, 0, 0, 0, "<", true)]
#[case(2025, 2, 1, 0, 0, 0, 2025, 1, 31, 23, 59, 59, ">", true)]
fn test_datetime_comparisons(
    #[case] year1: i64,
    #[case] month1: i64,
    #[case] day1: i64,
    #[case] hour1: i64,
    #[case] minute1: i64,
    #[case] second1: i64,
    #[case] year2: i64,
    #[case] month2: i64,
    #[case] day2: i64,
    #[case] hour2: i64,
    #[case] minute2: i64,
    #[case] second2: i64,
    #[case] operator: &str,
    #[case] expected: bool,
) -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let result = engine.eval::<bool>(&format!(
        r#"
                let dt1 = DateTime({}, {}, {}, {}, {}, {}, 0);
                let dt2 = DateTime({}, {}, {}, {}, {}, {}, 0);
                dt1 {} dt2
            "#,
        year1,
        month1,
        day1,
        hour1,
        minute1,
        second1,
        year2,
        month2,
        day2,
        hour2,
        minute2,
        second2,
        operator
    ))?;
    assert_eq!(result, expected);
    Ok(())
}
