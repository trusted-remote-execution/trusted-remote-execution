use rex_test_utils::rhai::common::{
    create_test_engine_and_register, create_test_file, deny_all_engine,
};
use rhai::Map;

// ── awk_split ───────────────────────────────────────────────────────────────

/// Given: A string with spaces
/// When: Using awk_split(text, " ")
/// Then: Fields are returned as an array
#[test]
fn test_awk_split_basic() {
    let engine = create_test_engine_and_register();
    let result: rhai::Array = engine.eval(r#"awk_split("hello world foo", " ")"#).unwrap();
    assert_eq!(result.len(), 3);
    assert_eq!(result[0].clone().into_string().unwrap(), "hello");
    assert_eq!(result[2].clone().into_string().unwrap(), "foo");
}

/// Given: A CSV string
/// When: Using awk_split with comma delimiter
/// Then: Fields are split by comma
#[test]
fn test_awk_split_csv() {
    let engine = create_test_engine_and_register();
    let result: rhai::Array = engine.eval(r#"awk_split("a,b,c", ",")"#).unwrap();
    assert_eq!(result.len(), 3);
}

// ── awk_field ───────────────────────────────────────────────────────────────

/// Given: A file with space-delimited fields
/// When: Using awk_field(2, " ", path)
/// Then: The second field from each line is returned
#[test]
fn test_awk_field_basic() {
    let (_temp, path) = create_test_file("a 10 x\nb 20 y\nc 30 z");
    let engine = create_test_engine_and_register();
    let result: rhai::Array = engine
        .eval(&format!(r#"awk_field(2, " ", "{path}")"#))
        .unwrap();
    let vals: Vec<String> = result
        .into_iter()
        .map(|v| v.into_string().unwrap())
        .collect();
    assert_eq!(vals, vec!["10", "20", "30"]);
}

/// Given: A field number of 0
/// When: Using awk_field
/// Then: An error is returned
#[test]
fn test_awk_field_invalid_index() {
    let (_temp, path) = create_test_file("a b c");
    let engine = create_test_engine_and_register();
    let result = engine.eval::<rhai::Array>(&format!(r#"awk_field(0, " ", "{path}")"#));
    assert!(result.is_err());
}

// ── awk_filter ──────────────────────────────────────────────────────────────

/// Given: A file with lines containing "ERROR"
/// When: Using awk_filter("ERROR", path)
/// Then: Only lines containing "ERROR" are returned
#[test]
fn test_awk_filter_basic() {
    let (_temp, path) = create_test_file("INFO ok\nERROR bad\nINFO fine\nERROR worse");
    let engine = create_test_engine_and_register();
    let result: rhai::Array = engine
        .eval(&format!(r#"awk_filter("ERROR", "{path}")"#))
        .unwrap();
    assert_eq!(result.len(), 2);
}

// ── awk_filter_field ────────────────────────────────────────────────────────

/// Given: A file with space-delimited fields
/// When: Using awk_filter_field to match field 1 containing "a"
/// Then: Only lines where field 1 contains "a" are returned
#[test]
fn test_awk_filter_field_basic() {
    let (_temp, path) = create_test_file("apple 1\nbanana 2\napricot 3");
    let engine = create_test_engine_and_register();
    let result: rhai::Array = engine
        .eval(&format!(r#"awk_filter_field(1, " ", "ap", "{path}")"#))
        .unwrap();
    assert_eq!(result.len(), 2);
}

// ── awk_sum ─────────────────────────────────────────────────────────────────

/// Given: A file with numeric data in column 2
/// When: Using awk_sum(2, " ", path)
/// Then: The sum of column 2 is returned
#[test]
fn test_awk_sum_basic() {
    let (_temp, path) = create_test_file("a 10\nb 20\nc 30");
    let engine = create_test_engine_and_register();
    let result: f64 = engine
        .eval(&format!(r#"awk_sum(2, " ", "{path}")"#))
        .unwrap();
    assert!((result - 60.0).abs() < f64::EPSILON);
}

/// Given: A file with non-numeric data in the target column
/// When: Using awk_sum
/// Then: Non-numeric values are skipped, sum is 0
#[test]
fn test_awk_sum_non_numeric() {
    let (_temp, path) = create_test_file("a x\nb y");
    let engine = create_test_engine_and_register();
    let result: f64 = engine
        .eval(&format!(r#"awk_sum(2, " ", "{path}")"#))
        .unwrap();
    assert!((result - 0.0).abs() < f64::EPSILON);
}

// ── awk_count_unique ────────────────────────────────────────────────────────

/// Given: A file with repeated values in column 1
/// When: Using awk_count_unique(1, " ", path)
/// Then: A map of value -> count is returned
#[test]
fn test_awk_count_unique_basic() {
    let (_temp, path) = create_test_file("a 1\nb 2\na 3\nb 4\nc 5");
    let engine = create_test_engine_and_register();
    let result: Map = engine
        .eval(&format!(r#"awk_count_unique(1, " ", "{path}")"#))
        .unwrap();
    assert_eq!(result["a"].clone().cast::<i64>(), 2);
    assert_eq!(result["b"].clone().cast::<i64>(), 2);
    assert_eq!(result["c"].clone().cast::<i64>(), 1);
}

// ── awk_filter_range ────────────────────────────────────────────────────────

/// Given: A file with 5 lines
/// When: Using awk_filter_range(2, 4, path)
/// Then: Lines 2 through 4 are returned
#[test]
fn test_awk_filter_range_basic() {
    let (_temp, path) = create_test_file("line1\nline2\nline3\nline4\nline5");
    let engine = create_test_engine_and_register();
    let result: rhai::Array = engine
        .eval(&format!(r#"awk_filter_range(2, 4, "{path}")"#))
        .unwrap();
    assert_eq!(result.len(), 3);
    assert_eq!(result[0].clone().into_string().unwrap(), "line2");
    assert_eq!(result[2].clone().into_string().unwrap(), "line4");
}

/// Given: An invalid range (start > end)
/// When: Using awk_filter_range
/// Then: An error is returned
#[test]
fn test_awk_filter_range_invalid() {
    let (_temp, path) = create_test_file("line1\nline2");
    let engine = create_test_engine_and_register();
    let result = engine.eval::<rhai::Array>(&format!(r#"awk_filter_range(5, 2, "{path}")"#));
    assert!(result.is_err());
}

// ── error cases ─────────────────────────────────────────────────────────────

/// Given: A file and a deny-all policy
/// When: Using awk_field
/// Then: An authorization error is returned
#[test]
fn test_awk_unauthorized() {
    let (_temp, path) = create_test_file("a b c");
    let engine = deny_all_engine();
    let result = engine.eval::<rhai::Array>(&format!(r#"awk_field(1, " ", "{path}")"#));
    assert!(result.is_err());
    let err_str = format!("{:?}", result.unwrap_err());
    assert!(
        err_str.contains("unauthorized") || err_str.contains("Permission denied"),
        "Expected authorization error, got: {err_str}",
    );
}
