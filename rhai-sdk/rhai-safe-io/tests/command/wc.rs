use assert_fs::TempDir;
use rex_test_utils::rhai::common::{
    create_test_engine_and_register, create_test_file, deny_all_engine,
};
use rhai::Map;
use std::fs;

// ── basic usage ─────────────────────────────────────────────────────────────

/// Given: A file with known content
/// When: Using wc(path)
/// Then: Correct line, word, and byte counts are returned
#[test]
fn test_wc_basic() {
    let (_temp, path) = create_test_file("hello world\nfoo bar baz\n");
    let engine = create_test_engine_and_register();
    let result: Map = engine.eval(&format!(r#"wc("{path}")"#)).unwrap();
    assert_eq!(result["lines"].clone().cast::<i64>(), 2);
    assert_eq!(result["words"].clone().cast::<i64>(), 5);
}

/// Given: An empty file
/// When: Using wc(path)
/// Then: All counts are 0
#[test]
fn test_wc_empty_file() {
    let (_temp, path) = create_test_file("");
    let engine = create_test_engine_and_register();
    let result: Map = engine.eval(&format!(r#"wc("{path}")"#)).unwrap();
    assert_eq!(result["lines"].clone().cast::<i64>(), 0);
    assert_eq!(result["words"].clone().cast::<i64>(), 0);
    assert_eq!(result["bytes"].clone().cast::<i64>(), 0);
}

/// Given: A file with a single line and no trailing newline
/// When: Using wc(path)
/// Then: Line count reflects the content
#[test]
fn test_wc_single_line_no_newline() {
    let (_temp, path) = create_test_file("hello world");
    let engine = create_test_engine_and_register();
    let result: Map = engine.eval(&format!(r#"wc("{path}")"#)).unwrap();
    assert_eq!(result["words"].clone().cast::<i64>(), 2);
    assert_eq!(result["bytes"].clone().cast::<i64>(), 11);
}

/// Given: A Rhai script that uses wc and accesses map fields
/// When: Running the script
/// Then: The fields are accessible as a map
#[test]
fn test_wc_script_access_fields() {
    let (_temp, path) = create_test_file("one two three\nfour five\n");
    let engine = create_test_engine_and_register();
    let script = format!(
        r#"
        let counts = wc("{path}");
        counts.words
        "#,
    );
    let result: i64 = engine.eval(&script).unwrap();
    assert_eq!(result, 5);
}

// ── flag usage ──────────────────────────────────────────────────────────────

/// Given: A file with known content and the lines flag
/// When: Using wc([wc::lines], path)
/// Then: Only the lines key is present in the result
#[test]
fn test_wc_lines_flag() {
    let (_temp, path) = create_test_file("hello world\nfoo bar baz\n");
    let engine = create_test_engine_and_register();
    let result: Map = engine
        .eval(&format!(r#"wc([wc::lines], "{path}")"#))
        .unwrap();
    assert!(result.contains_key("lines"));
    assert!(!result.contains_key("words"));
    assert!(!result.contains_key("bytes"));
    assert_eq!(result["lines"].clone().cast::<i64>(), 2);
}

/// Given: A file with known content and the short l flag
/// When: Using wc([wc::l], path)
/// Then: Only the lines key is present
#[test]
fn test_wc_short_l_flag() {
    let (_temp, path) = create_test_file("a\nb\nc\n");
    let engine = create_test_engine_and_register();
    let result: Map = engine.eval(&format!(r#"wc([wc::l], "{path}")"#)).unwrap();
    assert!(result.contains_key("lines"));
    assert!(!result.contains_key("words"));
}

/// Given: A file with known content and the words flag
/// When: Using wc([wc::words], path)
/// Then: Only the words key is present
#[test]
fn test_wc_words_flag() {
    let (_temp, path) = create_test_file("hello world\nfoo bar baz\n");
    let engine = create_test_engine_and_register();
    let result: Map = engine
        .eval(&format!(r#"wc([wc::words], "{path}")"#))
        .unwrap();
    assert!(!result.contains_key("lines"));
    assert!(result.contains_key("words"));
    assert!(!result.contains_key("bytes"));
    assert_eq!(result["words"].clone().cast::<i64>(), 5);
}

/// Given: A file with known content and the bytes flag
/// When: Using wc([wc::bytes], path)
/// Then: Only the bytes key is present
#[test]
fn test_wc_bytes_flag() {
    let (_temp, path) = create_test_file("hello");
    let engine = create_test_engine_and_register();
    let result: Map = engine.eval(&format!(r#"wc([wc::c], "{path}")"#)).unwrap();
    assert!(!result.contains_key("lines"));
    assert!(!result.contains_key("words"));
    assert!(result.contains_key("bytes"));
    assert_eq!(result["bytes"].clone().cast::<i64>(), 5);
}

/// Given: A file with known content and multiple flags
/// When: Using wc([wc::lines, wc::bytes], path)
/// Then: Only the requested keys are present
#[test]
fn test_wc_multiple_flags() {
    let (_temp, path) = create_test_file("hello world\n");
    let engine = create_test_engine_and_register();
    let result: Map = engine
        .eval(&format!(r#"wc([wc::lines, wc::bytes], "{path}")"#))
        .unwrap();
    assert!(result.contains_key("lines"));
    assert!(!result.contains_key("words"));
    assert!(result.contains_key("bytes"));
}

// ── error cases ─────────────────────────────────────────────────────────────

/// Given: A nonexistent file
/// When: Using wc
/// Then: An error is returned
#[test]
fn test_wc_nonexistent_file() {
    let temp = TempDir::new().unwrap();
    let missing = fs::canonicalize(temp.path()).unwrap().join("nope.txt");
    let engine = create_test_engine_and_register();
    let result = engine.eval::<Map>(&format!(r#"wc("{}")"#, missing.display()));
    assert!(result.is_err());
}

/// Given: A file and a deny-all policy
/// When: Using wc
/// Then: An authorization error is returned
#[test]
fn test_wc_unauthorized() {
    let (_temp, path) = create_test_file("content");
    let engine = deny_all_engine();
    let result = engine.eval::<Map>(&format!(r#"wc("{path}")"#));
    assert!(result.is_err());
    let err_str = format!("{:?}", result.unwrap_err());
    assert!(
        err_str.contains("unauthorized") || err_str.contains("Permission denied"),
        "Expected authorization error, got: {err_str}",
    );
}
