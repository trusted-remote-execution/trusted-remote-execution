use assert_fs::TempDir;
use rex_test_utils::rhai::common::{
    create_test_engine_and_register, create_test_file, deny_all_engine,
};
use std::fs;

// ── basic usage ─────────────────────────────────────────────────────────────

/// Given: A file with known content
/// When: Using cat() to read the file
/// Then: The content is returned correctly
#[test]
fn test_cat_reads_file_content() {
    let (_temp, path) = create_test_file("Hello, World!\nThis is a test file.");
    let engine = create_test_engine_and_register();
    let result: String = engine.eval(&format!(r#"cat("{path}")"#)).unwrap();
    assert_eq!(result, "Hello, World!\nThis is a test file.");
}

/// Given: An empty file
/// When: Using cat() to read the file
/// Then: An empty string is returned
#[test]
fn test_cat_empty_file() {
    let (_temp, path) = create_test_file("");
    let engine = create_test_engine_and_register();
    let result: String = engine.eval(&format!(r#"cat("{path}")"#)).unwrap();
    assert_eq!(result, "");
}

/// Given: A file with multi-line content
/// When: Using cat() to read the file
/// Then: All lines are returned with newlines preserved
#[test]
fn test_cat_multiline_file() {
    let (_temp, path) = create_test_file("line1\nline2\nline3\n");
    let engine = create_test_engine_and_register();
    let result: String = engine.eval(&format!(r#"cat("{path}")"#)).unwrap();
    assert_eq!(result, "line1\nline2\nline3\n");
}

// ── flags ───────────────────────────────────────────────────────────────────

/// Given: A file with multi-line content
/// When: Using cat() with cat::number flag
/// Then: Lines are numbered
#[test]
fn test_cat_with_number_flag() {
    let (_temp, path) = create_test_file("line1\nline2\nline3");
    let engine = create_test_engine_and_register();
    let result: String = engine
        .eval(&format!(r#"cat([cat::number], "{path}")"#))
        .unwrap();
    assert!(result.contains("     1\tline1"));
    assert!(result.contains("     2\tline2"));
    assert!(result.contains("     3\tline3"));
}

/// Given: A file with multi-line content
/// When: Using cat() with cat::n short form flag
/// Then: Lines are numbered (same as cat::number)
#[test]
fn test_cat_with_short_n_flag() {
    let (_temp, path) = create_test_file("line1\nline2");
    let engine = create_test_engine_and_register();
    let result: String = engine.eval(&format!(r#"cat([cat::n], "{path}")"#)).unwrap();
    assert!(result.contains("     1\tline1"));
    assert!(result.contains("     2\tline2"));
}

// ── error cases ─────────────────────────────────────────────────────────────

/// Given: A file that does not exist
/// When: Using cat() to read the file
/// Then: An error is returned
#[test]
fn test_cat_nonexistent_file_returns_error() {
    let temp = TempDir::new().unwrap();
    let missing = fs::canonicalize(temp.path())
        .unwrap()
        .join("nonexistent.txt");
    let engine = create_test_engine_and_register();
    let result = engine.eval::<String>(&format!(r#"cat("{}")"#, missing.display()));
    assert!(result.is_err());
}

/// Given: A file with content and a deny-all authorization policy
/// When: Using cat() to read the file
/// Then: An authorization error is returned
#[test]
fn test_cat_unauthorized_returns_error() {
    let (_temp, path) = create_test_file("secret content");
    let engine = deny_all_engine();
    let result = engine.eval::<String>(&format!(r#"cat("{path}")"#));
    assert!(result.is_err());
    let err_str = format!("{:?}", result.unwrap_err());
    assert!(
        err_str.contains("unauthorized") || err_str.contains("Permission denied"),
        "Expected authorization error, got: {err_str}",
    );
}

// ── Rhai script tests ───────────────────────────────────────────────────────

/// Given: A file with multi-line content
/// When: Running a Rhai script that reads the file, splits lines, and counts them
/// Then: The script returns the correct line count
#[test]
fn test_cat_script_read_and_count_lines() {
    let (_temp, path) = create_test_file("alpha\nbeta\ngamma\ndelta\n");
    let engine = create_test_engine_and_register();
    let script = format!(
        r#"
        let content = cat("{path}");
        let lines = content.split("\n");
        let count = 0;
        for line in lines {{
            if line != "" {{ count += 1; }}
        }}
        count
        "#,
    );
    let result: i64 = engine.eval(&script).unwrap();
    assert_eq!(result, 4);
}

/// Given: A file with numbered content
/// When: Running a Rhai script that uses cat with the number flag
/// Then: Each line is prefixed with its line number
#[test]
fn test_cat_script_number_flag_formatting() {
    let (_temp, path) = create_test_file("first\nsecond\nthird");
    let engine = create_test_engine_and_register();
    let script = format!(r#"cat([cat::number], "{path}")"#);
    let result: String = engine.eval(&script).unwrap();
    let lines: Vec<&str> = result.lines().collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0].trim(), "1\tfirst");
    assert_eq!(lines[1].trim(), "2\tsecond");
    assert_eq!(lines[2].trim(), "3\tthird");
}

/// Given: A Rhai script that cats a nonexistent file inside a try/catch
/// When: The script runs
/// Then: The catch block captures the error and the script completes
#[test]
fn test_cat_script_error_handling() {
    let temp = TempDir::new().unwrap();
    let missing = fs::canonicalize(temp.path()).unwrap().join("nope.txt");
    let engine = create_test_engine_and_register();
    let script = format!(
        r#"
        let status = "ok";
        try {{
            cat("{}");
            status = "should not reach here";
        }} catch(err) {{
            status = "caught";
        }}
        status
        "#,
        missing.display()
    );
    let result: String = engine.eval(&script).unwrap();
    assert_eq!(result, "caught");
}
