use assert_fs::TempDir;
use rex_test_utils::rhai::common::{
    create_test_engine_and_register, create_test_file, deny_all_engine,
};
use std::fs;

// ── basic usage ─────────────────────────────────────────────────────────────

/// Given: A file with lines containing "hello"
/// When: Using grep("hello", path)
/// Then: Only matching lines are returned
#[test]
fn test_grep_basic_match() {
    let (_temp, path) = create_test_file("hello world\nfoo bar\nhello again");
    let engine = create_test_engine_and_register();
    let result: rhai::Array = engine.eval(&format!(r#"grep("hello", "{path}")"#)).unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].clone().into_string().unwrap(), "hello world");
    assert_eq!(result[1].clone().into_string().unwrap(), "hello again");
}

/// Given: A file with no matching lines
/// When: Using grep with a pattern that doesn't match
/// Then: An empty array is returned
#[test]
fn test_grep_no_match() {
    let (_temp, path) = create_test_file("alpha\nbeta\ngamma");
    let engine = create_test_engine_and_register();
    let result: rhai::Array = engine.eval(&format!(r#"grep("zzz", "{path}")"#)).unwrap();
    assert!(result.is_empty());
}

// ── flags ───────────────────────────────────────────────────────────────────

/// Given: A file with mixed-case content
/// When: Using grep with grep::ignore_case
/// Then: Case-insensitive matches are returned
#[test]
fn test_grep_ignore_case_flag() {
    let (_temp, path) = create_test_file("Hello\nhello\nHELLO\nworld");
    let engine = create_test_engine_and_register();
    let result: rhai::Array = engine
        .eval(&format!(r#"grep([grep::ignore_case], "hello", "{path}")"#))
        .unwrap();
    assert_eq!(result.len(), 3);
}

/// Given: A file with mixed-case content
/// When: Using grep with grep::i (short form)
/// Then: Case-insensitive matches are returned
#[test]
fn test_grep_short_i_flag() {
    let (_temp, path) = create_test_file("Hello\nhello\nworld");
    let engine = create_test_engine_and_register();
    let result: rhai::Array = engine
        .eval(&format!(r#"grep([grep::i], "hello", "{path}")"#))
        .unwrap();
    assert_eq!(result.len(), 2);
}

/// Given: A file with matching lines
/// When: Using grep with grep::count
/// Then: Only the count is returned
#[test]
fn test_grep_count_flag() {
    let (_temp, path) = create_test_file("a\nb\na\nc\na");
    let engine = create_test_engine_and_register();
    let result: rhai::Array = engine
        .eval(&format!(r#"grep([grep::count], "a", "{path}")"#))
        .unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].clone().into_string().unwrap(), "3");
}

/// Given: A file with matching lines
/// When: Using grep with grep::c (short form)
/// Then: Only the count is returned
#[test]
fn test_grep_short_c_flag() {
    let (_temp, path) = create_test_file("x\ny\nx");
    let engine = create_test_engine_and_register();
    let result: rhai::Array = engine
        .eval(&format!(r#"grep([grep::c], "x", "{path}")"#))
        .unwrap();
    assert_eq!(result[0].clone().into_string().unwrap(), "2");
}

/// Given: A file with matching and non-matching lines
/// When: Using grep with grep::invert
/// Then: Non-matching lines are returned
#[test]
fn test_grep_invert_flag() {
    let (_temp, path) = create_test_file("keep\nremove\nkeep");
    let engine = create_test_engine_and_register();
    let result: rhai::Array = engine
        .eval(&format!(r#"grep([grep::invert], "remove", "{path}")"#))
        .unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].clone().into_string().unwrap(), "keep");
}

/// Given: A file with matching and non-matching lines
/// When: Using grep with grep::v (short form)
/// Then: Non-matching lines are returned
#[test]
fn test_grep_short_v_flag() {
    let (_temp, path) = create_test_file("yes\nno\nyes");
    let engine = create_test_engine_and_register();
    let result: rhai::Array = engine
        .eval(&format!(r#"grep([grep::v], "no", "{path}")"#))
        .unwrap();
    assert_eq!(result.len(), 2);
}

/// Given: A file with matching lines
/// When: Using grep with grep::line_number
/// Then: Lines are prefixed with their line number
#[test]
fn test_grep_line_number_flag() {
    let (_temp, path) = create_test_file("foo\nbar\nfoo");
    let engine = create_test_engine_and_register();
    let result: rhai::Array = engine
        .eval(&format!(r#"grep([grep::line_number], "foo", "{path}")"#))
        .unwrap();
    assert_eq!(result[0].clone().into_string().unwrap(), "1:foo");
    assert_eq!(result[1].clone().into_string().unwrap(), "3:foo");
}

/// Given: A file with matching lines
/// When: Using grep with grep::n (short form)
/// Then: Lines are prefixed with their line number
#[test]
fn test_grep_short_n_flag() {
    let (_temp, path) = create_test_file("a\nb\na");
    let engine = create_test_engine_and_register();
    let result: rhai::Array = engine
        .eval(&format!(r#"grep([grep::n], "a", "{path}")"#))
        .unwrap();
    assert_eq!(result[0].clone().into_string().unwrap(), "1:a");
}

/// Given: A file with many matching lines
/// When: Using grep with grep::max_count(2)
/// Then: At most 2 matches are returned
#[test]
fn test_grep_max_count_flag() {
    let (_temp, path) = create_test_file("a\na\na\na\na");
    let engine = create_test_engine_and_register();
    let result: rhai::Array = engine
        .eval(&format!(r#"grep([grep::max_count(2)], "a", "{path}")"#))
        .unwrap();
    assert_eq!(result.len(), 2);
}

/// Given: A file with many matching lines
/// When: Using grep with grep::m(2) (short form)
/// Then: At most 2 matches are returned
#[test]
fn test_grep_short_m_flag() {
    let (_temp, path) = create_test_file("x\nx\nx\nx");
    let engine = create_test_engine_and_register();
    let result: rhai::Array = engine
        .eval(&format!(r#"grep([grep::m(1)], "x", "{path}")"#))
        .unwrap();
    assert_eq!(result.len(), 1);
}

// ── flag combinations ───────────────────────────────────────────────────────

/// Given: A file with mixed-case content
/// When: Using grep with ignore_case + count
/// Then: The count of case-insensitive matches is returned
#[test]
fn test_grep_ignore_case_and_count() {
    let (_temp, path) = create_test_file("Hello\nhello\nworld");
    let engine = create_test_engine_and_register();
    let result: rhai::Array = engine
        .eval(&format!(
            r#"grep([grep::ignore_case, grep::count], "hello", "{path}")"#
        ))
        .unwrap();
    assert_eq!(result[0].clone().into_string().unwrap(), "2");
}

/// Given: A file with matching lines
/// When: Using grep with line_number + max_count
/// Then: Numbered lines are returned up to the max
#[test]
fn test_grep_line_number_and_max_count() {
    let (_temp, path) = create_test_file("a\nb\na\nb\na");
    let engine = create_test_engine_and_register();
    let result: rhai::Array = engine
        .eval(&format!(
            r#"grep([grep::line_number, grep::max_count(2)], "a", "{path}")"#
        ))
        .unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].clone().into_string().unwrap(), "1:a");
    assert_eq!(result[1].clone().into_string().unwrap(), "3:a");
}

// ── error cases ─────────────────────────────────────────────────────────────

/// Given: A nonexistent file
/// When: Using grep
/// Then: An error is returned
#[test]
fn test_grep_nonexistent_file() {
    let temp = TempDir::new().unwrap();
    let missing = fs::canonicalize(temp.path()).unwrap().join("nope.txt");
    let engine = create_test_engine_and_register();
    let result = engine.eval::<rhai::Array>(&format!(r#"grep("x", "{}")"#, missing.display()));
    assert!(result.is_err());
}

/// Given: A file and a deny-all policy
/// When: Using grep
/// Then: An authorization error is returned
#[test]
fn test_grep_unauthorized() {
    let (_temp, path) = create_test_file("content");
    let engine = deny_all_engine();
    let result = engine.eval::<rhai::Array>(&format!(r#"grep("c", "{path}")"#));
    assert!(result.is_err());
    let err_str = format!("{:?}", result.unwrap_err());
    assert!(
        err_str.contains("unauthorized") || err_str.contains("Permission denied"),
        "Expected authorization error, got: {err_str}",
    );
}
