use assert_fs::TempDir;
use rex_test_utils::rhai::common::{create_test_engine_and_register, deny_all_engine};
use std::fs;

// ── write with replace flag ─────────────────────────────────────────────────

/// Given: A path to a non-existent file
/// When: Using write([write::replace], path, content)
/// Then: The file is created with that content
#[test]
fn test_write_replace_creates_file() {
    let temp = TempDir::new().unwrap();
    let target = fs::canonicalize(temp.path()).unwrap().join("output.txt");
    let engine = create_test_engine_and_register();
    engine
        .eval::<()>(&format!(
            r#"write([write::replace], "{}", "hello world\n")"#,
            target.display()
        ))
        .unwrap();
    assert_eq!(fs::read_to_string(&target).unwrap(), "hello world\n");
}

/// Given: A file with existing content
/// When: Using write([write::replace], ...) with new content
/// Then: The file content is fully replaced
#[test]
fn test_write_replace_overwrites_existing() {
    let temp = TempDir::new().unwrap();
    let target = fs::canonicalize(temp.path()).unwrap().join("output.txt");
    let target_str = target.to_str().unwrap();
    let engine = create_test_engine_and_register();
    engine
        .eval::<()>(&format!(
            r#"write([write::replace], "{target_str}", "first\n")"#
        ))
        .unwrap();
    engine
        .eval::<()>(&format!(
            r#"write([write::replace], "{target_str}", "second\n")"#
        ))
        .unwrap();
    assert_eq!(fs::read_to_string(&target).unwrap(), "second\n");
}

/// Given: A file
/// When: Using write([write::replace], ...) with empty content
/// Then: The file is truncated to empty
#[test]
fn test_write_replace_with_empty_content() {
    let temp = TempDir::new().unwrap();
    let target = fs::canonicalize(temp.path()).unwrap().join("output.txt");
    let target_str = target.to_str().unwrap();
    let engine = create_test_engine_and_register();
    engine
        .eval::<()>(&format!(
            r#"write([write::replace], "{target_str}", "data")"#
        ))
        .unwrap();
    engine
        .eval::<()>(&format!(r#"write([write::replace], "{target_str}", "")"#))
        .unwrap();
    assert_eq!(fs::read_to_string(&target).unwrap(), "");
}

/// Given: A path in a nonexistent directory
/// When: Using write([write::replace], ...)
/// Then: An error is returned
#[test]
fn test_write_replace_missing_parent_dir() {
    let temp = TempDir::new().unwrap();
    let target = fs::canonicalize(temp.path())
        .unwrap()
        .join("nonexistent")
        .join("file.txt");
    let engine = create_test_engine_and_register();
    let result = engine.eval::<()>(&format!(
        r#"write([write::replace], "{}", "x")"#,
        target.display()
    ));
    assert!(result.is_err());
}

/// Given: A path and a deny-all policy
/// When: Using write([write::replace], ...)
/// Then: An authorization error is returned
#[test]
fn test_write_replace_unauthorized() {
    let temp = TempDir::new().unwrap();
    let target = fs::canonicalize(temp.path()).unwrap().join("forbidden.txt");
    let engine = deny_all_engine();
    let result = engine.eval::<()>(&format!(
        r#"write([write::replace], "{}", "x")"#,
        target.display()
    ));
    assert!(result.is_err());
    let err_str = format!("{:?}", result.unwrap_err());
    assert!(
        err_str.contains("unauthorized") || err_str.contains("Permission denied"),
        "Expected authorization error, got: {err_str}",
    );
}

// ── write with default append ───────────────────────────────────────────────

/// Given: A path to a non-existent file
/// When: Using write(path, content) (default append)
/// Then: The file is created with that content
#[test]
fn test_write_append_creates_file() {
    let temp = TempDir::new().unwrap();
    let target = fs::canonicalize(temp.path()).unwrap().join("output.txt");
    let engine = create_test_engine_and_register();
    engine
        .eval::<()>(&format!(r#"write("{}", "line one\n")"#, target.display()))
        .unwrap();
    assert_eq!(fs::read_to_string(&target).unwrap(), "line one\n");
}

/// Given: A file with existing content
/// When: Using write(path, content) (default append)
/// Then: The new content is added after the existing content
#[test]
fn test_write_append_adds_to_existing() {
    let temp = TempDir::new().unwrap();
    let target = fs::canonicalize(temp.path()).unwrap().join("output.txt");
    let target_str = target.to_str().unwrap();
    let engine = create_test_engine_and_register();
    engine
        .eval::<()>(&format!(
            r#"write([write::replace], "{target_str}", "line one\n")"#
        ))
        .unwrap();
    engine
        .eval::<()>(&format!(r#"write("{target_str}", "line two\n")"#))
        .unwrap();
    assert_eq!(fs::read_to_string(&target).unwrap(), "line one\nline two\n");
}

/// Given: A file with existing content
/// When: Using write(path, content) multiple times
/// Then: All appended content accumulates
#[test]
fn test_write_append_multiple_times() {
    let temp = TempDir::new().unwrap();
    let target = fs::canonicalize(temp.path()).unwrap().join("output.txt");
    let target_str = target.to_str().unwrap();
    let engine = create_test_engine_and_register();
    engine
        .eval::<()>(&format!(r#"write("{target_str}", "a")"#))
        .unwrap();
    engine
        .eval::<()>(&format!(r#"write("{target_str}", "b")"#))
        .unwrap();
    engine
        .eval::<()>(&format!(r#"write("{target_str}", "c")"#))
        .unwrap();
    assert_eq!(fs::read_to_string(&target).unwrap(), "abc");
}

/// Given: A path in a nonexistent directory
/// When: Using write(path, content)
/// Then: An error is returned
#[test]
fn test_write_append_missing_parent_dir() {
    let temp = TempDir::new().unwrap();
    let target = fs::canonicalize(temp.path())
        .unwrap()
        .join("nonexistent")
        .join("file.txt");
    let engine = create_test_engine_and_register();
    let result = engine.eval::<()>(&format!(r#"write("{}", "x")"#, target.display()));
    assert!(result.is_err());
}

/// Given: A path and a deny-all policy
/// When: Using write(path, content)
/// Then: An authorization error is returned
#[test]
fn test_write_append_unauthorized() {
    let temp = TempDir::new().unwrap();
    let target = fs::canonicalize(temp.path()).unwrap().join("forbidden.txt");
    let engine = deny_all_engine();
    let result = engine.eval::<()>(&format!(r#"write("{}", "x")"#, target.display()));
    assert!(result.is_err());
    let err_str = format!("{:?}", result.unwrap_err());
    assert!(
        err_str.contains("unauthorized") || err_str.contains("Permission denied"),
        "Expected authorization error, got: {err_str}",
    );
}
