use assert_fs::TempDir;
use assert_fs::prelude::*;
use rex_test_utils::rhai::common::{create_test_engine_and_register, deny_all_engine};
use std::fs;

fn create_numbered_file(n: usize) -> (TempDir, String) {
    let temp = TempDir::new().unwrap();
    let content: String = (1..=n)
        .map(|i| format!("line{i}"))
        .collect::<Vec<_>>()
        .join("\n");
    temp.child("test.txt").write_str(&content).unwrap();
    let path = fs::canonicalize(temp.path().join("test.txt"))
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    (temp, path)
}

// ── basic usage ─────────────────────────────────────────────────────────────

/// Given: A file with 15 lines
/// When: Using tail() with default options
/// Then: The last 10 lines are returned
#[test]
fn test_tail_default_last_10() {
    let (_temp, path) = create_numbered_file(15);
    let engine = create_test_engine_and_register();
    let result: rhai::Array = engine.eval(&format!(r#"tail("{path}")"#)).unwrap();
    assert_eq!(result.len(), 10);
    assert_eq!(result[0].clone().into_string().unwrap(), "line6");
    assert_eq!(result[9].clone().into_string().unwrap(), "line15");
}

/// Given: A file with fewer than 10 lines
/// When: Using tail() with default options
/// Then: All lines are returned
#[test]
fn test_tail_fewer_than_default() {
    let (_temp, path) = create_numbered_file(3);
    let engine = create_test_engine_and_register();
    let result: rhai::Array = engine.eval(&format!(r#"tail("{path}")"#)).unwrap();
    assert_eq!(result.len(), 3);
}

// ── flags ───────────────────────────────────────────────────────────────────

/// Given: A file with 15 lines
/// When: Using tail with tail::n(-5)
/// Then: The last 5 lines are returned
#[test]
fn test_tail_n_negative() {
    let (_temp, path) = create_numbered_file(15);
    let engine = create_test_engine_and_register();
    let result: rhai::Array = engine
        .eval(&format!(r#"tail([tail::n(-5)], "{path}")"#))
        .unwrap();
    assert_eq!(result.len(), 5);
    assert_eq!(result[0].clone().into_string().unwrap(), "line11");
    assert_eq!(result[4].clone().into_string().unwrap(), "line15");
}

/// Given: A file with 10 lines
/// When: Using tail with tail::from(5)
/// Then: Lines from line 5 onward are returned
#[test]
fn test_tail_from() {
    let (_temp, path) = create_numbered_file(10);
    let engine = create_test_engine_and_register();
    let result: rhai::Array = engine
        .eval(&format!(r#"tail([tail::from(5)], "{path}")"#))
        .unwrap();
    assert_eq!(result[0].clone().into_string().unwrap(), "line5");
}

/// Given: A file with 10 lines
/// When: Using tail with tail::range(3, 6)
/// Then: Lines 3 through 6 are returned
#[test]
fn test_tail_range() {
    let (_temp, path) = create_numbered_file(10);
    let engine = create_test_engine_and_register();
    let result: rhai::Array = engine
        .eval(&format!(r#"tail([tail::range(3, 6)], "{path}")"#))
        .unwrap();
    assert_eq!(result.len(), 4);
    assert_eq!(result[0].clone().into_string().unwrap(), "line3");
    assert_eq!(result[3].clone().into_string().unwrap(), "line6");
}

// ── error cases ─────────────────────────────────────────────────────────────

/// Given: A nonexistent file
/// When: Using tail
/// Then: An error is returned
#[test]
fn test_tail_nonexistent_file() {
    let temp = TempDir::new().unwrap();
    let missing = fs::canonicalize(temp.path()).unwrap().join("nope.txt");
    let engine = create_test_engine_and_register();
    let result = engine.eval::<rhai::Array>(&format!(r#"tail("{}")"#, missing.display()));
    assert!(result.is_err());
}

/// Given: A file and a deny-all policy
/// When: Using tail
/// Then: An authorization error is returned
#[test]
fn test_tail_unauthorized() {
    let (_temp, path) = create_numbered_file(5);
    let engine = deny_all_engine();
    let result = engine.eval::<rhai::Array>(&format!(r#"tail("{path}")"#));
    assert!(result.is_err());
    let err_str = format!("{:?}", result.unwrap_err());
    assert!(
        err_str.contains("unauthorized") || err_str.contains("Permission denied"),
        "Expected authorization error, got: {err_str}",
    );
}
