use assert_fs::TempDir;
use assert_fs::prelude::*;
use rex_test_utils::rhai::common::{create_test_engine_and_register, deny_all_engine};
use std::fs;

// ── basic usage ─────────────────────────────────────────────────────────────

/// Given: A directory with .txt and .log files
/// When: Using find_files("*.txt", path)
/// Then: Only .txt files are returned
#[test]
fn test_glob_matches_pattern() {
    let temp = TempDir::new().unwrap();
    temp.child("a.txt").write_str("a").unwrap();
    temp.child("b.txt").write_str("b").unwrap();
    temp.child("c.log").write_str("c").unwrap();
    let path = fs::canonicalize(temp.path())
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let engine = create_test_engine_and_register();
    let result: rhai::Array = engine
        .eval(&format!(r#"find_files("*.txt", "{path}")"#))
        .unwrap();
    assert_eq!(result.len(), 2);
    let names: Vec<String> = result
        .into_iter()
        .map(|v| v.into_string().unwrap())
        .collect();
    assert!(names.iter().all(|n| n.ends_with(".txt")));
}

/// Given: A directory with no matching files
/// When: Using find_files with a non-matching pattern
/// Then: An empty array is returned
#[test]
fn test_glob_no_match() {
    let temp = TempDir::new().unwrap();
    temp.child("file.txt").write_str("x").unwrap();
    let path = fs::canonicalize(temp.path())
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let engine = create_test_engine_and_register();
    let result: rhai::Array = engine
        .eval(&format!(r#"find_files("*.csv", "{path}")"#))
        .unwrap();
    assert!(result.is_empty());
}

// ── flags ───────────────────────────────────────────────────────────────────

/// Given: A directory with nested .txt files
/// When: Using find_files with glob::recursive
/// Then: Files in subdirectories are also found
#[test]
fn test_glob_recursive_flag() {
    let temp = TempDir::new().unwrap();
    temp.child("top.txt").write_str("a").unwrap();
    temp.child("sub/nested.txt").write_str("b").unwrap();
    let path = fs::canonicalize(temp.path())
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let engine = create_test_engine_and_register();
    let result: rhai::Array = engine
        .eval(&format!(
            r#"find_files([glob::recursive], "*.txt", "{path}")"#
        ))
        .unwrap();
    assert!(result.len() >= 2);
}

/// Given: A directory with nested .txt files
/// When: Using find_files with glob::r (short form)
/// Then: Files in subdirectories are also found
#[test]
fn test_glob_short_r_flag() {
    let temp = TempDir::new().unwrap();
    temp.child("top.txt").write_str("a").unwrap();
    temp.child("sub/nested.txt").write_str("b").unwrap();
    let path = fs::canonicalize(temp.path())
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let engine = create_test_engine_and_register();
    let result: rhai::Array = engine
        .eval(&format!(r#"find_files([glob::r], "*.txt", "{path}")"#))
        .unwrap();
    assert!(result.len() >= 2);
}

/// Given: A directory with nested files but no recursive flag
/// When: Using find_files without recursive
/// Then: Only top-level matches are returned
#[test]
fn test_glob_non_recursive_skips_subdirs() {
    let temp = TempDir::new().unwrap();
    temp.child("top.txt").write_str("a").unwrap();
    temp.child("sub/nested.txt").write_str("b").unwrap();
    let path = fs::canonicalize(temp.path())
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let engine = create_test_engine_and_register();
    let result: rhai::Array = engine
        .eval(&format!(r#"find_files("*.txt", "{path}")"#))
        .unwrap();
    assert_eq!(result.len(), 1);
}

// ── error cases ─────────────────────────────────────────────────────────────

/// Given: A nonexistent directory
/// When: Using find_files
/// Then: An error is returned
#[test]
fn test_glob_nonexistent_dir() {
    let temp = TempDir::new().unwrap();
    let missing = fs::canonicalize(temp.path()).unwrap().join("nope");
    let engine = create_test_engine_and_register();
    let result =
        engine.eval::<rhai::Array>(&format!(r#"find_files("*", "{}")"#, missing.display()));
    assert!(result.is_err());
}

/// Given: A directory and a deny-all policy
/// When: Using find_files
/// Then: An authorization error is returned
#[test]
fn test_glob_unauthorized() {
    let temp = TempDir::new().unwrap();
    temp.child("file.txt").write_str("x").unwrap();
    let path = fs::canonicalize(temp.path())
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let engine = deny_all_engine();
    let result = engine.eval::<rhai::Array>(&format!(r#"find_files("*", "{path}")"#));
    assert!(result.is_err());
    let err_str = format!("{:?}", result.unwrap_err());
    assert!(
        err_str.contains("unauthorized") || err_str.contains("Permission denied"),
        "Expected authorization error, got: {err_str}",
    );
}
