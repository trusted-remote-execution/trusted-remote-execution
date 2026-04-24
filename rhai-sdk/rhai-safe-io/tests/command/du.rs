use assert_fs::TempDir;
use assert_fs::prelude::*;
use rex_test_utils::rhai::common::{create_test_engine_and_register, deny_all_engine};
use rhai::Map;
use std::fs;

// ── basic usage ─────────────────────────────────────────────────────────────

/// Given: A directory with files
/// When: Using du(path)
/// Then: A map with entries, total_size_bytes, and total_inode_count is returned
#[test]
fn test_du_basic() {
    let temp = TempDir::new().unwrap();
    temp.child("file1.txt").write_str("hello").unwrap();
    temp.child("file2.txt").write_str("world").unwrap();
    let path = fs::canonicalize(temp.path())
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let engine = create_test_engine_and_register();
    let result: Map = engine.eval(&format!(r#"du("{path}")"#)).unwrap();
    assert!(result.contains_key("entries"));
    assert!(result.contains_key("total_size_bytes"));
    assert!(result.contains_key("total_inode_count"));
    let total = result["total_size_bytes"].clone().cast::<i64>();
    assert!(total > 0);
}

/// Given: An empty directory
/// When: Using du(path)
/// Then: The result has zero or minimal size
#[test]
fn test_du_empty_dir() {
    let temp = TempDir::new().unwrap();
    let path = fs::canonicalize(temp.path())
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let engine = create_test_engine_and_register();
    let result: Map = engine.eval(&format!(r#"du("{path}")"#)).unwrap();
    assert!(result.contains_key("total_size_bytes"));
}

/// Given: A Rhai script that uses du and accesses entries
/// When: Running the script
/// Then: The entries array is accessible
#[test]
fn test_du_script_access_entries() {
    let temp = TempDir::new().unwrap();
    temp.child("data.txt")
        .write_str("some content here")
        .unwrap();
    let path = fs::canonicalize(temp.path())
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let engine = create_test_engine_and_register();
    let script = format!(
        r#"
        let usage = du("{path}");
        usage.total_size_bytes
        "#,
    );
    let result: i64 = engine.eval(&script).unwrap();
    assert!(result > 0);
}

// ── flag usage ──────────────────────────────────────────────────────────────

/// Given: A directory with files and the summarize flag
/// When: Using du([du::summarize], path)
/// Then: The result is returned successfully
#[test]
fn test_du_summarize_flag() {
    let temp = TempDir::new().unwrap();
    temp.child("file1.txt").write_str("hello").unwrap();
    temp.child("file2.txt").write_str("world").unwrap();
    let path = fs::canonicalize(temp.path())
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let engine = create_test_engine_and_register();
    let result: Map = engine
        .eval(&format!(r#"du([du::summarize], "{path}")"#))
        .unwrap();
    assert!(result.contains_key("total_size_bytes"));
}

/// Given: A directory with files and the short s flag
/// When: Using du([du::s], path)
/// Then: The result is returned successfully
#[test]
fn test_du_short_s_flag() {
    let temp = TempDir::new().unwrap();
    temp.child("file.txt").write_str("data").unwrap();
    let path = fs::canonicalize(temp.path())
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let engine = create_test_engine_and_register();
    let result: Map = engine.eval(&format!(r#"du([du::s], "{path}")"#)).unwrap();
    assert!(result.contains_key("total_size_bytes"));
}

/// Given: A directory with nested subdirectories and max_depth flag
/// When: Using du([du::max_depth(1)], path)
/// Then: The result is returned successfully
#[test]
fn test_du_max_depth_flag() {
    let temp = TempDir::new().unwrap();
    temp.child("sub/file.txt").write_str("nested").unwrap();
    let path = fs::canonicalize(temp.path())
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let engine = create_test_engine_and_register();
    let result: Map = engine
        .eval(&format!(r#"du([du::max_depth(1)], "{path}")"#))
        .unwrap();
    assert!(result.contains_key("total_size_bytes"));
}

/// Given: A directory with files and the all_files flag
/// When: Using du([du::all_files], path)
/// Then: The result includes file entries
#[test]
fn test_du_all_files_flag() {
    let temp = TempDir::new().unwrap();
    temp.child("file1.txt").write_str("hello").unwrap();
    let path = fs::canonicalize(temp.path())
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let engine = create_test_engine_and_register();
    let result: Map = engine
        .eval(&format!(r#"du([du::all_files], "{path}")"#))
        .unwrap();
    assert!(result.contains_key("entries"));
}

// ── error cases ─────────────────────────────────────────────────────────────

/// Given: A nonexistent directory
/// When: Using du
/// Then: An error is returned
#[test]
fn test_du_nonexistent_dir() {
    let temp = TempDir::new().unwrap();
    let missing = fs::canonicalize(temp.path()).unwrap().join("nope");
    let engine = create_test_engine_and_register();
    let result = engine.eval::<Map>(&format!(r#"du("{}")"#, missing.display()));
    assert!(result.is_err());
}

/// Given: A directory and a deny-all policy
/// When: Using du
/// Then: An authorization error is returned
#[test]
fn test_du_unauthorized() {
    let temp = TempDir::new().unwrap();
    temp.child("file.txt").write_str("x").unwrap();
    let path = fs::canonicalize(temp.path())
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let engine = deny_all_engine();
    let result = engine.eval::<Map>(&format!(r#"du("{path}")"#));
    assert!(result.is_err());
    let err_str = format!("{:?}", result.unwrap_err());
    assert!(
        err_str.contains("unauthorized") || err_str.contains("Permission denied"),
        "Expected authorization error, got: {err_str}",
    );
}
