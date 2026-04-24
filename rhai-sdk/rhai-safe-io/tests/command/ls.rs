use assert_fs::TempDir;
use assert_fs::prelude::*;
use rex_test_utils::rhai::common::{create_test_engine_and_register, deny_all_engine};
use rhai::Map;
use std::fs;

fn setup_dir_with_hidden() -> (TempDir, String) {
    let temp = TempDir::new().unwrap();
    temp.child("file1.txt").write_str("content1").unwrap();
    temp.child("file2.txt").write_str("content2").unwrap();
    temp.child(".hidden").write_str("secret").unwrap();
    let path = fs::canonicalize(temp.path())
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    (temp, path)
}

// ── basic usage ─────────────────────────────────────────────────────────────

/// Given: A directory with files
/// When: Using ls() to list the directory
/// Then: A map of entries is returned
#[test]
fn test_ls_lists_directory_contents() {
    let (_temp, path) = setup_dir_with_hidden();
    let engine = create_test_engine_and_register();
    let result: Map = engine.eval(&format!(r#"ls("{path}")"#)).unwrap();
    assert!(result.contains_key("file1.txt"));
    assert!(result.contains_key("file2.txt"));
    // hidden files excluded by default
    assert!(!result.contains_key(".hidden"));
}

/// Given: An empty directory
/// When: Using ls() to list the directory
/// Then: An empty map is returned
#[test]
fn test_ls_empty_directory() {
    let temp = TempDir::new().unwrap();
    temp.child("empty_dir").create_dir_all().unwrap();
    let empty_dir = fs::canonicalize(temp.path().join("empty_dir")).unwrap();
    let engine = create_test_engine_and_register();
    let result: Map = engine
        .eval(&format!(r#"ls("{}")"#, empty_dir.display()))
        .unwrap();
    assert!(result.is_empty());
}

/// Given: A directory with subdirectories
/// When: Using ls() to list the directory
/// Then: Subdirectories are included in the result
#[test]
fn test_ls_includes_subdirectories() {
    let temp = TempDir::new().unwrap();
    temp.child("subdir").create_dir_all().unwrap();
    temp.child("file.txt").write_str("content").unwrap();
    let test_dir = fs::canonicalize(temp.path()).unwrap();
    let engine = create_test_engine_and_register();
    let result: Map = engine
        .eval(&format!(r#"ls("{}")"#, test_dir.display()))
        .unwrap();
    assert!(result.contains_key("subdir"));
    assert!(result.contains_key("file.txt"));
}

// ── flags ───────────────────────────────────────────────────────────────────

/// Given: A directory with hidden files
/// When: Using ls() with ls::all flag
/// Then: Hidden entries are included
#[test]
fn test_ls_with_all_flag() {
    let (_temp, path) = setup_dir_with_hidden();
    let engine = create_test_engine_and_register();
    let result: Map = engine.eval(&format!(r#"ls([ls::all], "{path}")"#)).unwrap();
    assert!(result.contains_key("file1.txt"));
    assert!(result.contains_key(".hidden"));
}

/// Given: A directory with hidden files
/// When: Using ls() with ls::a short form flag
/// Then: Hidden entries are included (same as ls::all)
#[test]
fn test_ls_with_short_a_flag() {
    let (_temp, path) = setup_dir_with_hidden();
    let engine = create_test_engine_and_register();
    let result: Map = engine.eval(&format!(r#"ls([ls::a], "{path}")"#)).unwrap();
    assert!(result.contains_key(".hidden"));
}

/// Given: A directory with files
/// When: Using ls() with ls::long flag
/// Then: Results are returned (long format reserved for future use)
#[test]
fn test_ls_with_long_flag() {
    let (_temp, path) = setup_dir_with_hidden();
    let engine = create_test_engine_and_register();
    let result: Map = engine
        .eval(&format!(r#"ls([ls::long], "{path}")"#))
        .unwrap();
    assert!(result.contains_key("file1.txt"));
}

/// Given: A directory with files
/// When: Using ls() with ls::l short form flag
/// Then: Results are returned
#[test]
fn test_ls_with_short_l_flag() {
    let (_temp, path) = setup_dir_with_hidden();
    let engine = create_test_engine_and_register();
    let result: Map = engine.eval(&format!(r#"ls([ls::l], "{path}")"#)).unwrap();
    assert!(result.contains_key("file1.txt"));
}

/// Given: A directory with hidden files
/// When: Using ls() with combined all + long flags
/// Then: Hidden entries are included
#[test]
fn test_ls_with_combined_all_long_flags() {
    let (_temp, path) = setup_dir_with_hidden();
    let engine = create_test_engine_and_register();
    let result: Map = engine
        .eval(&format!(r#"ls([ls::all, ls::long], "{path}")"#))
        .unwrap();
    assert!(result.contains_key(".hidden"));
    assert!(result.contains_key("file1.txt"));
}

// ── error cases ─────────────────────────────────────────────────────────────

/// Given: A directory that does not exist
/// When: Using ls() to list the directory
/// Then: An error is returned
#[test]
fn test_ls_nonexistent_directory_returns_error() {
    let temp = TempDir::new().unwrap();
    let nonexistent = fs::canonicalize(temp.path()).unwrap().join("nonexistent");
    let engine = create_test_engine_and_register();
    let result = engine.eval::<Map>(&format!(r#"ls("{}")"#, nonexistent.display()));
    assert!(result.is_err());
}

/// Given: A directory with files and a deny-all authorization policy
/// When: Using ls() to list the directory
/// Then: An authorization error is returned
#[test]
fn test_ls_unauthorized_returns_error() {
    let (_temp, path) = setup_dir_with_hidden();
    let engine = deny_all_engine();
    let result = engine.eval::<Map>(&format!(r#"ls("{path}")"#));
    assert!(result.is_err());
    let err_str = format!("{:?}", result.unwrap_err());
    assert!(
        err_str.contains("unauthorized") || err_str.contains("Permission denied"),
        "Expected authorization error, got: {err_str}",
    );
}
