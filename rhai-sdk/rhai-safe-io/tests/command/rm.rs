use assert_fs::TempDir;
use assert_fs::prelude::*;
use rex_test_utils::rhai::common::{create_test_engine_and_register, deny_all_engine};
use std::fs;
use std::path::Path;

// ── basic usage ─────────────────────────────────────────────────────────────

/// Given: A file that exists
/// When: Using rm(path)
/// Then: The file is deleted
#[test]
fn test_rm_file() {
    let temp = TempDir::new().unwrap();
    temp.child("delete_me.txt").write_str("bye").unwrap();
    let path = fs::canonicalize(temp.path().join("delete_me.txt"))
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let engine = create_test_engine_and_register();
    engine.eval::<()>(&format!(r#"rm("{path}")"#)).unwrap();
    assert!(!Path::new(&path).exists());
}

// ── flags ───────────────────────────────────────────────────────────────────

/// Given: A nonexistent file
/// When: Using rm with rm::force flag
/// Then: An error is still returned because the file cannot be opened
#[test]
fn test_rm_force_nonexistent() {
    let temp = TempDir::new().unwrap();
    let missing = fs::canonicalize(temp.path()).unwrap().join("nope.txt");
    let engine = create_test_engine_and_register();
    let result = engine.eval::<()>(&format!(r#"rm([rm::force], "{}")"#, missing.display()));
    assert!(result.is_err());
}

/// Given: A nonexistent file
/// When: Using rm with rm::f (short form)
/// Then: An error is still returned because the file cannot be opened
#[test]
fn test_rm_short_f_flag() {
    let temp = TempDir::new().unwrap();
    let missing = fs::canonicalize(temp.path()).unwrap().join("nope.txt");
    let engine = create_test_engine_and_register();
    let result = engine.eval::<()>(&format!(r#"rm([rm::f], "{}")"#, missing.display()));
    assert!(result.is_err());
}

/// Given: A directory with files
/// When: Using rm with rm::recursive flag
/// Then: The directory and its contents are removed
#[test]
fn test_rm_recursive_flag() {
    let temp = TempDir::new().unwrap();
    temp.child("subdir/file.txt").write_str("content").unwrap();
    let dir_path = fs::canonicalize(temp.path().join("subdir"))
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let engine = create_test_engine_and_register();
    engine
        .eval::<()>(&format!(r#"rm([rm::recursive], "{dir_path}")"#))
        .unwrap();
    assert!(!Path::new(&dir_path).exists());
}

/// Given: A directory with files
/// When: Using rm with rm::r (short form)
/// Then: The directory and its contents are removed
#[test]
fn test_rm_short_r_flag() {
    let temp = TempDir::new().unwrap();
    temp.child("subdir/file.txt").write_str("content").unwrap();
    let dir_path = fs::canonicalize(temp.path().join("subdir"))
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let engine = create_test_engine_and_register();
    engine
        .eval::<()>(&format!(r#"rm([rm::r], "{dir_path}")"#))
        .unwrap();
    assert!(!Path::new(&dir_path).exists());
}

/// Given: A directory with files
/// When: Using rm with recursive + force flags
/// Then: The directory is removed without error
#[test]
fn test_rm_recursive_and_force() {
    let temp = TempDir::new().unwrap();
    temp.child("subdir/nested/file.txt").write_str("x").unwrap();
    let dir_path = fs::canonicalize(temp.path().join("subdir"))
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let engine = create_test_engine_and_register();
    engine
        .eval::<()>(&format!(r#"rm([rm::recursive, rm::force], "{dir_path}")"#))
        .unwrap();
    assert!(!Path::new(&dir_path).exists());
}

// ── error cases ─────────────────────────────────────────────────────────────

/// Given: A nonexistent file without force flag
/// When: Using rm
/// Then: An error is returned
#[test]
fn test_rm_nonexistent_without_force() {
    let temp = TempDir::new().unwrap();
    let missing = fs::canonicalize(temp.path()).unwrap().join("nope.txt");
    let engine = create_test_engine_and_register();
    let result = engine.eval::<()>(&format!(r#"rm("{}")"#, missing.display()));
    assert!(result.is_err());
}

/// Given: A file and a deny-all policy
/// When: Using rm
/// Then: An authorization error is returned
#[test]
fn test_rm_unauthorized() {
    let temp = TempDir::new().unwrap();
    temp.child("secret.txt").write_str("x").unwrap();
    let path = fs::canonicalize(temp.path().join("secret.txt"))
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let engine = deny_all_engine();
    let result = engine.eval::<()>(&format!(r#"rm("{path}")"#));
    assert!(result.is_err());
    let err_str = format!("{:?}", result.unwrap_err());
    assert!(
        err_str.contains("unauthorized") || err_str.contains("Permission denied"),
        "Expected authorization error, got: {err_str}",
    );
}
