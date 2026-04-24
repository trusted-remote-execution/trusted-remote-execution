use assert_fs::TempDir;
use rex_test_utils::rhai::common::{create_test_engine_and_register, deny_all_engine};
use std::fs;

// ── basic usage ─────────────────────────────────────────────────────────────

/// Given: A path to a non-existent file
/// When: Using touch(path)
/// Then: The file is created and is empty
#[test]
fn test_touch_creates_file() {
    let temp = TempDir::new().unwrap();
    let target = fs::canonicalize(temp.path()).unwrap().join("new.txt");
    let engine = create_test_engine_and_register();
    engine
        .eval::<()>(&format!(r#"touch("{}")"#, target.display()))
        .unwrap();
    assert!(target.exists());
    assert_eq!(fs::read_to_string(&target).unwrap(), "");
}

/// Given: A file that already exists with content
/// When: Using touch(path)
/// Then: The file still exists (no error)
#[test]
fn test_touch_existing_file() {
    let temp = TempDir::new().unwrap();
    let target = fs::canonicalize(temp.path()).unwrap().join("existing.txt");
    fs::write(&target, "content").unwrap();
    let engine = create_test_engine_and_register();
    let result = engine.eval::<()>(&format!(r#"touch("{}")"#, target.display()));
    assert!(result.is_ok());
    assert!(target.exists());
}

// ── error cases ─────────────────────────────────────────────────────────────

/// Given: A path in a nonexistent directory
/// When: Using touch
/// Then: An error is returned
#[test]
fn test_touch_missing_parent_dir() {
    let temp = TempDir::new().unwrap();
    let target = fs::canonicalize(temp.path())
        .unwrap()
        .join("nonexistent")
        .join("file.txt");
    let engine = create_test_engine_and_register();
    let result = engine.eval::<()>(&format!(r#"touch("{}")"#, target.display()));
    assert!(result.is_err());
}

/// Given: A path and a deny-all policy
/// When: Using touch
/// Then: An authorization error is returned
#[test]
fn test_touch_unauthorized() {
    let temp = TempDir::new().unwrap();
    let target = fs::canonicalize(temp.path()).unwrap().join("forbidden.txt");
    let engine = deny_all_engine();
    let result = engine.eval::<()>(&format!(r#"touch("{}")"#, target.display()));
    assert!(result.is_err());
    let err_str = format!("{:?}", result.unwrap_err());
    assert!(
        err_str.contains("unauthorized") || err_str.contains("Permission denied"),
        "Expected authorization error, got: {err_str}",
    );
}
