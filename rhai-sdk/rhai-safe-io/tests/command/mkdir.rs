use assert_fs::TempDir;
use rex_test_utils::rhai::common::{create_test_engine_and_register, deny_all_engine};
use std::fs;

// ── basic usage ─────────────────────────────────────────────────────────────

/// Given: A non-existent directory path under an existing parent
/// When: Using mkdir(path)
/// Then: The directory is created
#[test]
fn test_mkdir_basic() {
    let temp = TempDir::new().unwrap();
    let target = fs::canonicalize(temp.path()).unwrap().join("newdir");
    let engine = create_test_engine_and_register();
    engine
        .eval::<()>(&format!(r#"mkdir("{}")"#, target.display()))
        .unwrap();
    assert!(target.exists());
    assert!(target.is_dir());
}

/// Given: A nested directory path where the parent exists
/// When: Using mkdir(path) for the leaf
/// Then: The leaf directory is created
#[test]
fn test_mkdir_nested_one_level() {
    let temp = TempDir::new().unwrap();
    let parent = fs::canonicalize(temp.path()).unwrap().join("parent");
    fs::create_dir(&parent).unwrap();
    let child = parent.join("child");
    let engine = create_test_engine_and_register();
    engine
        .eval::<()>(&format!(r#"mkdir("{}")"#, child.display()))
        .unwrap();
    assert!(child.exists());
}

// ── flags ───────────────────────────────────────────────────────────────────

/// Given: A deeply nested non-existent path
/// When: Using mkdir with mkdir::parents flag
/// Then: All intermediate directories are created
#[test]
fn test_mkdir_parents_flag() {
    let temp = TempDir::new().unwrap();
    let target = fs::canonicalize(temp.path()).unwrap().join("a/b/c");
    let engine = create_test_engine_and_register();
    engine
        .eval::<()>(&format!(
            r#"mkdir([mkdir::parents], "{}")"#,
            target.display()
        ))
        .unwrap();
    assert!(target.exists());
    assert!(target.is_dir());
}

/// Given: A deeply nested non-existent path
/// When: Using mkdir with mkdir::p (short form)
/// Then: All intermediate directories are created
#[test]
fn test_mkdir_short_p_flag() {
    let temp = TempDir::new().unwrap();
    let target = fs::canonicalize(temp.path()).unwrap().join("x/y/z");
    let engine = create_test_engine_and_register();
    engine
        .eval::<()>(&format!(r#"mkdir([mkdir::p], "{}")"#, target.display()))
        .unwrap();
    assert!(target.exists());
}

/// Given: A directory that already exists
/// When: Using mkdir with mkdir::parents
/// Then: No error is raised (idempotent like mkdir -p)
#[test]
fn test_mkdir_parents_already_exists() {
    let temp = TempDir::new().unwrap();
    let target = fs::canonicalize(temp.path()).unwrap().join("existing");
    fs::create_dir(&target).unwrap();
    let engine = create_test_engine_and_register();
    let result = engine.eval::<()>(&format!(
        r#"mkdir([mkdir::parents], "{}")"#,
        target.display()
    ));
    assert!(result.is_ok());
}

// ── error cases ─────────────────────────────────────────────────────────────

/// Given: A path where the parent does not exist
/// When: Using mkdir(path) without -p flag
/// Then: An error is returned
#[test]
fn test_mkdir_missing_parent() {
    let temp = TempDir::new().unwrap();
    let deep = fs::canonicalize(temp.path())
        .unwrap()
        .join("nonexistent_parent")
        .join("child");
    let engine = create_test_engine_and_register();
    let result = engine.eval::<()>(&format!(r#"mkdir("{}")"#, deep.display()));
    assert!(result.is_err());
}

/// Given: A path and a deny-all policy
/// When: Using mkdir
/// Then: An authorization error is returned
#[test]
fn test_mkdir_unauthorized() {
    let temp = TempDir::new().unwrap();
    let target = fs::canonicalize(temp.path()).unwrap().join("forbidden");
    let engine = deny_all_engine();
    let result = engine.eval::<()>(&format!(r#"mkdir("{}")"#, target.display()));
    assert!(result.is_err());
    let err_str = format!("{:?}", result.unwrap_err());
    assert!(
        err_str.contains("unauthorized") || err_str.contains("Permission denied"),
        "Expected authorization error, got: {err_str}",
    );
}
