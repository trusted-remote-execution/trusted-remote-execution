use assert_fs::TempDir;
use assert_fs::prelude::*;
use rex_test_utils::rhai::common::{create_test_engine_and_register, deny_all_engine};
use std::fs;
use std::path::Path;

// ── basic usage ─────────────────────────────────────────────────────────────

/// Given: A source file
/// When: Using mv(src, dst)
/// Then: The file exists at the new location and not the old
#[test]
fn test_mv_basic() {
    let temp = TempDir::new().unwrap();
    let canon_temp = fs::canonicalize(temp.path()).unwrap();
    temp.child("old.txt").write_str("content").unwrap();
    let src = canon_temp.join("old.txt").to_str().unwrap().to_string();
    let dst_path = canon_temp.join("new.txt");
    let dst = dst_path.to_str().unwrap().to_string();
    let engine = create_test_engine_and_register();
    engine
        .eval::<()>(&format!(r#"mv("{src}", "{dst}")"#))
        .unwrap();
    assert!(dst_path.exists());
    assert!(!Path::new(&src).exists());
}

/// Given: A source file with content
/// When: Using mv to rename it
/// Then: The content is preserved at the new location
#[test]
fn test_mv_preserves_content() {
    let temp = TempDir::new().unwrap();
    let canon_temp = fs::canonicalize(temp.path()).unwrap();
    temp.child("original.txt")
        .write_str("important data")
        .unwrap();
    let src = canon_temp
        .join("original.txt")
        .to_str()
        .unwrap()
        .to_string();
    let dst_path = canon_temp.join("renamed.txt");
    let dst = dst_path.to_str().unwrap().to_string();
    let engine = create_test_engine_and_register();
    engine
        .eval::<()>(&format!(r#"mv("{src}", "{dst}")"#))
        .unwrap();
    assert_eq!(fs::read_to_string(&dst_path).unwrap(), "important data");
}

// ── error cases ─────────────────────────────────────────────────────────────

/// Given: A nonexistent source file
/// When: Using mv
/// Then: An error is returned
#[test]
fn test_mv_nonexistent_source() {
    let temp = TempDir::new().unwrap();
    let missing = fs::canonicalize(temp.path()).unwrap().join("nope.txt");
    let dst = temp.path().join("dst.txt");
    let engine = create_test_engine_and_register();
    let result = engine.eval::<()>(&format!(
        r#"mv("{}", "{}")"#,
        missing.display(),
        dst.display()
    ));
    assert!(result.is_err());
}

/// Given: A source file and a deny-all policy
/// When: Using mv
/// Then: An authorization error is returned
#[test]
fn test_mv_unauthorized() {
    let temp = TempDir::new().unwrap();
    temp.child("src.txt").write_str("x").unwrap();
    let src = fs::canonicalize(temp.path().join("src.txt"))
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let dst = temp.path().join("dst.txt");
    let engine = deny_all_engine();
    let result = engine.eval::<()>(&format!(r#"mv("{src}", "{}")"#, dst.display()));
    assert!(result.is_err());
    let err_str = format!("{:?}", result.unwrap_err());
    assert!(
        err_str.contains("unauthorized") || err_str.contains("Permission denied"),
        "Expected authorization error, got: {err_str}",
    );
}
