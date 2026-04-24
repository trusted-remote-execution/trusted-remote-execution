use assert_fs::TempDir;
use assert_fs::prelude::*;
use rex_test_utils::rhai::common::{create_test_engine_and_register, deny_all_engine};
use std::fs;

// ── basic usage ─────────────────────────────────────────────────────────────

/// Given: A source file with content
/// When: Using cp(src, dst)
/// Then: The destination file has the same content
#[test]
fn test_cp_basic() {
    let temp = TempDir::new().unwrap();
    temp.child("src.txt").write_str("hello").unwrap();
    temp.child("dst.txt").write_str("").unwrap();
    let src = fs::canonicalize(temp.path().join("src.txt"))
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let dst = fs::canonicalize(temp.path().join("dst.txt"))
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let engine = create_test_engine_and_register();
    engine
        .eval::<()>(&format!(r#"cp("{src}", "{dst}")"#))
        .unwrap();
    assert_eq!(fs::read_to_string(&dst).unwrap(), "hello");
}

// ── flags ───────────────────────────────────────────────────────────────────

/// Given: A source file and an existing destination
/// When: Using cp with cp::force flag
/// Then: The destination is overwritten
#[test]
fn test_cp_force_flag() {
    let temp = TempDir::new().unwrap();
    temp.child("src.txt").write_str("new").unwrap();
    temp.child("dst.txt").write_str("old").unwrap();
    let src = fs::canonicalize(temp.path().join("src.txt"))
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let dst = fs::canonicalize(temp.path().join("dst.txt"))
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let engine = create_test_engine_and_register();
    engine
        .eval::<()>(&format!(r#"cp([cp::force], "{src}", "{dst}")"#))
        .unwrap();
    assert_eq!(fs::read_to_string(&dst).unwrap(), "new");
}

/// Given: A source file and an existing destination
/// When: Using cp with cp::f (short form)
/// Then: The destination is overwritten
#[test]
fn test_cp_short_f_flag() {
    let temp = TempDir::new().unwrap();
    temp.child("src.txt").write_str("new").unwrap();
    temp.child("dst.txt").write_str("old").unwrap();
    let src = fs::canonicalize(temp.path().join("src.txt"))
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let dst = fs::canonicalize(temp.path().join("dst.txt"))
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let engine = create_test_engine_and_register();
    engine
        .eval::<()>(&format!(r#"cp([cp::f], "{src}", "{dst}")"#))
        .unwrap();
    assert_eq!(fs::read_to_string(&dst).unwrap(), "new");
}

/// Given: A source file
/// When: Using cp with cp::preserve flag
/// Then: The copy succeeds (metadata preservation is best-effort)
#[test]
fn test_cp_preserve_flag() {
    let temp = TempDir::new().unwrap();
    temp.child("src.txt").write_str("data").unwrap();
    temp.child("dst.txt").write_str("").unwrap();
    let src = fs::canonicalize(temp.path().join("src.txt"))
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let dst = fs::canonicalize(temp.path().join("dst.txt"))
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let engine = create_test_engine_and_register();
    engine
        .eval::<()>(&format!(r#"cp([cp::preserve], "{src}", "{dst}")"#))
        .unwrap();
    assert_eq!(fs::read_to_string(&dst).unwrap(), "data");
}

/// Given: A source file
/// When: Using cp with cp::p (short form)
/// Then: The copy succeeds
#[test]
fn test_cp_short_p_flag() {
    let temp = TempDir::new().unwrap();
    temp.child("src.txt").write_str("data").unwrap();
    temp.child("dst.txt").write_str("").unwrap();
    let src = fs::canonicalize(temp.path().join("src.txt"))
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let dst = fs::canonicalize(temp.path().join("dst.txt"))
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let engine = create_test_engine_and_register();
    engine
        .eval::<()>(&format!(r#"cp([cp::p], "{src}", "{dst}")"#))
        .unwrap();
    assert_eq!(fs::read_to_string(&dst).unwrap(), "data");
}

/// Given: A source file
/// When: Using cp with force + preserve flags combined
/// Then: The copy succeeds with both options
#[test]
fn test_cp_force_and_preserve() {
    let temp = TempDir::new().unwrap();
    temp.child("src.txt").write_str("combined").unwrap();
    temp.child("dst.txt").write_str("old").unwrap();
    let src = fs::canonicalize(temp.path().join("src.txt"))
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let dst = fs::canonicalize(temp.path().join("dst.txt"))
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let engine = create_test_engine_and_register();
    engine
        .eval::<()>(&format!(
            r#"cp([cp::force, cp::preserve], "{src}", "{dst}")"#
        ))
        .unwrap();
    assert_eq!(fs::read_to_string(&dst).unwrap(), "combined");
}

// ── error cases ─────────────────────────────────────────────────────────────

/// Given: A nonexistent source file
/// When: Using cp
/// Then: An error is returned
#[test]
fn test_cp_nonexistent_source() {
    let temp = TempDir::new().unwrap();
    temp.child("dst.txt").write_str("").unwrap();
    let missing = fs::canonicalize(temp.path()).unwrap().join("nope.txt");
    let dst = fs::canonicalize(temp.path().join("dst.txt"))
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let engine = create_test_engine_and_register();
    let result = engine.eval::<()>(&format!(r#"cp("{}", "{dst}")"#, missing.display()));
    assert!(result.is_err());
}

/// Given: A source file and a deny-all policy
/// When: Using cp
/// Then: An authorization error is returned
#[test]
fn test_cp_unauthorized() {
    let temp = TempDir::new().unwrap();
    temp.child("src.txt").write_str("x").unwrap();
    temp.child("dst.txt").write_str("").unwrap();
    let src = fs::canonicalize(temp.path().join("src.txt"))
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let dst = fs::canonicalize(temp.path().join("dst.txt"))
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let engine = deny_all_engine();
    let result = engine.eval::<()>(&format!(r#"cp("{src}", "{dst}")"#));
    assert!(result.is_err());
    let err_str = format!("{:?}", result.unwrap_err());
    assert!(
        err_str.contains("unauthorized") || err_str.contains("Permission denied"),
        "Expected authorization error, got: {err_str}",
    );
}
