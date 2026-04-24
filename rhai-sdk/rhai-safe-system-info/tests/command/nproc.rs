#![cfg(target_os = "linux")]

use rex_test_utils::rhai::common::{create_test_engine_and_register, deny_all_engine};

// ── basic usage ─────────────────────────────────────────────────────────────

/// Given: A Linux system
/// When: Using nproc()
/// Then: A positive integer is returned
#[test]
fn test_nproc_basic() {
    let engine = create_test_engine_and_register();
    let result: i64 = engine.eval(r#"nproc()"#).unwrap();
    assert!(result > 0);
}

// ── error cases ─────────────────────────────────────────────────────────────

/// Given: A deny-all Cedar policy
/// When: Using nproc()
/// Then: An authorization error is returned
#[test]
fn test_nproc_unauthorized() {
    let engine = deny_all_engine();
    let result = engine.eval::<i64>(r#"nproc()"#);
    assert!(result.is_err());
}
