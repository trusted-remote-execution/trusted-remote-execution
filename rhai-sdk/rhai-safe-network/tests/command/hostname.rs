#![cfg(target_os = "linux")]

use rex_test_utils::rhai::common::{create_test_engine_and_register, deny_all_engine};

// ── basic usage ─────────────────────────────────────────────────────────────

/// Given: A Linux system
/// When: Using hostname()
/// Then: A non-empty string is returned
#[test]
fn test_hostname_basic() {
    let engine = create_test_engine_and_register();
    let result: String = engine.eval(r#"hostname()"#).unwrap();
    assert!(!result.is_empty());
}

// ── error cases ─────────────────────────────────────────────────────────────

/// Given: A deny-all Cedar policy
/// When: Using hostname()
/// Then: An authorization error is returned
#[test]
fn test_hostname_unauthorized() {
    let engine = deny_all_engine();
    let result = engine.eval::<String>(r#"hostname()"#);
    assert!(result.is_err());
}
