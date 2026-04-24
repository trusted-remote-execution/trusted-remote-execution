#![cfg(target_os = "linux")]

use rex_test_utils::rhai::common::{create_test_engine_and_register, deny_all_engine};
use rhai::Array;

// ── basic usage ─────────────────────────────────────────────────────────────

/// Given: The hostname "localhost"
/// When: Using resolve("localhost")
/// Then: An array with at least one IP address is returned
#[test]
fn test_resolve_localhost() {
    let engine = create_test_engine_and_register();
    let result: Array = engine.eval(r#"resolve("localhost")"#).unwrap();
    assert!(!result.is_empty());
}

// ── error cases ─────────────────────────────────────────────────────────────

/// Given: A deny-all Cedar policy
/// When: Using resolve
/// Then: An authorization error is returned
#[test]
fn test_resolve_unauthorized() {
    let engine = deny_all_engine();
    let result = engine.eval::<Array>(r#"resolve("localhost")"#);
    assert!(result.is_err());
}
