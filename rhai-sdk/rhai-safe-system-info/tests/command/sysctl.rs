#![cfg(target_os = "linux")]

use rex_test_utils::rhai::common::{create_test_engine_and_register, deny_all_engine};
use rhai::Array;

// ── sysctl_read ─────────────────────────────────────────────────────────────

/// Given: A valid kernel parameter key
/// When: Using sysctl_read(key)
/// Then: A non-empty string value is returned
#[test]
fn test_sysctl_read_basic() {
    let engine = create_test_engine_and_register();
    let result: String = engine.eval(r#"sysctl_read("kernel.hostname")"#).unwrap();
    assert!(!result.is_empty());
}

/// Given: A deny-all Cedar policy
/// When: Using sysctl_read
/// Then: An authorization error is returned
#[test]
fn test_sysctl_read_unauthorized() {
    let engine = deny_all_engine();
    let result = engine.eval::<String>(r#"sysctl_read("kernel.hostname")"#);
    assert!(result.is_err());
}

// ── sysctl_find ─────────────────────────────────────────────────────────────

/// Given: A pattern matching kernel parameters
/// When: Using sysctl_find(pattern)
/// Then: A non-empty array of key/value maps is returned
#[test]
fn test_sysctl_find_basic() {
    let engine = create_test_engine_and_register();
    let result: Array = engine.eval(r#"sysctl_find("kernel.hostname")"#).unwrap();
    assert!(!result.is_empty());
}

/// Given: A deny-all Cedar policy
/// When: Using sysctl_find
/// Then: An authorization error is returned
#[test]
fn test_sysctl_find_unauthorized() {
    let engine = deny_all_engine();
    let result = engine.eval::<Array>(r#"sysctl_find("kernel")"#);
    assert!(result.is_err());
}
