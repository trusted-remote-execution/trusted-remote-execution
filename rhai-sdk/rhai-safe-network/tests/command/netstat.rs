#![cfg(target_os = "linux")]

use rex_test_utils::rhai::common::{create_test_engine_and_register, deny_all_engine};
use rhai::Dynamic;

// ── basic usage ─────────────────────────────────────────────────────────────

/// Given: A Linux system
/// When: Using netstat()
/// Then: A map with internet and unix arrays is returned
#[test]
fn test_netstat_basic() {
    let engine = create_test_engine_and_register();
    let script = r#"
        let stats = netstat();
        let inet_count = stats.internet.len();
        let unix_count = stats.unix.len();
        inet_count + unix_count
    "#;
    let result: i64 = engine.eval(script).unwrap();
    assert!(result >= 0);
}

// ── error cases ─────────────────────────────────────────────────────────────

/// Given: A deny-all Cedar policy
/// When: Using netstat()
/// Then: An authorization error is returned
#[test]
fn test_netstat_unauthorized() {
    let engine = deny_all_engine();
    let result = engine.eval::<Dynamic>(r#"netstat()"#);
    assert!(result.is_err());
}
