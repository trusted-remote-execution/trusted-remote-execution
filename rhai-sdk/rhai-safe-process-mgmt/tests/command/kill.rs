#![cfg(target_os = "linux")]

use rex_test_utils::rhai::common::{create_test_engine_and_register, deny_all_engine};
use rhai::Array;

// ── error cases ─────────────────────────────────────────────────────────────

/// Given: A nonexistent PID
/// When: Using kill(pid)
/// Then: An error is returned
#[test]
fn test_kill_nonexistent_pid() {
    let engine = create_test_engine_and_register();
    let result = engine.eval::<Array>(r#"kill(999999999)"#);
    assert!(result.is_err());
}

/// Given: A deny-all Cedar policy
/// When: Using kill(pid)
/// Then: An authorization error is returned
#[test]
fn test_kill_unauthorized() {
    let engine = deny_all_engine();
    let result = engine.eval::<Array>(r#"kill(1)"#);
    assert!(result.is_err());
}

/// Given: A nonexistent PID and a signal flag
/// When: Using kill with kill::SIGKILL flag
/// Then: An error is returned
#[test]
fn test_kill_with_signal_flag_nonexistent() {
    let engine = create_test_engine_and_register();
    let result = engine.eval::<Array>(r#"kill([kill::SIGKILL], 999999999)"#);
    assert!(result.is_err());
}
