#![cfg(target_os = "linux")]

use rex_test_utils::rhai::common::{create_test_engine_and_register, deny_all_engine};
use rhai::Map;

// ── basic usage ─────────────────────────────────────────────────────────────

/// Given: A Linux system with block device sysfs available
/// When: Using lsblk()
/// Then: A non-empty map of block devices is returned (skipped in containers)
#[test]
fn test_lsblk_basic() {
    let engine = create_test_engine_and_register();
    let result = engine.eval::<Map>(r#"lsblk()"#);
    match result {
        Ok(map) => assert!(!map.is_empty()),
        Err(e) => {
            let msg = format!("{e}");
            if msg.contains("No such file or directory") {
                eprintln!("Skipping test_lsblk_basic: required sysfs paths not available");
                return;
            }
            panic!("Unexpected error: {e}");
        }
    }
}

// ── error cases ─────────────────────────────────────────────────────────────

/// Given: A deny-all Cedar policy
/// When: Using lsblk()
/// Then: An authorization error is returned
#[test]
fn test_lsblk_unauthorized() {
    let engine = deny_all_engine();
    let result = engine.eval::<Map>(r#"lsblk()"#);
    assert!(result.is_err());
}
