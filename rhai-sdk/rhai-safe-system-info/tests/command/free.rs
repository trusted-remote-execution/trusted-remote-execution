#![cfg(target_os = "linux")]

use rex_test_utils::rhai::common::{create_test_engine_and_register, deny_all_engine};
use rhai::Map;

// ── basic usage ─────────────────────────────────────────────────────────────

/// Given: A Linux system
/// When: Using free()
/// Then: A map with memory (Meminfo) and swap (Swapinfo) structs is returned
#[test]
fn test_free_basic() {
    let engine = create_test_engine_and_register();
    let script = r#"
        let mem = free();
        let total = mem.memory.total;
    "#;
    let result = engine.eval::<()>(script);
    assert!(
        result.is_ok(),
        "free() basic failed: {:?}",
        result.unwrap_err()
    );
}

/// Given: A Linux system
/// When: Accessing all Meminfo fields from free()
/// Then: total, free, available, and used are accessible
#[test]
fn test_free_memory_fields() {
    let engine = create_test_engine_and_register();
    let script = r#"
        let m = free().memory;
        let v1 = m.total;
        let v2 = m.free;
        let v3 = m.available;
        let v4 = m.used;
    "#;
    let result = engine.eval::<()>(script);
    assert!(
        result.is_ok(),
        "free memory fields failed: {:?}",
        result.unwrap_err()
    );
}

/// Given: A Linux system
/// When: Accessing all Swapinfo fields from free()
/// Then: total, free, and used are accessible
#[test]
fn test_free_swap_fields() {
    let engine = create_test_engine_and_register();
    let script = r#"
        let s = free().swap;
        let v1 = s.total;
        let v2 = s.free;
        let v3 = s.used;
    "#;
    let result = engine.eval::<()>(script);
    assert!(
        result.is_ok(),
        "free swap fields failed: {:?}",
        result.unwrap_err()
    );
}

// ── error cases ─────────────────────────────────────────────────────────────

/// Given: A deny-all Cedar policy
/// When: Using free()
/// Then: An authorization error is returned
#[test]
fn test_free_unauthorized() {
    let engine = deny_all_engine();
    let result = engine.eval::<Map>(r#"free()"#);
    assert!(result.is_err());
}

// ── registry completeness ───────────────────────────────────────────────────

/// Given: The Meminfo struct with known fields (total, free, available, used)
/// When: Probing each field via Rhai property access
/// Then: Every field has a corresponding Rhai property getter
#[test]
fn test_free_meminfo_registry_completeness() {
    let engine = create_test_engine_and_register();
    // Meminfo does not derive Serialize, so we check known fields directly.
    // ext is #[getter(skip)] and not exposed to Rhai.
    let expected_fields = ["total", "free", "available", "used"];
    let mut missing = Vec::new();
    for field in &expected_fields {
        let script = format!("let m = free().memory; m.{field}");
        if engine.eval::<rhai::Dynamic>(&script).is_err() {
            missing.push(*field);
        }
    }
    assert!(
        missing.is_empty(),
        "Meminfo registry mismatch — missing Rhai getters: {missing:?}"
    );
}

/// Given: The Swapinfo struct with all its fields serialized via serde
/// When: Comparing serde field names against registered Rhai getters
/// Then: Every serialized field has a corresponding Rhai property getter
#[test]
fn test_free_swapinfo_registry_completeness() {
    use rex_test_utils::rhai::safe_io::assert_rhai_getters_match_serde_fields;
    use rust_system_info::Swapinfo;

    let engine = create_test_engine_and_register();
    let swap: Swapinfo = engine.eval("free().swap").unwrap();
    let json = serde_json::to_value(&swap).unwrap();

    assert_rhai_getters_match_serde_fields(&engine, "free().swap", &json, &[], "Swapinfo");
}
