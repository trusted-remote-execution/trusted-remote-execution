#![cfg(target_os = "linux")]

use rex_test_utils::rhai::common::{create_test_engine_and_register, deny_all_engine};
use rhai::Array;

/// Returns true only if /dev/kmsg can actually be opened for reading.
/// The file may exist and have read permissions, but opening it still
/// requires `CAP_SYSLOG`, which is absent in most dev/CI environments.
fn kmsg_is_readable() -> bool {
    std::fs::File::open("/dev/kmsg").is_ok()
}

// ── basic usage ─────────────────────────────────────────────────────────────

/// Given: A Linux system with /dev/kmsg available
/// When: Using dmesg()
/// Then: An array of DmesgEntry structs is returned
#[test]
fn test_dmesg_basic() {
    if !kmsg_is_readable() {
        eprintln!("Skipping test_dmesg_basic: /dev/kmsg not readable (requires CAP_SYSLOG)");
        return;
    }
    let engine = create_test_engine_and_register();
    let result: Array = engine.eval(r#"dmesg()"#).unwrap();
    assert!(!result.is_empty());
}

/// Given: A Linux system with /dev/kmsg available
/// When: Accessing all fields of a dmesg() entry
/// Then: timestamp_from_system_start and message are accessible
#[test]
fn test_dmesg_entry_fields() {
    if !kmsg_is_readable() {
        eprintln!("Skipping test_dmesg_entry_fields: /dev/kmsg not readable (requires CAP_SYSLOG)");
        return;
    }
    let engine = create_test_engine_and_register();
    let script = r#"
        let entries = dmesg();
        let entry = entries[0];
        let result = #{};
        result["timestamp_from_system_start"] = entry.timestamp_from_system_start;
        result["message"] = entry.message;
        result
    "#;
    let result = engine.eval::<rhai::Map>(script).unwrap();
    assert!(
        !result
            .get("timestamp_from_system_start")
            .unwrap()
            .clone_cast::<String>()
            .is_empty()
    );
    assert!(
        !result
            .get("message")
            .unwrap()
            .clone_cast::<String>()
            .is_empty()
    );
}

// ── error cases ─────────────────────────────────────────────────────────────

/// Given: A deny-all Cedar policy
/// When: Using dmesg()
/// Then: An authorization error is returned
#[test]
fn test_dmesg_unauthorized() {
    let engine = deny_all_engine();
    let result = engine.eval::<Array>(r#"dmesg()"#);
    assert!(result.is_err());
}

// ── registry completeness ───────────────────────────────────────────────────

/// Given: The DmesgEntry struct has fields: timestamp_from_system_start, message
/// When: Accessing every field via Rhai property syntax
/// Then: All fields are accessible, confirming the registry matches the struct
#[test]
fn test_dmesg_entry_registry_completeness() {
    if !kmsg_is_readable() {
        eprintln!("Skipping test_dmesg_entry_registry_completeness: /dev/kmsg not readable");
        return;
    }
    let engine = create_test_engine_and_register();
    let expected_fields = ["timestamp_from_system_start", "message"];
    let obj_expr = "dmesg()[0]";
    for field in &expected_fields {
        let script = format!("let obj = {obj_expr}; obj.{field}");
        let result = engine.eval::<rhai::Dynamic>(&script);
        assert!(
            result.is_ok(),
            "DmesgEntry field '{field}' is not registered as a Rhai getter: {:?}",
            result.err()
        );
    }
}

// ── registry completeness ───────────────────────────────────────────────────

/// Given: The DmesgEntry struct with all its fields serialized via serde
/// When: Comparing serde field names against registered Rhai getters
/// Then: Every serialized field has a corresponding Rhai property getter
#[test]
fn test_dmesg_registry_completeness() {
    if !kmsg_is_readable() {
        eprintln!("Skipping test_dmesg_registry_completeness: /dev/kmsg not readable");
        return;
    }
    use rex_test_utils::rhai::safe_io::assert_rhai_getters_match_serde_fields;
    use rust_safe_system_info::DmesgEntry;

    let engine = create_test_engine_and_register();
    let entries: Array = engine.eval("dmesg()").unwrap();
    let entry: DmesgEntry = entries[0].clone().cast();
    let json = serde_json::to_value(&entry).unwrap();

    assert_rhai_getters_match_serde_fields(&engine, "dmesg()[0]", &json, &[], "DmesgEntry");
}
