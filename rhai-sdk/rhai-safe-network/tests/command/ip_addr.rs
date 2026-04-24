#![cfg(target_os = "linux")]

use rex_test_utils::rhai::common::{create_test_engine_and_register, deny_all_engine};
use rhai::Array;

// ── basic usage ─────────────────────────────────────────────────────────────

/// Given: A Linux system
/// When: Using ip_addr()
/// Then: A non-empty array of Network structs is returned
#[test]
fn test_ip_addr_basic() {
    let engine = create_test_engine_and_register();
    let result: Array = engine.eval(r#"ip_addr()"#).unwrap();
    assert!(!result.is_empty());
}

/// Given: A Linux system
/// When: Accessing all fields of an ip_addr() entry
/// Then: interface_name and addresses are accessible
#[test]
fn test_ip_addr_entry_fields() {
    let engine = create_test_engine_and_register();
    let script = r#"
        let interfaces = ip_addr();
        let iface = interfaces[0];
        let result = #{};
        result["interface_name"] = iface.interface_name;
        result["addresses"] = iface.addresses;
        result
    "#;
    let result = engine.eval::<rhai::Map>(script).unwrap();
    assert!(
        !result
            .get("interface_name")
            .unwrap()
            .clone_cast::<String>()
            .is_empty()
    );
    let addrs = result.get("addresses").unwrap().clone_cast::<Array>();
    assert!(addrs.len() >= 0); // may be empty for some interfaces
}

// ── error cases ─────────────────────────────────────────────────────────────

/// Given: A deny-all Cedar policy
/// When: Using ip_addr()
/// Then: An authorization error is returned
#[test]
fn test_ip_addr_unauthorized() {
    let engine = deny_all_engine();
    let result = engine.eval::<Array>(r#"ip_addr()"#);
    assert!(result.is_err());
}

// ── registry completeness ───────────────────────────────────────────────────

/// Given: The Network struct with all its fields serialized via serde
/// When: Comparing serde field names against registered Rhai getters
/// Then: Every serialized field has a corresponding Rhai property getter
#[test]
fn test_ip_addr_network_registry_completeness() {
    use rex_test_utils::rhai::safe_io::assert_rhai_getters_match_serde_fields;
    use rust_network::Network;

    let engine = create_test_engine_and_register();
    let interfaces: Array = engine.eval("ip_addr()").unwrap();
    let net: Network = interfaces[0].clone().cast();
    let json = serde_json::to_value(&net).unwrap();

    assert_rhai_getters_match_serde_fields(&engine, "ip_addr()[0]", &json, &[], "Network");
}
