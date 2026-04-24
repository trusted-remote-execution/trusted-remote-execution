#![cfg(target_os = "linux")]

use rex_test_utils::rhai::common::{create_test_engine_and_register, deny_all_engine};
use rhai::Dynamic;

// ── basic usage ─────────────────────────────────────────────────────────────

/// Given: A Linux system
/// When: Using uname()
/// Then: An UnameInfo struct with all system info properties is returned
#[test]
fn test_uname_basic() {
    let engine = create_test_engine_and_register();
    let script = r#"
        let info = uname();
        info.kernel_name + " " + info.nodename + " " + info.kernel_release + " " + info.machine
    "#;
    let result: String = engine.eval(script).unwrap();
    assert!(!result.is_empty());
}

/// Given: A Linux system
/// When: Accessing all fields of uname()
/// Then: All registered UnameInfo fields are accessible
#[test]
fn test_uname_all_fields() {
    let engine = create_test_engine_and_register();
    let script = r#"
        let info = uname();
        let result = #{};
        result["kernel_name"] = info.kernel_name;
        result["nodename"] = info.nodename;
        result["kernel_release"] = info.kernel_release;
        result["kernel_version"] = info.kernel_version;
        result["machine"] = info.machine;
        result["processor"] = info.processor;
        result["hardware_platform"] = info.hardware_platform;
        result["operating_system"] = info.operating_system;
        result
    "#;
    let result = engine.eval::<rhai::Map>(script).unwrap();
    assert_eq!(
        result.get("kernel_name").unwrap().clone_cast::<String>(),
        "Linux"
    );
    assert!(
        !result
            .get("nodename")
            .unwrap()
            .clone_cast::<String>()
            .is_empty()
    );
    assert!(
        !result
            .get("kernel_release")
            .unwrap()
            .clone_cast::<String>()
            .is_empty()
    );
    assert!(
        !result
            .get("kernel_version")
            .unwrap()
            .clone_cast::<String>()
            .is_empty()
    );
    assert!(
        !result
            .get("machine")
            .unwrap()
            .clone_cast::<String>()
            .is_empty()
    );
    assert!(
        !result
            .get("processor")
            .unwrap()
            .clone_cast::<String>()
            .is_empty()
    );
    assert!(
        !result
            .get("hardware_platform")
            .unwrap()
            .clone_cast::<String>()
            .is_empty()
    );
    assert!(
        !result
            .get("operating_system")
            .unwrap()
            .clone_cast::<String>()
            .is_empty()
    );
}

// ── error cases ─────────────────────────────────────────────────────────────

/// Given: A deny-all Cedar policy
/// When: Using uname()
/// Then: An authorization error is returned
#[test]
fn test_uname_unauthorized() {
    let engine = deny_all_engine();
    let result = engine.eval::<Dynamic>(r#"uname()"#);
    assert!(result.is_err());
}

// ── registry completeness ───────────────────────────────────────────────────

/// Given: The UnameInfo struct with all its fields serialized via serde
/// When: Comparing serde field names against registered Rhai getters
/// Then: Every serialized field has a corresponding Rhai property getter
#[test]
fn test_uname_registry_completeness() {
    use rex_test_utils::rhai::safe_io::assert_rhai_getters_match_serde_fields;
    use rust_system_info::UnameInfo;

    let engine = create_test_engine_and_register();
    let info: UnameInfo = engine.eval::<Dynamic>("uname()").unwrap().cast();
    let json = serde_json::to_value(&info).unwrap();

    assert_rhai_getters_match_serde_fields(&engine, "uname()", &json, &[], "UnameInfo");
}
