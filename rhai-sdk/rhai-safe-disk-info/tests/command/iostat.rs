#![cfg(target_os = "linux")]

use rex_test_utils::rhai::common::{create_test_engine_and_register, deny_all_engine};
use rhai::Dynamic;

// ── basic usage ─────────────────────────────────────────────────────────────

/// Given: A Linux system
/// When: Using iostat()
/// Then: An IoStatSnapshot struct with cpu_stats and device_stats is returned
#[test]
fn test_iostat_basic() {
    let engine = create_test_engine_and_register();
    let script = r#"
        let stats = iostat();
        stats.cpu_stats.idle_percent
    "#;
    let result: f64 = engine.eval(script).unwrap();
    assert!(result >= 0.0);
}

/// Given: A Linux system
/// When: Accessing all CpuStats fields from iostat()
/// Then: All CPU stat fields are accessible
#[test]
fn test_iostat_cpu_stats_fields() {
    let engine = create_test_engine_and_register();
    let script = r#"
        let cpu = iostat().cpu_stats;
        let result = #{};
        result["user_percent"] = cpu.user_percent;
        result["nice_percent"] = cpu.nice_percent;
        result["system_percent"] = cpu.system_percent;
        result["iowait_percent"] = cpu.iowait_percent;
        result["steal_percent"] = cpu.steal_percent;
        result["idle_percent"] = cpu.idle_percent;
        result
    "#;
    let result = engine.eval::<rhai::Map>(script).unwrap();
    assert!(result.get("user_percent").unwrap().clone_cast::<f64>() >= 0.0);
    assert!(result.get("nice_percent").unwrap().clone_cast::<f64>() >= 0.0);
    assert!(result.get("system_percent").unwrap().clone_cast::<f64>() >= 0.0);
    assert!(result.get("iowait_percent").unwrap().clone_cast::<f64>() >= 0.0);
    assert!(result.get("steal_percent").unwrap().clone_cast::<f64>() >= 0.0);
    assert!(result.get("idle_percent").unwrap().clone_cast::<f64>() >= 0.0);
}

/// Given: A Linux system with block devices
/// When: Accessing all DeviceStats fields from iostat()
/// Then: All device stat fields are accessible
#[test]
fn test_iostat_device_stats_fields() {
    let engine = create_test_engine_and_register();
    let script = r#"
        let devices = iostat().device_stats;
        if devices.len() == 0 {
            return #{};
        }
        let dev = devices[0];
        let result = #{};
        result["device_name"] = dev.device_name;
        result["rrqm_per_sec"] = dev.rrqm_per_sec;
        result["wrqm_per_sec"] = dev.wrqm_per_sec;
        result["read_requests_per_sec"] = dev.read_requests_per_sec;
        result["write_requests_per_sec"] = dev.write_requests_per_sec;
        result["rkb_per_sec"] = dev.rkb_per_sec;
        result["wkb_per_sec"] = dev.wkb_per_sec;
        result["avg_request_size"] = dev.avg_request_size;
        result["avg_queue_size"] = dev.avg_queue_size;
        result["avg_wait"] = dev.avg_wait;
        result["avg_read_wait"] = dev.avg_read_wait;
        result["avg_write_wait"] = dev.avg_write_wait;
        result["svctm"] = dev.svctm;
        result["util_percent"] = dev.util_percent;
        result
    "#;
    let result = engine.eval::<rhai::Map>(script).unwrap();
    if !result.is_empty() {
        assert!(
            !result
                .get("device_name")
                .unwrap()
                .clone_cast::<String>()
                .is_empty()
        );
        assert!(result.get("rrqm_per_sec").unwrap().clone_cast::<f64>() >= 0.0);
        assert!(result.get("util_percent").unwrap().clone_cast::<f64>() >= 0.0);
    }
}

// ── error cases ─────────────────────────────────────────────────────────────

/// Given: A deny-all Cedar policy
/// When: Using iostat()
/// Then: An authorization error is returned
#[test]
fn test_iostat_unauthorized() {
    let engine = deny_all_engine();
    let result = engine.eval::<Dynamic>(r#"iostat()"#);
    assert!(result.is_err());
}

// ── registry completeness ───────────────────────────────────────────────────

/// Given: The CpuStats struct with all its fields serialized via serde
/// When: Comparing serde field names against registered Rhai getters
/// Then: Every serialized field has a corresponding Rhai property getter
#[test]
fn test_iostat_cpu_stats_registry_completeness() {
    use rex_test_utils::rhai::safe_io::assert_rhai_getters_match_serde_fields;
    use rust_disk_info::iostat::CpuStats;

    let engine = create_test_engine_and_register();
    let snapshot: Dynamic = engine.eval("iostat()").unwrap();
    let cpu: CpuStats = engine.eval::<Dynamic>("iostat().cpu_stats").unwrap().cast();
    let json = serde_json::to_value(&cpu).unwrap();

    assert_rhai_getters_match_serde_fields(&engine, "iostat().cpu_stats", &json, &[], "CpuStats");
}

/// Given: The DeviceStats struct with all its fields serialized via serde
/// When: Comparing serde field names against registered Rhai getters
/// Then: Every serialized field has a corresponding Rhai property getter
#[test]
fn test_iostat_device_stats_registry_completeness() {
    use rex_test_utils::rhai::safe_io::assert_rhai_getters_match_serde_fields;
    use rust_disk_info::iostat::DeviceStats;

    let engine = create_test_engine_and_register();
    let devices: rhai::Array = engine.eval("iostat().device_stats").unwrap();
    if devices.is_empty() {
        eprintln!("Skipping: no block devices available");
        return;
    }
    let dev: DeviceStats = devices[0].clone().cast();
    let json = serde_json::to_value(&dev).unwrap();

    assert_rhai_getters_match_serde_fields(
        &engine,
        "iostat().device_stats[0]",
        &json,
        &[],
        "DeviceStats",
    );
}

/// Given: The IoStatSnapshot struct with cpu_stats and device_stats fields
/// When: Comparing serde field names against registered Rhai getters
/// Then: Both top-level fields are accessible as Rhai properties
#[test]
fn test_iostat_snapshot_registry_completeness() {
    let engine = create_test_engine_and_register();
    for field in &["cpu_stats", "device_stats"] {
        let script = format!("let obj = iostat(); obj.{field}");
        let result = engine.eval::<Dynamic>(&script);
        assert!(
            result.is_ok(),
            "IoStatSnapshot field '{field}' is not registered: {:?}",
            result.err()
        );
    }
}
