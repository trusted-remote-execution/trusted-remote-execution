#![cfg(target_os = "linux")]
use rex_cedar_auth::test_utils::get_test_rex_principal;
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::rhai::common::create_test_engine_and_register;

mod common;
use common::create_test_engine_and_register_with_policy;

mod iostat_tests {
    use rhai::{EvalAltResult, Map};

    use super::*;

    /// Given: a Filesystems object
    /// When: iostat method is called
    /// Then: an IoStatSnapshot is returned with valid CPU and device statistics
    #[test]
    fn test_get_iostat_success() {
        let engine = create_test_engine_and_register();

        let result = engine.eval::<()>(
            r#"
                let fs_opts = FilesystemOptions().build();
                let filesystems = Filesystems(fs_opts);
                let iostat_snapshot = filesystems.iostat();
                
                // Test IoStatSnapshot getters
                let cpu_stats = iostat_snapshot.cpu_stats;
                let device_stats = iostat_snapshot.device_stats;
                
                // Validate CPU stats exist and have expected getters
                let user_percent = cpu_stats.user_percent;
                let nice_percent = cpu_stats.nice_percent;
                let system_percent = cpu_stats.system_percent;
                let iowait_percent = cpu_stats.iowait_percent;
                let steal_percent = cpu_stats.steal_percent;
                let idle_percent = cpu_stats.idle_percent;
                
                // Validate device stats array exists
                if (device_stats.len() < 0) {
                    throw "Device stats should be a valid array";
                }
                
                // Test device stats getters if devices exist
                if (device_stats.len() > 0) {
                    let first_device = device_stats[0];
                    
                    // Test all DeviceStats getters
                    let device_name = first_device.device_name;
                    let rrqm_per_sec = first_device.rrqm_per_sec;
                    let wrqm_per_sec = first_device.wrqm_per_sec;
                    let read_requests_per_sec = first_device.read_requests_per_sec;
                    let write_requests_per_sec = first_device.write_requests_per_sec;
                    let rkb_per_sec = first_device.rkb_per_sec;
                    let wkb_per_sec = first_device.wkb_per_sec;
                    let avg_request_size = first_device.avg_request_size;
                    let avg_queue_size = first_device.avg_queue_size;
                    let avg_wait = first_device.avg_wait;
                    let avg_read_wait = first_device.avg_read_wait;
                    let avg_write_wait = first_device.avg_write_wait;
                    let svctm = first_device.svctm;
                    let util_percent = first_device.util_percent;
                    
                    // Validate device name is not empty
                    if (device_name.len() == 0) {
                        throw "Device name should not be empty";
                    }
                    
                    // Validate utilization percentage is reasonable (0-100)
                    if (util_percent < 0.0 || util_percent > 100.0) {
                        throw "Device utilization percent should be between 0-100, got: " + util_percent;
                    }
                }
            "#,
        );

        assert!(
            result.is_ok(),
            "iostat() should return valid I/O statistics: {:?}",
            result.unwrap_err()
        );
    }

    /// Given: an iostat snapshot
    /// When: to_map method is called
    /// Then: the value is equal to expected
    #[test]
    fn test_iostat_to_map() -> Result<(), Box<EvalAltResult>> {
        let engine = create_test_engine_and_register();

        let result = engine.eval::<Map>(
            r#"
                let fs_opts = FilesystemOptions().build();
                let filesystems = Filesystems(fs_opts);
                let iostat_snapshot = filesystems.iostat();
                let iostat_snapshot_map = iostat_snapshot.to_map();

                // First validate that CpuStats.to_map() and DeviceStats.to_map() exist and are consistent
                // with iostat_snapshot.to_map()
                let cpu_stats_map = iostat_snapshot.cpu_stats.to_map();
                let device_stats_map = iostat_snapshot.device_stats[0].to_map();
                
                if cpu_stats_map != iostat_snapshot_map["cpu_stats"] {
                    throw "cpu_stats.to_map() should equal iostat_snapshot.to_map()['cpu_stats']";
                }

                if device_stats_map != iostat_snapshot_map["device_stats"][0] {
                    throw "device_stats.to_map() should equal iostat_snapshot.to_map()['device_stats']";
                }

                // Next validate the iostat_snapshot map all at once
                let cpu_stats = iostat_snapshot.cpu_stats;
                let device_stats = iostat_snapshot.device_stats.map(|stat| {
                    return #{
                        "device_name": stat.device_name,
                        "rrqm_per_sec": stat.rrqm_per_sec,
                        "wrqm_per_sec": stat.wrqm_per_sec,
                        "read_requests_per_sec": stat.read_requests_per_sec,
                        "write_requests_per_sec": stat.write_requests_per_sec,
                        "rkb_per_sec": stat.rkb_per_sec,
                        "wkb_per_sec": stat.wkb_per_sec,
                        "avg_request_size": stat.avg_request_size,
                        "avg_queue_size": stat.avg_queue_size,
                        "avg_wait": stat.avg_wait,
                        "avg_read_wait": stat.avg_read_wait,
                        "avg_write_wait": stat.avg_write_wait,
                        "svctm": stat.svctm,
                        "util_percent": stat.util_percent,
                    };
                });

                let expected = #{
                    "cpu_stats": #{
                        "user_percent": cpu_stats.user_percent,
                        "nice_percent": cpu_stats.nice_percent,
                        "system_percent": cpu_stats.system_percent,
                        "iowait_percent": cpu_stats.iowait_percent,
                        "steal_percent": cpu_stats.steal_percent,
                        "idle_percent": cpu_stats.idle_percent,
                    },
                    "device_stats": device_stats
                };
                
                #{
                    "expected": expected.to_json(),
                    "actual": iostat_snapshot_map.to_json()
                }
            "#,
        )?;

        let expected: String = result.get("expected").unwrap().clone().into_string()?;
        let actual: String = result.get("actual").unwrap().clone().into_string()?;
        assert_eq!(expected, actual);

        Ok(())
    }

    /// Given: an unauthorized user and a Filesystems object
    /// When: user calls iostat method
    /// Then: an authorization error is returned
    #[test]
    fn test_iostat_permission_denied() {
        let principal = get_test_rex_principal();
        let restrictive_policy = r#"
            forbid (
                principal,  
                action,
                resource
            );
        "#;

        let engine = create_test_engine_and_register_with_policy(restrictive_policy);
        let result = engine.eval::<()>(
            r#"
                let fs_opts = FilesystemOptions().build();
                let filesystems = Filesystems(fs_opts);
                filesystems.iostat();
            "#,
        );

        assert!(
            result.is_err(),
            "Unauthorized user should not be able to get iostat information"
        );

        let expected_error = format!("Permission denied: {principal} unauthorized to perform");
        assert_error_contains(result, &expected_error);
    }
}
