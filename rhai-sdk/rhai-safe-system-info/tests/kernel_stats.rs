#![cfg(target_os = "linux")]
use rex_cedar_auth::test_utils::get_test_rex_principal;
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::rhai::common::create_test_engine_and_register;

mod common;
use common::create_test_engine_and_register_with_policy;

use rhai::{EvalAltResult, Map};

mod cpu_time_tests {
    use super::*;

    /// Given: kernel_stats
    /// When: total_cpu_time is called
    /// Then: the total cpu time is returned and the tick values are valid
    #[test]
    fn test_cpu_time_tick_getters() {
        let engine = create_test_engine_and_register();

        let result = engine.eval::<()>(
            r#"
                let system_info = SystemInfo();
                let kernel_stats = system_info.kernel_stats();
                let cpu_time = kernel_stats.total_cpu_time;
                
                let user_ticks = cpu_time.user_ticks;
                let nice_ticks = cpu_time.nice_ticks;
                let system_ticks = cpu_time.system_ticks;
                let idle_ticks = cpu_time.idle_ticks;
                let iowait_ticks = cpu_time.iowait_ticks;
                let irq_ticks = cpu_time.irq_ticks;
                let softirq_ticks = cpu_time.softirq_ticks;
                let stolen_ticks = cpu_time.stolen_ticks;
                let guest_ticks = cpu_time.guest_ticks;
                let guest_nice_ticks = cpu_time.guest_nice_ticks;
                
                // Verify all values are non-negative integers
                if (user_ticks < 0 || nice_ticks < 0 || system_ticks < 0 || idle_ticks < 0 ||
                    iowait_ticks < 0 || irq_ticks < 0 || softirq_ticks < 0 || stolen_ticks < 0 ||
                    guest_ticks < 0 || guest_nice_ticks < 0) {
                    throw "All tick values should be non-negative";
                }
            "#,
        );

        assert!(
            result.is_ok(),
            "CPU time tick getters test failed: {:?}",
            result.unwrap_err()
        );
    }

    /// Given: kernel_stats
    /// When: total_cpu_time is called
    /// Then: the total cpu time is returned and the millis values are valid
    #[test]
    fn test_cpu_time_millisecond_getters() {
        let engine = create_test_engine_and_register();

        let result = engine.eval::<()>(
            r#"
                let system_info = SystemInfo();
                let kernel_stats = system_info.kernel_stats();
                let cpu_time = kernel_stats.total_cpu_time;
                
                let user_ms = cpu_time.user_ms;
                let nice_ms = cpu_time.nice_ms;
                let system_ms = cpu_time.system_ms;
                let idle_ms = cpu_time.idle_ms;
                let iowait_ms = cpu_time.iowait_ms;
                let irq_ms = cpu_time.irq_ms;
                let softirq_ms = cpu_time.softirq_ms;
                let stolen_ms = cpu_time.stolen_ms;
                let guest_ms = cpu_time.guest_ms;
                let guest_nice_ms = cpu_time.guest_nice_ms;
                
                // Verify all values are non-negative integers
                if (user_ms < 0 || nice_ms < 0 || system_ms < 0 || idle_ms < 0 ||
                    iowait_ms < 0 || irq_ms < 0 || softirq_ms < 0 || stolen_ms < 0 ||
                    guest_ms < 0 || guest_nice_ms < 0) {
                    throw "All millisecond values should be non-negative";
                }
            "#,
        );

        assert!(
            result.is_ok(),
            "CPU time millisecond getters test failed: {:?}",
            result.unwrap_err()
        );
    }

    /// Given: kernel_stats
    /// When: cpu_time is called
    /// Then: a vector of cpu_time is returned and it contains valid cpu times for each cpu
    #[test]
    fn test_cpu_time_individual_cpu_access() {
        let engine = create_test_engine_and_register();

        let result = engine.eval::<()>(
            r#"
                let system_info = SystemInfo();
                let kernel_stats = system_info.kernel_stats();
                let cpu_times = kernel_stats.cpu_time;
                
                // Verify we can access individual CPU times
                if (cpu_times.len() == 0) {
                    throw "Should have at least one CPU";
                }
                
                // Validate that accessing using bracket notation works
                let cpu0_time = cpu_times[0];
                
                // We converted the Vec<CpuTime> into an array of Dynamic, so this ensures we can still call getters on the retrieved CPU
                let user_ticks = cpu0_time.user_ticks;
            "#,
        );

        assert!(
            result.is_ok(),
            "Individual CPU time access test failed: {:?}",
            result.unwrap_err()
        );
    }
}

mod kernel_stats_tests {
    use super::*;
    use rhai::Scope;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Given: system_info
    /// When: kernel_stats is called
    /// Then: the kernel stats are returned and the values are valid
    #[test]
    fn test_kernel_stats_basic_getters() {
        let engine = create_test_engine_and_register();

        let current_system_time = SystemTime::now();
        let duration_since_epoch = current_system_time.duration_since(UNIX_EPOCH).unwrap();
        let now_timestamp = duration_since_epoch.as_secs() as i64;

        let mut scope = Scope::new();
        scope.push_constant("now_timestamp_sec", now_timestamp);

        let result = engine.eval_with_scope::<()>(
            &mut scope,
            r#"
                let system_info = SystemInfo();
                let kernel_stats = system_info.kernel_stats();
                
                let procs_running = kernel_stats.procs_running;
                let procs_blocked = kernel_stats.procs_blocked;
                let context_switches = kernel_stats.context_switches;
                let boot_time = kernel_stats.boot_time;
                let forks = kernel_stats.forks;
                
                // Verify all values are non-negative integers
                if (procs_running < 0 || procs_blocked < 0 || context_switches < 0 || 
                    boot_time < 0 || forks < 0) {
                    throw "All kernel stats values should be non-negative";
                }
                
                if (boot_time > now_timestamp_sec) {
                    throw "Boot time should be in the past";
                }
            "#,
        );

        assert!(
            result.is_ok(),
            "Kernel stats basic getters test failed: {:?}",
            result.unwrap_err()
        );
    }

    /// Given: kernel_stats
    /// When: to_map is called
    /// Then: the value equals expected
    #[test]
    fn test_kernel_stats_to_map() -> Result<(), Box<EvalAltResult>> {
        let engine = create_test_engine_and_register();

        let mut scope = Scope::new();
        let result = engine.eval_with_scope::<Map>(
            &mut scope,
            r#"
                let system_info = SystemInfo();
                let kernel_stats = system_info.kernel_stats();

                // first validate that CpuInfo.to_map matches kernel stats
                let kernel_stats_map = kernel_stats.to_map();
                let total_cpu_time_map = kernel_stats.total_cpu_time.to_map();

                if kernel_stats_map["total_cpu_time"] != total_cpu_time_map {
                    throw "kernel_stats_map[\"total_cpu_time\"] should equal total_cpu_time_map";
                }

                // next validate the whole map
                let total_cpu_time = kernel_stats.total_cpu_time;
                let expected = #{
                    "total_cpu_time": #{
                        "user_ticks": total_cpu_time.user_ticks,
                        "nice_ticks": total_cpu_time.nice_ticks,
                        "system_ticks": total_cpu_time.system_ticks,
                        "idle_ticks": total_cpu_time.idle_ticks,
                        "iowait_ticks": total_cpu_time.iowait_ticks,
                        "irq_ticks": total_cpu_time.irq_ticks,
                        "softirq_ticks": total_cpu_time.softirq_ticks,
                        "stolen_ticks": total_cpu_time.stolen_ticks,
                        "guest_ticks": total_cpu_time.guest_ticks,
                        "guest_nice_ticks": total_cpu_time.guest_nice_ticks,
                        "user_ms": total_cpu_time.user_ms,
                        "nice_ms": total_cpu_time.nice_ms,
                        "system_ms": total_cpu_time.system_ms,
                        "idle_ms": total_cpu_time.idle_ms,
                        "iowait_ms": total_cpu_time.iowait_ms,
                        "irq_ms": total_cpu_time.irq_ms,
                        "softirq_ms": total_cpu_time.softirq_ms,
                        "stolen_ms": total_cpu_time.stolen_ms,
                        "guest_ms": total_cpu_time.guest_ms,
                        "guest_nice_ms": total_cpu_time.guest_nice_ms,
                    },
                    "cpu_time": kernel_stats.cpu_time.map(|cpu_time| {
                        return #{
                            "user_ticks": cpu_time.user_ticks,
                            "nice_ticks": cpu_time.nice_ticks,
                            "system_ticks": cpu_time.system_ticks,
                            "idle_ticks": cpu_time.idle_ticks,
                            "iowait_ticks": cpu_time.iowait_ticks,
                            "irq_ticks": cpu_time.irq_ticks,
                            "softirq_ticks": cpu_time.softirq_ticks,
                            "stolen_ticks": cpu_time.stolen_ticks,
                            "guest_ticks": cpu_time.guest_ticks,
                            "guest_nice_ticks": cpu_time.guest_nice_ticks,
                            "user_ms": cpu_time.user_ms,
                            "nice_ms": cpu_time.nice_ms,
                            "system_ms": cpu_time.system_ms,
                            "idle_ms": cpu_time.idle_ms,
                            "iowait_ms": cpu_time.iowait_ms,
                            "irq_ms": cpu_time.irq_ms,
                            "softirq_ms": cpu_time.softirq_ms,
                            "stolen_ms": cpu_time.stolen_ms,
                            "guest_ms": cpu_time.guest_ms,
                            "guest_nice_ms": cpu_time.guest_nice_ms,
                        };
                    }),
                    "procs_running": kernel_stats.procs_running,
                    "procs_blocked": kernel_stats.procs_blocked,
                    "context_switches": kernel_stats.context_switches,
                    "boot_time": kernel_stats.boot_time,
                    "forks": kernel_stats.forks,
                };

                #{
                    "expected": expected.to_json(),
                    "actual": kernel_stats_map.to_json(),
                }
            "#,
        )?;

        let expected: String = result.get("expected").unwrap().clone().into_string()?;
        let actual: String = result.get("actual").unwrap().clone().into_string()?;
        assert_eq!(expected, actual);

        Ok(())
    }

    /// Given: system_info
    /// When: kernel_stats is called twice
    /// Then: the second call returns data that is more up-to-date than the first call
    #[test]
    fn test_kernel_stats_reload() {
        let engine = create_test_engine_and_register();

        let result = engine.eval::<()>(
            r#"
                let system_info = SystemInfo();
                let kernel_stats1 = system_info.kernel_stats();
                let kernel_stats2 = system_info.kernel_stats();

                if (kernel_stats1.boot_time > kernel_stats2.boot_time) {
                    throw "Boot time should not decrease over time";
                }
            "#,
        );

        assert!(
            result.is_ok(),
            "Kernel stats reload test failed: {:?}",
            result.unwrap_err()
        );
    }

    // For testing the getters for cpu_time and total_cpu_time, see `cpu_time_tests`

    // NB: this test is only here to cover the failure path for kernel_stats method. The actual auth logic is already tested in RustSysinfo
    /// Given: an unauthorized user and a SystemInfo object
    /// When: user gets kernel_stats
    /// Then: an authorization error is returned
    #[test]
    fn test_get_kernel_stats_unauthorized() {
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
                let system_info = SystemInfo();
                system_info.kernel_stats();
            "#,
        );
        assert!(
            result.is_err(),
            "Unauthorized user should not be able to get kernel stats"
        );

        let expected_error = format!("Permission denied: {principal} unauthorized to perform");
        assert_error_contains(result, &expected_error);
    }
}
