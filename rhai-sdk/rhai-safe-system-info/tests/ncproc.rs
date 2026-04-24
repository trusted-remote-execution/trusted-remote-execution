use rex_cedar_auth::test_utils::{DEFAULT_TEST_CEDAR_AUTH, get_test_rex_principal};
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::rhai::common::create_test_engine_and_register;
use rust_system_info::open_proc_fd;

mod common;
use common::create_test_engine_and_register_with_policy;

/// Given: An unauthorized user and a SystemInfo object
/// When: cpu_count method is called
/// Then: An authorization error is returned
#[test]
fn test_cpu_count_unauthorized() -> Result<(), anyhow::Error> {
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
                system_info.cpu_count();
            "#,
    );

    assert!(
        result.is_err(),
        "Unauthorized user should not be able to get CPU count"
    );

    let expected_error = format!("Permission denied: {principal} unauthorized to perform");
    assert_error_contains(result, &expected_error);
    Ok(())
}

/// Given: A policy that allows system info access
/// When: cpu_count method is called
/// Then: The CPU count is returned and validated
#[test]
fn test_cpu_count_success() -> Result<(), anyhow::Error> {
    let engine = create_test_engine_and_register();

    let result = engine.eval::<i64>(
        r#"
                let system_info = SystemInfo();
                system_info.cpu_count();
            "#,
    );

    assert!(
        result.is_ok(),
        "cpu_count() should return valid CPU count: {:?}",
        result.as_ref().unwrap_err()
    );

    let cpu_count = result.unwrap();

    assert!(
        cpu_count > 0,
        "CPU count should be at least 1, got {}",
        cpu_count
    );
    #[cfg(target_os = "linux")]
    {
        let cpuinfo_handle = open_proc_fd(&DEFAULT_TEST_CEDAR_AUTH, "cpuinfo")?;
        let content = cpuinfo_handle.safe_read(&DEFAULT_TEST_CEDAR_AUTH)?;
        let proc_cpu_count = content
            .lines()
            .filter(|line| line.starts_with("processor"))
            .count();

        assert_eq!(
            cpu_count as usize, proc_cpu_count,
            "CPU count mismatch: ours={} /proc/cpuinfo={}",
            cpu_count, proc_cpu_count
        );
    }

    #[cfg(not(target_os = "linux"))]
    {
        let std_cpu_count = std::thread::available_parallelism()?.get();
        assert_eq!(
            cpu_count as usize, std_cpu_count,
            "CPU count mismatch. If this fails, check if CPU affinity is set: \
                 Linux: taskset -p $$, macOS: taskpolicy -c, Windows: Task Manager"
        );
    }

    Ok(())
}
