use rex_cedar_auth::sysinfo::actions::SysinfoAction;
use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rex_test_utils::assertions::assert_error_contains;
use rust_system_info::{SystemInfo, open_proc_fd};

/// Given: A SystemInfo object
/// When: The cpu_count method is called and the user is unauthorized
/// Then: An authorization error is returned
#[test]
fn test_cpu_count_unauthorized() -> Result<(), anyhow::Error> {
    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"
            forbid(
                principal,
                action == {},
                resource
            );"#,
        SysinfoAction::List
    );
    let cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let system_info = SystemInfo::new().unwrap();

    let result = system_info.cpu_count(&cedar_auth);

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        SysinfoAction::List
    );
    assert_error_contains(result, &expected_error);
    Ok(())
}

/// Given: A SystemInfo object
/// When: The cpu_count is called and the user is authorized
/// Then: The CPU count is returned and matches std::thread::available_parallelism()
#[test]
fn test_cpu_count_success() -> Result<(), anyhow::Error> {
    let system_info = SystemInfo::new().unwrap();
    let result = system_info.cpu_count(&DEFAULT_TEST_CEDAR_AUTH);

    assert!(
        result.is_ok(),
        "could not call cpu_count successfully: {:?}",
        result.unwrap_err()
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
            cpu_count, proc_cpu_count,
            "CPU count mismatch: ours={} /proc/cpuinfo={}",
            cpu_count, proc_cpu_count
        );
    }

    #[cfg(not(target_os = "linux"))]
    {
        let std_cpu_count = std::thread::available_parallelism()?.get();
        assert_eq!(
            cpu_count, std_cpu_count,
            "CPU count mismatch. If this fails, check if CPU affinity is set: \
         Linux: taskset -p $$, macOS: taskpolicy -c, Windows: Task Manager"
        );
    }

    Ok(())
}
