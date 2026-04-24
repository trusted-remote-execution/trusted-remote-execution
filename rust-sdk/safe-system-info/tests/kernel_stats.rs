#![cfg(target_os = "linux")]

use rex_cedar_auth::{
    fs::actions::FilesystemAction, test_utils::TestCedarAuthBuilder,
    test_utils::get_test_rex_principal,
};
use rex_test_utils::assertions::assert_error_contains;
use rust_system_info::SystemInfo;

use std::time::{SystemTime, UNIX_EPOCH};

/// Given: an authorized user
/// When: a user calls SystemInfo::kernel_stats
/// Then: the kernel stats are returned
#[test]
fn test_system_kernel_stats_authorized() {
    let cedar_auth = TestCedarAuthBuilder::default().build().unwrap().create();

    let system_info = SystemInfo::new().unwrap();

    let kernel_stats_result = system_info.kernel_stats(&cedar_auth);
    assert!(
        kernel_stats_result.is_ok(),
        "kernel_stats() should return a valid result"
    );

    let kernel_stats = kernel_stats_result.unwrap();

    let current_system_time = SystemTime::now();
    let duration_since_epoch = current_system_time.duration_since(UNIX_EPOCH).unwrap();
    let now_timestamp = duration_since_epoch.as_secs();

    // Validate that the kernel stats contain reasonable values
    assert!(
        kernel_stats.btime < now_timestamp,
        "Boot time should be in the past"
    );
}

/// Given: an unauthorized user
/// When: a user calls SystemInfo::kernel_stats
/// Then: an error is returned
#[test]
fn test_system_kernel_stats_unauthorized() {
    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"/proc/stat"
        );"#,
        FilesystemAction::Read.to_string()
    );
    let cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let system_info = SystemInfo::new().unwrap();
    let result = system_info.kernel_stats(&cedar_auth);

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Read
    );
    assert_error_contains(result, &expected_error);
}
