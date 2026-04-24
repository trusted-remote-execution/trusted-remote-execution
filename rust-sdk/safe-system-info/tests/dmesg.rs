#![cfg(target_os = "linux")]
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{TestCedarAuthBuilder, get_test_rex_principal};
use rex_test_utils::assertions::assert_error_contains;
use rust_system_info::{SystemInfo, options::DmesgOptionsBuilder};

mod dmesg_tests {
    use super::*;

    // dmesg_restrict is set on build hosts so we can't unit test the dmesg success case. There are integration tests covering this.

    /// Given: a system_info object
    /// When: dmesg_info method is called and the user is not authorized
    /// Then: an authorization error is returned
    #[test]
    #[cfg(target_os = "linux")]
    fn test_system_dmesg_info_unauthorized() {
        let principal = get_test_rex_principal();
        let test_policy = format!(
            r#"
            forbid(
                principal == User::"{principal}",
                action == {},
                resource == file_system::File::"/dev/kmsg"
            );"#,
            FilesystemAction::Read
        );
        let cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy)
            .build()
            .unwrap()
            .create();

        let system_info = SystemInfo::new().unwrap();

        let dmesg_options = DmesgOptionsBuilder::default()
            .human_readable_time(false)
            .build()
            .unwrap();

        let result = system_info.dmesg_info(&cedar_auth, dmesg_options);

        let expected_error = format!(
            "Permission denied: {principal} unauthorized to perform {}",
            FilesystemAction::Read
        );
        assert_error_contains(result, &expected_error);
    }

    /// Given: a system_info object on non-Linux platform
    /// When: dmesg_info method is called
    /// Then: returns UnsupportedOperationError
    #[test]
    #[cfg(not(target_os = "linux"))]
    fn test_system_dmesg_info_non_linux_platform() {
        let cedar_auth = TestCedarAuthBuilder::default().build().unwrap().create();

        let mut system_info = SystemInfo::new().unwrap();

        let dmesg_options = DmesgOptionsBuilder::default()
            .human_readable_time(false)
            .build()
            .unwrap();

        let result = system_info.dmesg_info(&cedar_auth, dmesg_options);

        assert_error_contains(
            result,
            "dmesg functionality is only available on Linux systems",
        )
    }
}
