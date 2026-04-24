#![cfg(target_os = "linux")]
use rex_cedar_auth::sysinfo::actions::SysinfoAction;
use rex_cedar_auth::test_utils::{TestCedarAuthBuilder, get_test_rex_principal};
use rex_test_utils::assertions::assert_error_contains;
use rust_system_info::SystemInfo;
use std::process::Command;

mod uname_tests {
    use core::assert;

    use super::*;

    /// Given: System action
    /// When: uname_info method and the sysinfo action is always forbidden
    /// Then: an authorization error is returned
    #[test]
    #[cfg(target_os = "linux")]
    fn test_system_uname_info_unauthorized() {
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

        let result = system_info.uname_info(&cedar_auth);

        let expected_error = format!(
            "Permission denied: {principal} unauthorized to perform {}",
            SysinfoAction::List
        );
        assert_error_contains(result, &expected_error);
    }

    /// Given: System action
    /// When: uname_info method is called and the user is not authorized
    /// Then: an authorization error is returned
    #[test]
    #[cfg(target_os = "linux")]
    fn test_system_uname_info_user_unauthorized() {
        let principal = get_test_rex_principal();
        let test_policy = format!(
            r#"
            permit (
                principal == User::"randouser",
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

        let result = system_info.uname_info(&cedar_auth);

        let expected_error = format!(
            "Permission denied: {principal} unauthorized to perform {}",
            SysinfoAction::List
        );
        assert_error_contains(result, &expected_error);
    }

    /// Given: a system_info object
    /// When: uname_info method is called and the user is authorized
    /// Then: a SysinfoInfo struct is returned and it matches system uname output
    #[test]
    fn test_uname() {
        let principal = get_test_rex_principal();
        let test_policy = format!(
            r#"
            permit (
                principal == User::"{principal}",
                action == {},
                resource
            );"#,
            SysinfoAction::List
        );
        let cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy.clone())
            .build()
            .unwrap()
            .create();

        let system_info = SystemInfo::new().unwrap();
        let result = system_info.uname_info(&cedar_auth);
        assert!(
            result.is_ok(),
            "could not call uname_info successfully: {:?}",
            result.unwrap_err()
        );

        let our_uname = result.unwrap();

        // Test each field against system uname command
        let uname_commands = [
            ("-s", our_uname.kernel_name()),    // kernel name
            ("-n", our_uname.nodename()),       // node name
            ("-r", our_uname.kernel_release()), // kernel release
            ("-v", our_uname.kernel_version()), // kernel version
            ("-m", our_uname.machine()),        // machine
            ("-a", &our_uname.to_string()),     // machine
        ];

        for (flag, our_value) in uname_commands {
            let output = Command::new("uname")
                .args(&[flag])
                .output()
                .expect(&format!("Failed to execute uname {}", flag));

            let system_value = String::from_utf8(output.stdout)
                .expect("Invalid UTF-8 from uname command")
                .trim()
                .to_string();

            assert_eq!(
                our_value, &system_value,
                "Mismatch for uname {}: ours='{}' system='{}'",
                flag, our_value, system_value
            );
        }
    }
}
