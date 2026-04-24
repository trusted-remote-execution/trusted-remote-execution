use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::sysctl::actions::SysctlAction;
use rex_cedar_auth::test_utils::get_test_rex_principal;
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::rhai::common::create_test_engine_and_register;
use std::process::Command;

mod common;
use common::create_test_engine_and_register_with_policy;

#[cfg(target_os = "linux")]
mod sysctl_tests {
    use rhai::{EvalAltResult, Map};

    use super::*;

    /// Given: a SysctlManager object
    /// When: read method is called with a valid sysctl key
    /// Then: the kernel parameter value is returned and matches sysctl command output
    #[test]
    fn test_sysctl_read_success() {
        let engine = create_test_engine_and_register();

        let result = engine.eval::<String>(
            r#"
                let sysctl = SysctlManager();
                let hostname = sysctl.read("kernel.hostname");
                
                if hostname.is_empty() {
                    throw "Hostname should not be empty";
                }
                
                hostname
            "#,
        );

        assert!(
            result.is_ok(),
            "read() should return kernel parameter value: {:?}",
            result.unwrap_err()
        );

        let hostname = result.unwrap();
        assert!(!hostname.is_empty(), "Hostname should not be empty");

        let sysctl_output = Command::new("/usr/sbin/sysctl")
            .arg("-n")
            .arg("kernel.hostname")
            .output()
            .expect("Failed to execute sysctl command");

        let expected_hostname = String::from_utf8_lossy(&sysctl_output.stdout)
            .trim()
            .to_string();

        assert_eq!(
            hostname, expected_hostname,
            "Hostname from read() should match sysctl command output"
        );
    }

    // NB: this test is only here to cover the failure path for read method. The actual auth logic is already tested in RustSysinfo
    /// Given: an unauthorized user and a SysctlManager object
    /// When: user tries to read a sysctl parameter
    /// Then: an authorization error is returned
    #[test]
    fn test_sysctl_read_unauthorized() {
        let principal = get_test_rex_principal();
        let policy_forbid_read = format!(
            r#"
            permit(
                principal == User::"{principal}",
                action,
                resource
            );
            forbid(
                principal == User::"{principal}",
                action == {},
                resource == file_system::File::"/proc/sys/kernel/hostname"
            );
            forbid(
                principal,
                action == file_system::Action::"redacted_read",
                resource
            );
            "#,
            FilesystemAction::Read.to_string()
        );

        let engine = create_test_engine_and_register_with_policy(&policy_forbid_read);
        let result = engine.eval::<()>(
            r#"
                let sysctl = SysctlManager();
                sysctl.read("kernel.hostname");
            "#,
        );

        assert!(
            result.is_err(),
            "Unauthorized user should not be able to read sysctl parameters"
        );

        let expected_error = format!("Permission denied: {principal} unauthorized to perform");
        assert_error_contains(result, &expected_error);
    }

    // NB: This test only validates Rhai registration. CAP_SETUID requirement prevents
    // execution from reaching Cedar authorization check. Full Cedar authorization testing
    // is performed in Cedar Test Suite
    /// Given: an unauthorized user and a SysctlManager object
    /// When: user tries to write a sysctl parameter
    /// Then: an authorization error is returned
    #[test]
    fn test_sysctl_write_unauthorized() {
        let principal = get_test_rex_principal();
        let policy_forbid_write = format!(
            r#"
            permit(
                principal == User::"{principal}",
                action,
                resource
            );
            forbid(
                principal == User::"{principal}",
                action == {},
                resource == file_system::File::"/proc/sys/kernel/perf_event_mlock_kb"
            );
            "#,
            FilesystemAction::Write.to_string()
        );

        let engine = create_test_engine_and_register_with_policy(&policy_forbid_write);
        let result = engine.eval::<()>(
            r#"
                let sysctl = SysctlManager();
                sysctl.write("kernel.perf_event_mlock_kb", "2048");
            "#,
        );

        assert!(
            result.is_err(),
            "Test validates registration only. CAP_SETUID requirement prevents full execution."
        );

        // Note: Test fails at CAP_SETUID requirement before Cedar authorization is checked.
        // Cedar authorization is validated in Cedar Test Suite.
        let display_string = format!("{}", result.unwrap_err());
        assert!(
            display_string.contains("Operation not permitted"),
            "Expected CAP_SETUID error, got: {display_string}"
        );
    }

    // NB: this test is only here to cover the failure path for load_system method.
    // Success case requires CAP_SETUID capability which is not available in test environment
    /// Given: an unauthorized user and a SysctlManager object
    /// When: user tries to load system sysctl configuration
    /// Then: an authorization error is returned
    #[test]
    fn test_sysctl_load_system_unauthorized() {
        let principal = get_test_rex_principal();
        let policy_forbid_load = format!(
            r#"
            permit(
                principal == User::"{principal}",
                action,
                resource
            );
            forbid(
                principal == User::"{principal}",
                action == {},
                resource
            );
            "#,
            SysctlAction::Load.to_string()
        );

        let engine = create_test_engine_and_register_with_policy(&policy_forbid_load);
        let result = engine.eval::<()>(
            r#"
                let sysctl = SysctlManager();
                sysctl.load_system();
            "#,
        );

        assert!(
            result.is_err(),
            "Unauthorized user should not be able to load system sysctl configuration"
        );

        let expected_error = format!("Permission denied: {principal} unauthorized to perform");
        assert_error_contains(result, &expected_error);
    }

    /// Given: a SysctlManager object
    /// When: find method is called with a valid pattern
    /// Then: returns array of SysctlEntry objects with key and value matching sysctl command
    #[test]
    fn test_sysctl_find_success() {
        let engine = create_test_engine_and_register();

        let result = engine.eval::<String>(
            r#"
                let sysctl = SysctlManager();
                let results = sysctl.find("kernel/hostname");
                
                if results.is_empty() {
                    throw "Should find kernel.hostname parameter";
                }
                
                // Verify first entry has key and value
                let entry = results[0];
                if entry.key != "kernel.hostname" {
                    throw "Key should be kernel.hostname";
                }
                
                if entry.value.is_empty() {
                    throw "Value should not be empty";
                }
                
                entry.value
            "#,
        );

        assert!(
            result.is_ok(),
            "find() should return results: {:?}",
            result.unwrap_err()
        );

        let hostname_value = result.unwrap();

        // Validate value matches sysctl command
        let sysctl_output = Command::new("/usr/sbin/sysctl")
            .arg("-n")
            .arg("kernel.hostname")
            .output()
            .expect("Failed to execute sysctl command");

        let expected_hostname = String::from_utf8_lossy(&sysctl_output.stdout)
            .trim()
            .to_string();

        assert_eq!(
            hostname_value, expected_hostname,
            "Value from find() should match sysctl command output"
        );
    }

    /// Given: a SysctlEntry
    /// When: to_map is called
    /// Then: the value is equal to expected
    #[test]
    fn test_sysctl_entry_to_map() -> Result<(), Box<EvalAltResult>> {
        let engine = create_test_engine_and_register();

        let result = engine.eval::<Map>(
            r#"
                let sysctl = SysctlManager();
                let result = sysctl.find("kernel/hostname")[0];
                let expected = #{
                    "key": result.key,
                    "value": result.value
                };

                #{
                    "expected": expected.to_json(),
                    "actual": result.to_map().to_json()
                }
            "#,
        )?;

        let expected: String = result.get("expected").unwrap().clone().into_string()?;
        let actual: String = result.get("actual").unwrap().clone().into_string()?;
        assert_eq!(expected, actual);

        Ok(())
    }

    // NB: this test is only here to cover the failure path for find method. The actual auth logic is already tested in RustSafeIO
    /// Given: an unauthorized user and a SysctlManager object
    /// When: user tries to find sysctl parameters
    /// Then: an authorization error is returned
    #[test]
    fn test_sysctl_find_unauthorized() {
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
                let sysctl = SysctlManager();
                sysctl.find("kernel/.*");
            "#,
        );

        assert!(
            result.is_err(),
            "Unauthorized user should not be able to find sysctl parameters"
        );

        let expected_error = format!("Permission denied: {principal} unauthorized");
        assert_error_contains(result, &expected_error);
    }

    /// Given: Cedar policy forbids reading kernel.hostname file
    /// When: find() is called with pattern that would match kernel.hostname
    /// Then: Operation succeeds but returns empty results (file is skipped)
    #[test]
    fn test_sysctl_find_skips_unauthorized_file() {
        let principal = get_test_rex_principal();
        let policy_forbid_hostname = format!(
            r#"
            permit(
                principal == User::"{principal}",
                action,
                resource
            );
            forbid(
                principal == User::"{principal}",
                action == {},
                resource == file_system::File::"/proc/sys/kernel/hostname"
            );
            "#,
            FilesystemAction::Read.to_string()
        );

        let engine = create_test_engine_and_register_with_policy(&policy_forbid_hostname);

        let result = engine.eval::<rhai::Array>(
            r#"
                let sysctl = SysctlManager();
                let results = sysctl.find("kernel/hostname");
                
                // Should succeed but return empty results
                if !results.is_empty() {
                    throw "Should not find kernel.hostname when read is forbidden";
                }
                
                results
            "#,
        );

        assert!(
            result.is_ok(),
            "find() should succeed even when file is unauthorized: {:?}",
            result.unwrap_err()
        );
    }
}
