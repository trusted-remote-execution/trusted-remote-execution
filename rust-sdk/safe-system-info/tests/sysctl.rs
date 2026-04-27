use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::sysctl::actions::SysctlAction;
use rex_cedar_auth::test_utils::{TestCedarAuthBuilder, get_test_rex_principal};
use rex_test_utils::assertions::assert_error_contains;
use rust_safe_system_info::SysctlManager;
use std::process::Command;

#[cfg(target_os = "linux")]
mod sysctl_tests {
    use super::*;

    /// Given: a SysctlManager object
    /// When: read method is called with a valid key and the user is authorized
    /// Then: the parameter value is returned and matches sysctl command output
    #[test]
    fn test_sysctl_read_authorized() {
        let cedar_auth = TestCedarAuthBuilder::default().build().unwrap().create();
        let sysctl = SysctlManager::new().unwrap();

        let result = sysctl.read(&cedar_auth, "kernel.hostname");
        assert!(
            result.is_ok(),
            "read() should return a valid result for kernel.hostname"
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

    /// Given: a SysctlManager object
    /// When: read method is called and the user is not authorized to Open the directory
    /// Then: an error is returned indicating Open action failure
    #[test]
    fn test_sysctl_read_unauthorized_open() {
        let principal = get_test_rex_principal();
        let test_policy = format!(
            r#"
            forbid(
                principal == User::"{principal}",
                action == {},
                resource == file_system::Dir::"/proc/sys/kernel"
            );"#,
            FilesystemAction::Open.to_string()
        );
        let cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy)
            .build()
            .unwrap()
            .create();

        let sysctl = SysctlManager::new().unwrap();
        let result = sysctl.read(&cedar_auth, "kernel.hostname");

        let expected_error = format!(
            "Permission denied: {principal} unauthorized to perform {} for file_system::Dir::/proc/sys/kernel",
            FilesystemAction::Open
        );
        assert_error_contains(result, &expected_error);
    }

    /// Given: a SysctlManager object
    /// When: read method is called and the user is not authorized to Read the file (but can Open directory and file)
    /// Then: an error is returned indicating Read action failure
    #[test]
    fn test_sysctl_read_unauthorized() {
        let principal = get_test_rex_principal();
        let test_policy = format!(
            r#"
            permit(
                principal == User::"{principal}",
                action == {},
                resource in file_system::Dir::"/proc/sys"
            );
            forbid(
                principal == User::"{principal}",
                action == {},
                resource == file_system::File::"/proc/sys/kernel/hostname"
            );"#,
            FilesystemAction::Open.to_string(),
            FilesystemAction::Read.to_string()
        );
        let cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy)
            .build()
            .unwrap()
            .create();

        let sysctl = SysctlManager::new().unwrap();
        let result = sysctl.read(&cedar_auth, "kernel.hostname");

        let expected_error = format!(
            "Permission denied: {principal} unauthorized to perform {} for file_system::File::/proc/sys/kernel/hostname",
            FilesystemAction::Read
        );
        assert_error_contains(result, &expected_error);
    }

    /// Given: a SysctlManager object
    /// When: read method is called and the user is not authorized to Open the file (but can Open directory)
    /// Then: an error is returned indicating file Open action failure
    #[test]
    fn test_sysctl_read_unauthorized_file_open() {
        let principal = get_test_rex_principal();
        let test_policy = format!(
            r#"
            permit(
                principal == User::"{principal}",
                action == {},
                resource == file_system::Dir::"/proc/sys/kernel"
            );
            forbid(
                principal == User::"{principal}",
                action == {},
                resource == file_system::File::"/proc/sys/kernel"
            );"#,
            FilesystemAction::Open.to_string(),
            FilesystemAction::Open.to_string()
        );
        let cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy)
            .build()
            .unwrap()
            .create();

        let sysctl = SysctlManager::new().unwrap();
        let result = sysctl.read(&cedar_auth, "kernel.hostname");

        let expected_error = format!(
            "Permission denied: {principal} unauthorized to perform {} for file_system::File::/proc/sys/kernel/hostname",
            FilesystemAction::Open
        );
        assert_error_contains(result, &expected_error);
    }

    /// Given: a SysctlManager object
    /// When: load_system method is called and the user is not authorized
    /// Then: an error is returned indicating Load action failure
    #[test]
    fn test_sysctl_load_system_unauthorized() {
        let principal = get_test_rex_principal();
        let test_policy = format!(
            r#"
            forbid(
                principal == User::"{principal}",
                action == {},
                resource
            );"#,
            SysctlAction::Load.to_string()
        );
        let cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy)
            .build()
            .unwrap()
            .create();

        let sysctl = SysctlManager::new().unwrap();
        let result = sysctl.load_system(&cedar_auth);

        let expected_error = format!(
            "Permission denied: {principal} unauthorized to perform {}",
            SysctlAction::Load
        );
        assert_error_contains(result, &expected_error);
    }

    /// Given: SysctlManager with authorized Cedar context
    /// When: find() is called with "kernel/hostname" pattern
    /// Then: Returns the hostname parameter and value matches read()
    #[test]
    fn test_sysctl_find_specific_parameter() {
        let cedar_auth = TestCedarAuthBuilder::default().build().unwrap().create();
        let sysctl = SysctlManager::new().unwrap();

        let results = sysctl.find(&cedar_auth, "kernel/hostname").unwrap();

        assert_eq!(results.len(), 1, "Should find exactly one parameter");
        assert_eq!(results[0].key(), "kernel.hostname");

        // Validate value matches direct read
        let direct_value = sysctl.read(&cedar_auth, "kernel.hostname").unwrap();
        assert_eq!(results[0].value(), &direct_value);
    }

    /// Given: SysctlManager with authorized Cedar context
    /// When: find() is called with "kernel/.*" pattern
    /// Then: Returns multiple kernel parameters
    #[test]
    fn test_sysctl_find_kernel_parameters() {
        let cedar_auth = TestCedarAuthBuilder::default().build().unwrap().create();
        let sysctl = SysctlManager::new().unwrap();

        let results = sysctl.find(&cedar_auth, "kernel/.*").unwrap();

        assert!(results.len() > 100, "Should find many kernel parameters");

        // Verify all keys start with "kernel."
        for entry in &results {
            assert!(
                entry.key().starts_with("kernel."),
                "Key {} should start with 'kernel.'",
                entry.key()
            );
        }

        // Verify we can find kernel.hostname in results
        let hostname_entry = results.iter().find(|e| e.key() == "kernel.hostname");
        assert!(hostname_entry.is_some(), "Should find kernel.hostname");
    }

    /// Given: SysctlManager with authorized Cedar context
    /// When: find() is called with "net/ipv4/.*" pattern
    /// Then: Returns multiple IPv4 parameters
    #[test]
    fn test_sysctl_find_ipv4_parameters() {
        let cedar_auth = TestCedarAuthBuilder::default().build().unwrap().create();
        let sysctl = SysctlManager::new().unwrap();

        let results = sysctl.find(&cedar_auth, "net/ipv4/.*").unwrap();

        assert!(results.len() > 50, "Should find many IPv4 parameters");

        // Verify all keys start with "net.ipv4."
        for entry in &results {
            assert!(
                entry.key().starts_with("net.ipv4."),
                "Key {} should start with 'net.ipv4.'",
                entry.key()
            );
        }
    }

    /// Given: SysctlManager with authorized Cedar context
    /// When: find() is called with ".*" pattern
    /// Then: Returns all sysctl parameters
    #[test]
    fn test_sysctl_find_all_parameters() {
        let cedar_auth = TestCedarAuthBuilder::default().build().unwrap().create();
        let sysctl = SysctlManager::new().unwrap();

        let results = sysctl.find(&cedar_auth, ".*").unwrap();

        let has_kernel = results.iter().any(|e| e.key().starts_with("kernel."));
        let has_net = results.iter().any(|e| e.key().starts_with("net."));
        let has_vm = results.iter().any(|e| e.key().starts_with("vm."));

        assert!(has_kernel, "Should have kernel parameters");
        assert!(has_net, "Should have net parameters");
        assert!(has_vm, "Should have vm parameters");
    }

    /// Given: SysctlManager with authorized Cedar context
    /// When: find() is called and a parameter is found
    /// Then: The value from find() matches the value from read()
    #[test]
    fn test_sysctl_find_values_match_read() {
        let cedar_auth = TestCedarAuthBuilder::default().build().unwrap().create();
        let sysctl = SysctlManager::new().unwrap();

        let results = sysctl.find(&cedar_auth, "kernel/.*").unwrap();

        for entry in results.iter().take(5) {
            let direct_value = sysctl.read(&cedar_auth, entry.key()).unwrap();
            assert_eq!(
                entry.value(),
                &direct_value,
                "Value for {} should match between find() and read()",
                entry.key()
            );
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod sysctl_nonlinux_tests {
    use super::*;

    /// Given: a SysctlManager object on a non-Linux system
    /// When: any sysctl method is called
    /// Then: an UnsupportedOperationError is returned
    #[test]
    fn test_sysctl_unsupported_on_nonlinux() {
        let principal = get_test_rex_principal();
        let test_policy = format!(
            r#"
            permit (
                principal == User::"{principal}",
                action,
                resource
            );"#,
        );
        let cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy)
            .build()
            .unwrap()
            .create();
        let sysctl = SysctlManager::new().unwrap();

        let read_result = sysctl.read(&cedar_auth, "kernel.hostname");
        assert!(read_result.is_err());
        assert_error_contains(read_result, "only supported on Linux");

        let write_result = sysctl.write(&cedar_auth, "kernel.hostname", "test");
        assert!(write_result.is_err());
        assert_error_contains(write_result, "only supported on Linux");

        let load_result = sysctl.load_system(&cedar_auth);
        assert!(load_result.is_err());
        assert_error_contains(load_result, "only supported on Linux");

        let find_result = sysctl.find(&cedar_auth, ".*");
        assert!(find_result.is_err());
        assert_error_contains(find_result, "only supported on Linux");
    }
}
