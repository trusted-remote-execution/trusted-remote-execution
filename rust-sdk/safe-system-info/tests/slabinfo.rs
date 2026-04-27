#![cfg(target_os = "linux")]

use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_test_utils::assertions::assert_error_contains;
use rust_safe_io::errors::RustSafeIoError;
use rust_safe_system_info::SystemInfo;
use std::io::ErrorKind;

mod slabinfo_tests {
    use rex_cedar_auth::test_utils::{TestCedarAuthBuilder, get_test_rex_principal};

    use super::*;

    /// Given: a system_info object
    /// When: slab_info method is called and the user is authorized
    /// Then: an error is returned due to missing CAP_DAC_READ_SEARCH capability
    #[test]
    fn test_system_slab_info_authorized_but_no_capability() {
        let cedar_auth = TestCedarAuthBuilder::default().build().unwrap().create();

        let mut system_info = SystemInfo::new().unwrap();

        let slabinfo_result = system_info.slab_info(&cedar_auth);

        assert!(
            slabinfo_result.is_err(),
            "slab_info() should fail without CAP_DAC_READ_SEARCH capability"
        );

        match slabinfo_result.unwrap_err() {
            rust_safe_system_info::RustSysteminfoError::SafeIoError(RustSafeIoError::IoError(
                io_error,
            )) => {
                assert_eq!(io_error.raw_os_error(), Some(13));
                assert_eq!(io_error.kind(), ErrorKind::PermissionDenied);
                assert!(io_error.to_string().contains("Permission denied"));
            }
            error => {
                assert!(false, "Expected SafeIoError, got: {:?}", error);
            }
        }
    }

    /// Given: a system_info object
    /// When: slab_info method is called and the user is not authorized
    /// Then: an authorization error is returned
    #[test]
    fn test_system_slab_info_unauthorized() {
        let principal = get_test_rex_principal();
        let test_policy = format!(
            r#"
            forbid(
                principal == User::"{principal}",
                action == {},
                resource == file_system::Dir::"/proc"
            );"#,
            FilesystemAction::Open.to_string()
        );
        let cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy)
            .build()
            .unwrap()
            .create();

        let mut system_info = SystemInfo::new().unwrap();
        let result = system_info.slab_info(&cedar_auth);

        let expected_error = format!(
            "Permission denied: {principal} unauthorized to perform {}",
            FilesystemAction::Open
        );
        assert_error_contains(result, &expected_error);
    }
}
