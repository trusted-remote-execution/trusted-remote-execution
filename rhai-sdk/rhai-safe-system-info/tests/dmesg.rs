#![cfg(target_os = "linux")]
use rex_cedar_auth::test_utils::get_test_rex_principal;
use rex_test_utils::assertions::assert_error_contains;

mod common;
use common::create_test_engine_and_register_with_policy;

mod dmesg_info_tests {
    use super::*;

    // dmesg_restrict is set on build hosts so we can't unit test the dmesg success case. There are integration tests covering this.

    /// Given: an unauthorized user and a SystemInfo object
    /// When: dmesg_info method is called with default options
    /// Then: an authorization error is returned
    #[test]
    fn test_get_dmesg_info_unauthorized() {
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
                system_info.dmesg_info(DmesgOptions().build());
            "#,
        );

        assert!(
            result.is_err(),
            "Unauthorized user should not be able to get dmesg info"
        );

        let expected_error = format!("Permission denied: {principal} unauthorized to perform");
        assert_error_contains(result, &expected_error);
    }
}
