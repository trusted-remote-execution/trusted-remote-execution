#![cfg(target_os = "linux")]
use rex_cedar_auth::test_utils::get_test_rex_principal;
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::rhai::common::create_test_engine_and_register;

mod common;
use common::create_test_engine_and_register_with_policy;

mod slabinfo_tests {
    use super::*;

    /// Given: a SystemInfo object
    /// When: slab_info method is called and user is authorized but lacks capability
    /// Then: an error is returned due to missing CAP_DAC_READ_SEARCH capability
    #[test]
    fn test_get_slab_info_authorized_but_no_capability() {
        let engine = create_test_engine_and_register();

        let result = engine.eval::<()>(
            r#"
                let system_info = SystemInfo();
                system_info.slab_info();
            "#,
        );

        assert!(
            result.is_err(),
            "slab_info() should fail without CAP_DAC_READ_SEARCH capability"
        );

        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Permission denied (os error 13)"),
            "Expected permission error - OS error code 13, got: {}",
            error_msg
        );
    }

    /// Given: an unauthorized user and a SystemInfo object
    /// When: user gets slab info
    /// Then: an authorization error is returned
    #[test]
    fn test_get_slab_info_unauthorized() {
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
                system_info.slab_info();
            "#,
        );

        assert!(
            result.is_err(),
            "Unauthorized user should not be able to get slab info"
        );

        let expected_error = format!("Permission denied: {principal} unauthorized to perform");
        assert_error_contains(result, &expected_error);
    }
}
