#![cfg(target_os = "linux")]
use rex_cedar_auth::sysinfo::actions::SysinfoAction;
use rex_cedar_auth::test_utils::get_test_rex_principal;
use rex_test_utils::assertions::assert_error_contains;
use rust_system_info::UnameInfo;

mod common;
use common::create_test_engine_and_register_with_policy;

mod uname_info_tests {
    use rhai::{EvalAltResult, Map};

    use super::*;

    /// Given: an unauthorized user and a SystemInfo object
    /// When: uname_info method is called
    /// Then: an authorization error is returned
    #[test]
    fn test_get_uname_info_unauthorized() {
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
                system_info.uname_info();
            "#,
        );

        assert!(
            result.is_err(),
            "Unauthorized user should not be able to get uname info"
        );

        let expected_error = format!("Permission denied: {principal} unauthorized to perform");
        assert_error_contains(result, &expected_error);
    }

    /// Given: A policy that allows uname info
    /// When: uname_info method is called
    /// Then: the info is returned
    #[test]
    fn test_get_uname_info_success() {
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

        let engine = create_test_engine_and_register_with_policy(&test_policy);
        let result = engine.eval::<UnameInfo>(
            r#"
                let system_info = SystemInfo();
                system_info.uname_info();
            "#,
        );

        assert!(
            result.is_ok(),
            "uname_info() should return valid uname information: {:?}",
            result.unwrap_err()
        );

        let result = engine.eval::<String>(
            r#"
                let system_info = SystemInfo();
                let uname = system_info.uname_info();
                let v = uname.processor;
                let v = uname.nodename;
                let v = uname.kernel_release;
                let v = uname.kernel_version;
                let v = uname.machine;
                let v = uname.hardware_platform;
                let v = uname.operating_system;
                uname.to_string();
            "#,
        );
        assert!(
            result.is_ok(),
            "uname_info() getters had issues: {:?}",
            result.unwrap_err()
        );
        assert!(result.unwrap().contains("GNU/Linux"));
    }

    /// Given: unameInfo
    /// When: to_map is called on it
    /// Then: the map matches expected
    #[test]
    fn test_get_uname_info_to_map() -> Result<(), Box<EvalAltResult>> {
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

        let engine = create_test_engine_and_register_with_policy(&test_policy);
        let result = engine.eval::<Map>(
            r#"
                let system_info = SystemInfo();
                let uname = system_info.uname_info();
                let expected = #{
                    "kernel_name": uname.kernel_name,
                    "nodename": uname.nodename,
                    "kernel_release": uname.kernel_release,
                    "kernel_version": uname.kernel_version,
                    "machine": uname.machine,
                    "hardware_platform": uname.hardware_platform,
                    "operating_system": uname.operating_system,
                    "processor": uname.processor,
                };

                #{
                    "expected": expected.to_json(),
                    "actual": uname.to_map().to_json(),
                }
            "#,
        )?;

        let expected: String = result.get("expected").unwrap().clone().into_string()?;
        let actual: String = result.get("actual").unwrap().clone().into_string()?;
        assert_eq!(expected, actual);

        Ok(())
    }
}
