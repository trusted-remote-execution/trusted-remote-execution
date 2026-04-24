use rex_cedar_auth::test_utils::get_test_rex_principal;
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::rhai::common::create_test_engine_and_register;

mod common;
use common::create_test_engine_and_register_with_policy;

use rhai::{EvalAltResult, Map};

mod memory_info_tests {
    use super::*;

    /// Given: a SystemInfo object
    /// When: memory_info method is called
    /// Then: a meminfo struct is returned and it is valid
    #[test]
    fn test_get_memory_info() {
        let engine = create_test_engine_and_register();

        let result = engine.eval::<()>(
            r#"
                let system_info = SystemInfo();
                let meminfo = system_info.memory_info();
                
                // Validate that meminfo has expected properties
                let total = meminfo.total;
                let free = meminfo.free;
                let available = meminfo.available;
                let used = meminfo.used;
                
                if (total < free) {
                    throw "Total memory should be >= free memory";
                }
                
                if (total < available) {
                    throw "Total memory should be >= available memory";
                }
                
                if (used != (total - available)) {
                    throw "Used memory should equal total - available";
                }
            "#,
        );

        assert!(
            result.is_ok(),
            "meminfo() should return valid memory information: {:?}",
            result.unwrap_err()
        );
    }

    /// Given: a SystemInfo object on Linux
    /// When: memory_info method is called
    /// Then: Linux-specific fields are available
    #[test]
    #[cfg(target_os = "linux")]
    fn test_get_memory_info_linux() {
        let engine = create_test_engine_and_register();

        let result = engine.eval::<()>(
            r#"
                let system_info = SystemInfo();
                let meminfo = system_info.memory_info();
                
                // Validate Linux-specific fields
                let buffers = meminfo.buffers;
                let cached = meminfo.cached;
                let shared_mem = meminfo.shared_mem;
                let total = meminfo.total;
                let available = meminfo.available;
                
                if (buffers > available) {
                    throw "Buffers should be <= available memory";
                }
                
                if (cached > total) {
                    throw "Cached should be <= total memory";
                }
                
                if (shared_mem > total) {
                    throw "Shared should be <= total memory";
                }
            "#,
        );

        assert!(
            result.is_ok(),
            "Linux-specific meminfo fields should be valid: {:?}",
            result.unwrap_err()
        );
    }

    /// Given: a Meminfo struct
    /// When: to_map() method is called
    /// Then: a Map with the Meminfo fields is returned with correct values
    #[test]
    #[cfg(target_os = "linux")]
    fn test_mem_info_to_map() -> Result<(), Box<EvalAltResult>> {
        let engine = create_test_engine_and_register();

        let result = engine.eval::<Map>(
            r#"
                let system_info = SystemInfo();
                let mem_info = system_info.memory_info();

                let expected = #{
                    "total": mem_info.total.to_int(),
                    "free": mem_info.free.to_int(),
                    "available": mem_info.available.to_int(),
                    "used": mem_info.used.to_int(),
                    "shared_mem": mem_info.shared_mem.to_int(),
                    "buffers": mem_info.buffers.to_int(),
                    "cached": mem_info.cached.to_int()
                };

                #{
                    "expected": expected.to_json(),
                    "actual": mem_info.to_map().to_json()
                }
            "#,
        )?;

        let expected: String = result.get("expected").unwrap().clone().into_string()?;
        let actual: String = result.get("actual").unwrap().clone().into_string()?;
        assert_eq!(expected, actual);

        Ok(())
    }

    // NB: this test is only here to cover the failure path for memory_info method. The actual auth logic is already tested in RustSysinfo
    /// Given: an unauthorized user and a SystemInfo object
    /// When: user gets memory info
    /// Then: an authorization error is returned
    #[test]
    fn test_get_memory_info_unauthorized() {
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
                system_info.memory_info();
            "#,
        );
        assert!(
            result.is_err(),
            "Unauthorized user should not be able to get memory info"
        );

        let expected_error = format!("Permission denied: {principal} unauthorized to perform");
        assert_error_contains(result, &expected_error);
    }
}

mod swap_info_tests {
    use super::*;

    /// Given: a system_info object
    /// When: swap_info method is called
    /// Then: a swapinfo struct is returned and it is valid
    #[test]
    fn test_get_swap_info() {
        let engine = create_test_engine_and_register();

        let result = engine.eval::<()>(
            r#"
                let system_info = SystemInfo();
                let swapinfo = system_info.swap_info();
                
                // Validate that swapinfo has expected properties
                let total = swapinfo.total;
                let free = swapinfo.free;
                let used = swapinfo.used;
                
                // Note: total swap can be 0 on systems without swap configured
                if (total < free) {
                    throw "Total swap should be >= free swap";
                }
                
                if (used != (total - free)) {
                    throw "Used swap should equal total - free";
                }
            "#,
        );

        assert!(
            result.is_ok(),
            "swapinfo() should return valid swap information: {:?}",
            result.unwrap_err()
        );
    }

    // NB: this test is only here to cover the failure path for swap_info method. The actual auth logic is already tested in RustSysinfo
    /// Given: an unauthorized user and a SystemInfo object
    /// When: user gets swap info
    /// Then: an authorization error is returned
    #[test]
    fn test_get_swap_info_unauthorized() {
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
                system_info.swap_info();
            "#,
        );
        assert!(
            result.is_err(),
            "Unauthorized user should not be able to get swapinfo"
        );

        let expected_error = format!("Permission denied: {principal} unauthorized to perform");
        assert_error_contains(result, &expected_error);
    }

    /// Given: a SwapInfo struct
    /// When: to_map() method is called
    /// Then: a Map with the SwapInfo fields is returned with correct values
    #[test]
    fn test_swap_info_to_map() -> Result<(), Box<EvalAltResult>> {
        let engine = create_test_engine_and_register();

        let result = engine.eval::<Map>(
            r#"
                let system_info = SystemInfo();
                let swap_info = system_info.swap_info();

                let expected = #{
                    "total": swap_info.total.to_int(),
                    "free": swap_info.free.to_int(),
                    "used": swap_info.used.to_int()
                };

                #{
                    "expected": expected.to_json(),
                    "actual": swap_info.to_map().to_json()
                }
            "#,
        )?;

        let expected: String = result.get("expected").unwrap().clone().into_string()?;
        let actual: String = result.get("actual").unwrap().clone().into_string()?;
        assert_eq!(expected, actual);

        Ok(())
    }
}
