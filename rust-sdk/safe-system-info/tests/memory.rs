use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{TestCedarAuthBuilder, get_test_rex_principal};
use rex_test_utils::assertions::assert_error_contains;
use rust_system_info::SystemInfo;

mod meminfo_tests {

    use super::*;

    /// Given: a system_info object
    /// When: memory_info method is called and the user is authorized
    /// Then: a meminfo struct is returned and it is valid
    #[test]
    fn test_system_memory_info_authorized() {
        let cedar_auth = TestCedarAuthBuilder::default().build().unwrap().create();

        let mut system_info = SystemInfo::new().unwrap();

        let meminfo_result = system_info.memory_info(&cedar_auth);
        assert!(
            meminfo_result.is_ok(),
            "meminfo() should return a valid result"
        );

        let meminfo = meminfo_result.unwrap();

        assert!(
            *meminfo.total() > 0,
            "Total memory should be greater than 0"
        );
        assert!(
            meminfo.total() >= meminfo.free(),
            "Total memory should be >= free memory"
        );
        assert!(
            meminfo.total() >= meminfo.available(),
            "Total memory should be >= available memory"
        );

        let used = meminfo.used();
        assert_eq!(
            used,
            meminfo.total() - meminfo.available(),
            "used() should equal total - available"
        );

        // Linux-specific fields
        #[cfg(target_os = "linux")]
        {
            assert!(
                meminfo.buffers() <= meminfo.available(),
                "Buffers should be less than available"
            );
            assert!(
                meminfo.cached() <= meminfo.total(),
                "Cached should be less than total"
            );
            assert!(
                meminfo.shared() <= meminfo.total(),
                "Shared should be less than total"
            );
        }
    }

    /// Given: a system_info object
    /// When: memory_info method is called and the user is not authorized
    /// Then: an error is returned
    #[test]
    fn test_system_memory_info_unauthorized() {
        let principal = get_test_rex_principal();
        let test_policy = format!(
            r#"
            forbid(
                principal == User::"{principal}",
                action == {},
                resource == file_system::File::"/proc/meminfo"
            );"#,
            FilesystemAction::Read.to_string()
        );
        let cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy)
            .build()
            .unwrap()
            .create();

        let mut system_info = SystemInfo::new().unwrap();
        let result = system_info.memory_info(&cedar_auth);

        let expected_error = format!(
            "Permission denied: {principal} unauthorized to perform {}",
            FilesystemAction::Read
        );
        assert_error_contains(result, &expected_error);
    }

    /// Given: a memory object
    /// When: meminfo method is called multiple times
    /// Then: the two meminfo objects are consistent
    #[test]
    fn test_memory_info_reload() {
        let cedar_auth = TestCedarAuthBuilder::default().build().unwrap().create();

        let mut system_info = SystemInfo::new().unwrap();

        let meminfo1 = system_info
            .memory_info(&cedar_auth)
            .expect("First meminfo call should succeed");
        let meminfo2 = system_info
            .memory_info(&cedar_auth)
            .expect("Second meminfo call should succeed");

        assert_eq!(
            meminfo1.total(),
            meminfo2.total(),
            "Total memory should be consistent between calls"
        );
    }

    /// Given: a memory object
    /// When: Display trait is used on meminfo
    /// Then: the output contains expected information
    #[test]
    fn test_meminfo_display_implementation() {
        let cedar_auth = TestCedarAuthBuilder::default().build().unwrap().create();

        let mut system_info = SystemInfo::new().unwrap();
        let meminfo = system_info
            .memory_info(&cedar_auth)
            .expect("meminfo call should succeed");

        let meminfo_display = format!("{}", meminfo);
        assert!(meminfo_display.contains("Memory Info:"));
        assert!(meminfo_display.contains("Total:"));
        assert!(meminfo_display.contains("Free:"));
        assert!(meminfo_display.contains("Available:"));
        assert!(meminfo_display.contains("Used:"));
        assert!(meminfo_display.contains("bytes"));

        // On Linux, should also contain additional fields
        #[cfg(target_os = "linux")]
        {
            assert!(meminfo_display.contains("Buffers:"));
            assert!(meminfo_display.contains("Cached:"));
            assert!(meminfo_display.contains("Shared:"));
        }

        // Verify the displayed values match the actual values
        assert!(meminfo_display.contains(&meminfo.total().to_string()));
        assert!(meminfo_display.contains(&meminfo.free().to_string()));
        assert!(meminfo_display.contains(&meminfo.available().to_string()));
        assert!(meminfo_display.contains(&meminfo.used().to_string()));
    }
}

mod swapinfo_tests {
    use super::*;

    /// Given: a system_info object
    /// When: swap_info method is called and the user is authorized
    /// Then: a swapinfo struct is returned and it is valid
    #[test]
    fn test_system_swap_info_authorized() {
        let cedar_auth = TestCedarAuthBuilder::default().build().unwrap().create();

        let mut system_info = SystemInfo::new().unwrap();

        let swapinfo_result = system_info.swap_info(&cedar_auth);
        assert!(
            swapinfo_result.is_ok(),
            "swapinfo() should return a valid result"
        );

        let swapinfo = swapinfo_result.unwrap();

        // Validate that the swapinfo struct contains reasonable values
        // Note: total swap can be 0 on systems without swap configured
        assert!(
            swapinfo.total() >= swapinfo.free(),
            "Total swap should be >= free swap"
        );

        // Test the calculated used() method
        let used = swapinfo.used();
        assert_eq!(
            used,
            swapinfo.total() - swapinfo.free(),
            "used() should equal total - free"
        );
    }

    /// Given: a system_info object
    /// When: memory_info method is called and the user is not authorized
    /// Then: an error is returned
    #[test]
    fn test_system_swap_info_unauthorized() {
        let principal = get_test_rex_principal();
        let test_policy = format!(
            r#"
            forbid(
                principal == User::"{principal}",
                action == {},
                resource == file_system::File::"/proc/meminfo"
            );"#,
            FilesystemAction::Read.to_string()
        );
        let cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy)
            .build()
            .unwrap()
            .create();

        let mut system_info = SystemInfo::new().unwrap();
        let result = system_info.swap_info(&cedar_auth);

        let expected_error = format!(
            "Permission denied: {principal} unauthorized to perform {}",
            FilesystemAction::Read
        );
        assert_error_contains(result, &expected_error);
    }

    /// Given: a memory object
    /// When: swapinfo method is called multiple times
    /// Then: the two swapinfo objects are consistent    
    #[test]
    fn test_swap_info_reload() {
        let cedar_auth = TestCedarAuthBuilder::default().build().unwrap().create();

        let mut system_info = SystemInfo::new().unwrap();

        let swapinfo1 = system_info
            .swap_info(&cedar_auth)
            .expect("Should be able to get swapinfo object for authorized user");
        let swapinfo2 = system_info
            .swap_info(&cedar_auth)
            .expect("Should be able to get swapinfo object for authorized user");

        assert_eq!(
            swapinfo1.total(),
            swapinfo2.total(),
            "Total swap should be consistent between calls"
        );
    }

    /// Given: a memory object
    /// When: Display trait is used on swapinfo
    /// Then: the output contains expected information
    #[test]
    fn test_swapinfo_display_implementation() {
        let cedar_auth = TestCedarAuthBuilder::default().build().unwrap().create();

        let mut system_info = SystemInfo::new().unwrap();
        let swapinfo = system_info
            .swap_info(&cedar_auth)
            .expect("swapinfo call should succeed");

        let swapinfo_display = format!("{}", swapinfo);
        assert!(swapinfo_display.contains("Swap Info:"));
        assert!(swapinfo_display.contains("Total:"));
        assert!(swapinfo_display.contains("Free:"));
        assert!(swapinfo_display.contains("Used:"));
        assert!(swapinfo_display.contains("bytes"));

        // Verify the displayed values match the actual values
        assert!(swapinfo_display.contains(&swapinfo.total().to_string()));
        assert!(swapinfo_display.contains(&swapinfo.free().to_string()));
        assert!(swapinfo_display.contains(&swapinfo.used().to_string()));
    }
}
