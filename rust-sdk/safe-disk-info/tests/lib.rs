#![cfg(target_os = "linux")]
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rex_test_utils::assertions::assert_error_contains;
use rust_disk_info::Unit;

use rust_disk_info::{Filesystem, FilesystemOptionsBuilder, Filesystems};

#[cfg(target_os = "linux")]
use rust_disk_info::{UnmountOptionsBuilder, unmount};

use anyhow::Result;

/// Given: A Cedar policy that denies filesystem read permissions on `/proc/mounts`
/// When: Attempting to create a Filesystems instance
/// Then: Authorization fails with Permission denied error
#[test]
fn test_unauthorized_read_proc_mounts() -> Result<()> {
    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"/proc/mounts"
        );
        permit(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"/proc/diskstats"
        );
        "#,
        FilesystemAction::Read.to_string(),
        FilesystemAction::Read.to_string()
    );
    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let fs_opts = FilesystemOptionsBuilder::default().build()?;
    let diskinfo = Filesystems::new(fs_opts.clone());
    let result = diskinfo.filesystems(&test_cedar_auth);

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Read
    );
    assert_error_contains(result, &expected_error);

    Ok(())
}

/// Given: A Cedar policy that denies filesystem unmount permissions
/// When: Attempting to unmount a filesystem
/// Then: Authorization fails with Permission denied error
#[test]
#[cfg(target_os = "linux")]
fn test_unauthorized_unmount() -> Result<()> {
    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"
        forbid(
            principal == User::"{principal}",
            action == {},
            resource
        );"#,
        FilesystemAction::Unmount.to_string()
    );
    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let options = UnmountOptionsBuilder::default()
        .path("/mnt/test".to_string())
        .build()?;

    let result = unmount(&test_cedar_auth, options);

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Unmount
    );
    assert_error_contains(result, &expected_error);

    Ok(())
}

/// Given: UnmountOptionsBuilder with a valid path
/// When: Building UnmountOptions
/// Then: Options are successfully created with the correct path
#[test]
#[cfg(target_os = "linux")]
fn test_unmount_options_builder_success() -> Result<()> {
    let path = "/mnt/test".to_string();
    let options = UnmountOptionsBuilder::default()
        .path(path.clone())
        .build()?;

    assert_eq!(options.path, path);

    Ok(())
}

/// Given: UnmountOptionsBuilder without setting the required path
/// When: Attempting to build UnmountOptions
/// Then: Build fails with an error indicating missing path field
#[test]
#[cfg(target_os = "linux")]
fn test_unmount_options_builder_missing_path() -> Result<()> {
    let result = UnmountOptionsBuilder::default().build();

    assert!(result.is_err(), "Expected build to fail without path");
    let error = result.unwrap_err().to_string();
    assert!(
        error.contains("path"),
        "Error should mention missing path field, got: {}",
        error
    );

    Ok(())
}

/// Given: A valid unmount operation on the root filesystem
/// When: Attempting to unmount without CAP_SYS_ADMIN capability
/// Then: Operation fails with permission error from the kernel
#[test]
#[cfg(target_os = "linux")]
fn test_unmount_without_cap_sys_admin() -> Result<()> {
    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action == {},
            resource
        );"#,
        FilesystemAction::Unmount.to_string()
    );
    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let options = UnmountOptionsBuilder::default()
        .path("/".to_string())
        .build()?;

    let result = unmount(&test_cedar_auth, options);

    assert!(
        result.is_err(),
        "Expected unmount to fail without CAP_SYS_ADMIN capability"
    );
    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("Failed to unmount") || error_msg.contains("Operation not permitted"),
        "Error should indicate unmount failure or lack of permissions, got: {}",
        error_msg
    );

    Ok(())
}

/// Given: A Cedar policy that denies filesystem read permissions on `/proc/disks`
/// When: Attempting to create a Filesystems instance
/// Then: Authorization fails with Permission denied error
#[test]
fn test_unauthorized_read_proc_disks() -> Result<()> {
    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"/proc/diskstats"
        );
        permit(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"/proc/mounts"
        );"#,
        FilesystemAction::Read.to_string(),
        FilesystemAction::Read.to_string()
    );
    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let fs_opts = FilesystemOptionsBuilder::default().build()?;
    let diskinfo = Filesystems::new(fs_opts.clone());
    let result = diskinfo.filesystems(&test_cedar_auth);

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Read
    );
    assert_error_contains(result, &expected_error);

    Ok(())
}

/// Given: A Cedar policy that denies filesystem stat permissions
/// When: Attempting to get filesystems
/// Then: Authorization fails with Permission denied error
#[test]
fn test_unauthorized_stat_mount_point() -> Result<()> {
    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"
            permit(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"/proc/mounts"
        );
            permit(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"/proc/diskstats"
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource
        );"#,
        FilesystemAction::Read.to_string(),
        FilesystemAction::Read.to_string(),
        FilesystemAction::Stat.to_string()
    );
    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let fs_opts = FilesystemOptionsBuilder::default().build()?;
    let diskinfo = Filesystems::new(fs_opts.clone());
    let result = diskinfo.filesystems(&test_cedar_auth);

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Stat
    );
    assert_error_contains(result, &expected_error);

    Ok(())
}

/// Given: A valid filesystem options configuration and authorized Cedar context
/// When: Creating a filesystem handle and getting filesystem information
/// Then: Filesystem data is successfully retrieved with expected properties
#[test]
fn test_get_filesystems_success() -> Result<()> {
    let fs_opts = FilesystemOptionsBuilder::default()
        .local(true)
        .targets(vec!["/".to_string()])
        .build()?;
    let diskinfo = Filesystems::new(fs_opts.clone());
    let filesystems = diskinfo.filesystems(&DEFAULT_TEST_CEDAR_AUTH)?;

    assert!(
        !filesystems.is_empty(),
        "Should have at least one filesystem"
    );

    let first_fs = &filesystems[0];
    assert!(
        !first_fs.mounted_on().is_empty(),
        "Mount point should not be empty"
    );

    assert!(
        *first_fs.block_use_percent() >= 0.0,
        "Usage percentage should be non-negative"
    );

    Ok(())
}

/// Given: Filesystem options with multiple target paths
/// When: Getting filesystem information with multiple targets
/// Then: Filesystems matching any of the target paths are returned
#[test]
fn test_get_filesystems_with_multiple_target_paths() -> Result<()> {
    let fs_opts = FilesystemOptionsBuilder::default().build()?;
    let diskinfo = Filesystems::new(fs_opts.clone());
    let filesystems = diskinfo.filesystems(&DEFAULT_TEST_CEDAR_AUTH)?;

    if filesystems.len() < 2 {
        return Ok(());
    }

    let target1 = filesystems[0].mounted_on().to_string();
    let target2 = if filesystems.len() > 1 {
        filesystems[1].mounted_on().to_string()
    } else {
        "/nonexistent".to_string()
    };

    let multi_target_opts = FilesystemOptionsBuilder::default()
        .targets(vec![target1.clone(), target2.clone()])
        .build()?;

    let multi_diskinfo = Filesystems::new(multi_target_opts.clone());
    let multi_filtered = multi_diskinfo.filesystems(&DEFAULT_TEST_CEDAR_AUTH)?;

    for fs in &multi_filtered {
        let mount_point = fs.mounted_on();
        let matches_target1 = mount_point.starts_with(&target1) || target1.starts_with(mount_point);
        let matches_target2 = mount_point.starts_with(&target2) || target2.starts_with(mount_point);

        assert!(
            matches_target1 || matches_target2,
            "Filesystem '{}' should match either '{}' or '{}'",
            mount_point,
            target1,
            target2
        );
    }

    Ok(())
}

/// Given: A Cedar policy with evaluation-time errors (not parse-time errors)
/// When: Attempting to create a Filesystems instance
/// Then: Authorization evaluation fails during is_authorized() call
#[test]
fn test_authorization_evaluation_fails() -> Result<()> {
    let principal = get_test_rex_principal();

    let test_policy = format!(
        r#"permit(
        principal == Rex::User::"{principal}",
        action == Rex::Action::"safe_read_file",
        resource
    ) when {{
        context.access_level >= 5
    }};"#
    );

    let test_schema = r#"namespace Rex {
        entity User;
        entity File;
        action safe_read_file appliesTo {
            principal: [User],
            resource: [File],
            context: {
                access_level: Long
            }
        };
    }"#;

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy.to_string())
        .schema(test_schema.to_string())
        .build()
        .unwrap()
        .create();

    let fs_opts = FilesystemOptionsBuilder::default().build()?;
    let diskinfo = Filesystems::new(fs_opts.clone());
    let result = diskinfo.filesystems(&test_cedar_auth);

    assert_error_contains(result, "Authorization check failed");

    Ok(())
}

/// Given: A Filesystem instance with known values
/// When: Calling all getter methods
/// Then: Each getter returns the expected value
#[test]
fn test_filesystem_getters() -> Result<()> {
    let fs_device = "test_device";
    let fs_kind = "ext4";
    let inodes = 1000;
    let iused = 250;
    let ifree = 750;
    let iuse_percent = 25.0;
    let block_used = 5000;
    let block_available = 15000;
    let block_use_percent = 25.0;
    let mounted_on = "/test";
    let kb_blocks = 19;
    let mb_blocks = 20_000;
    let raw_size = 20_480_000;
    let mount_options = vec!["rw".to_string(), "relatime".to_string()];

    let filesystem = Filesystem::new(
        fs_device.to_string(),
        fs_kind.to_string(),
        inodes,
        iused,
        ifree,
        iuse_percent,
        block_used,
        block_available,
        block_use_percent,
        mounted_on.to_string(),
        kb_blocks,
        mb_blocks,
        raw_size,
        mount_options.clone(),
    );

    assert_eq!(filesystem.fs_device(), fs_device);
    assert_eq!(filesystem.fs_kind(), fs_kind);
    assert_eq!(filesystem.mounted_on(), mounted_on);

    assert_eq!(*filesystem.kb_blocks(), kb_blocks);
    assert_eq!(*filesystem.mb_blocks(), mb_blocks);

    assert_eq!(*filesystem.raw_size(), raw_size);

    assert_eq!(*filesystem.block_used(), block_used);
    assert_eq!(*filesystem.block_available(), block_available);
    assert_eq!(*filesystem.block_use_percent(), block_use_percent);

    assert_eq!(*filesystem.inodes(), inodes);
    assert_eq!(*filesystem.iused(), iused);
    assert_eq!(*filesystem.ifree(), ifree);
    assert_eq!(*filesystem.iuse_percent(), iuse_percent);

    assert_eq!(filesystem.mount_options(), &mount_options);

    Ok(())
}

/// Given: A valid filesystem options configuration
/// When: Getting filesystem information
/// Then: Mount options are properly retrieved from /proc/mounts
#[test]
fn test_filesystem_mount_options() -> Result<()> {
    let fs_opts = FilesystemOptionsBuilder::default()
        .targets(vec!["/".to_string()])
        .build()?;
    let diskinfo = Filesystems::new(fs_opts);
    let filesystems = diskinfo.filesystems(&DEFAULT_TEST_CEDAR_AUTH)?;

    assert!(
        !filesystems.is_empty(),
        "Should have at least one filesystem"
    );

    let root_fs = &filesystems[0];
    let mount_options = root_fs.mount_options();

    assert!(
        !mount_options.is_empty(),
        "Mount options should not be empty"
    );

    let has_rw_or_ro = mount_options.iter().any(|opt| opt == "rw" || opt == "ro");
    assert!(
        has_rw_or_ro,
        "Mount options should contain either 'rw' or 'ro', got: {:?}",
        mount_options
    );

    Ok(())
}

/// Given: A Filesystem instance with known byte values
/// When: Using the format function to convert to different units
/// Then: Unit conversions are mathematically correct
#[test]
fn test_filesystem_format_function() -> Result<()> {
    let size = 3072000;
    let block_used = 2048000;
    let block_available = 1024000;

    // Test bytes (should return original values)
    assert_eq!(Filesystem::format_bytes(size, Unit::Bytes), 3072000);
    assert_eq!(Filesystem::format_bytes(block_used, Unit::Bytes), 2048000);
    assert_eq!(
        Filesystem::format_bytes(block_available, Unit::Bytes),
        1024000
    );

    // Test kilobytes conversion
    assert_eq!(Filesystem::format_bytes(size, Unit::Kilobytes), 3000);
    assert_eq!(Filesystem::format_bytes(block_used, Unit::Kilobytes), 2000);
    assert_eq!(
        Filesystem::format_bytes(block_available, Unit::Kilobytes),
        1000
    );

    // Test megabytes conversion (3000 KB = 2.929... MB, truncated to 2)
    assert_eq!(Filesystem::format_bytes(size, Unit::Megabytes), 2);
    assert_eq!(Filesystem::format_bytes(block_used, Unit::Megabytes), 1);
    assert_eq!(
        Filesystem::format_bytes(block_available, Unit::Megabytes),
        0
    );

    Ok(())
}

/// Given: A Cedar policy that denies filesystem read permissions on `/proc/diskstats`
/// When: An unauthorized user attempts to call iostats
/// Then: Authorization fails with Permission denied error
#[test]
fn test_unauthorized_iostat_read_proc_diskstats() -> Result<()> {
    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"/proc/diskstats"
        );
        permit(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"/proc/stat"
        );"#,
        FilesystemAction::Read.to_string(),
        FilesystemAction::Read.to_string()
    );
    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let fs_opts = FilesystemOptionsBuilder::default().build()?;
    let diskinfo = Filesystems::new(fs_opts);
    let result = diskinfo.iostat(&test_cedar_auth);

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Read
    );
    let error_msg = result.as_ref().err().unwrap().to_string();
    assert_error_contains(result, &expected_error);

    println!("result: {error_msg}");
    Ok(())
}

/// Given: A Cedar policy that denies filesystem read permissions on `/proc/stat`
/// When: An unauthorized user attempts to call iostats
/// Then: Authorization fails with Permission denied error
#[test]
fn test_unauthorized_iostat_read_proc_stats() -> Result<()> {
    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"/proc/stat"
        );
        permit(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"/proc/diskstats"
        );"#,
        FilesystemAction::Read.to_string(),
        FilesystemAction::Read.to_string()
    );
    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let fs_opts = FilesystemOptionsBuilder::default().build()?;
    let diskinfo = Filesystems::new(fs_opts);
    let result = diskinfo.iostat(&test_cedar_auth);

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Read
    );
    assert_error_contains(result, &expected_error);

    Ok(())
}

/// Given: A valid filesystem options configuration and authorized Cedar context
/// When: Calling iostat() to get I/O statistics snapshot
/// Then: IoStatSnapshot is successfully retrieved with valid CPU and device statistics
#[test]
fn test_iostat_success() -> Result<()> {
    let fs_opts = FilesystemOptionsBuilder::default().build()?;
    let diskinfo = Filesystems::new(fs_opts);

    let snapshot = diskinfo.iostat(&DEFAULT_TEST_CEDAR_AUTH)?;

    // Validate CPU stats
    let cpu_stats = snapshot.cpu_stats();

    let total_percent = cpu_stats.user_percent()
        + cpu_stats.nice_percent()
        + cpu_stats.system_percent()
        + cpu_stats.iowait_percent()
        + cpu_stats.steal_percent()
        + cpu_stats.idle_percent();

    snapshot.to_string();
    assert!(
        (total_percent - 100.0).abs() < 1.0, // Allow up to 1% tolerance for rounding
        "CPU percentages should sum to ~100%, got: {}",
        total_percent
    );

    let device_stats = snapshot.device_stats();
    assert!(!device_stats.is_empty(), "Should have at least one device");

    for device in device_stats {
        assert!(!device.device_name().is_empty());

        assert!(device.rrqm_per_sec() >= &0.0);
        assert!(device.wrqm_per_sec() >= &0.0);
        assert!(device.read_requests_per_sec() >= &0.0);
        assert!(device.write_requests_per_sec() >= &0.0);
        assert!(device.rkb_per_sec() >= &0.0);
        assert!(device.wkb_per_sec() >= &0.0);

        assert!(device.avg_request_size() >= &0.0);
        assert!(device.avg_queue_size() >= &0.0);

        assert!(device.avg_wait() >= &0.0);
        assert!(device.avg_read_wait() >= &0.0);
        assert!(device.avg_write_wait() >= &0.0);
        assert!(device.svctm() >= &0.0);

        assert!(device.util_percent() >= &0.0 && device.util_percent() <= &100.0);
    }

    Ok(())
}
