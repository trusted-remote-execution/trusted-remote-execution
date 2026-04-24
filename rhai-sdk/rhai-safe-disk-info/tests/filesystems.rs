#![cfg(target_os = "linux")]
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::get_test_rex_principal;
use rex_test_utils::rhai::common::create_test_engine_and_register;

mod common;
use common::create_test_engine_and_register_with_policy;
use rhai::{EvalAltResult, Map, Scope};

/// Given: A Cedar policy that denies filesystem unmount permissions
/// When: Attempting to unmount a filesystem
/// Then: Authorization fails with Permission denied error
#[test]
#[cfg(target_os = "linux")]
fn test_unauthorized_unmount() {
    let principal = get_test_rex_principal();
    let deny_policy = format!(
        r#"
        forbid(
            principal == User::"{principal}",
            action == {},
            resource
        );"#,
        FilesystemAction::Unmount.to_string()
    );
    let engine = create_test_engine_and_register_with_policy(&deny_policy);

    let result = engine.eval::<()>(
        r#"
        let options = UnmountOptions()
            .path("/mnt/test")
            .build();
        unmount(options);
        "#,
    );

    assert!(result.is_err(), "Expected an error but got success");
    let error_msg = result.unwrap_err().to_string();
    let expected_error = format!("Permission denied: {principal} unauthorized to perform");
    assert!(
        error_msg.contains(&expected_error),
        "Error message should contain permission denied, got: {}",
        error_msg
    );
}

/// Given: A system with available filesystems
/// When: Filesystems are queried with local-only filter
/// Then: The first filesystem device name is returned successfully
#[test]
fn test_get_filesystems_success() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();

    let mut scope = Scope::new();

    let result = engine.eval_with_scope::<String>(
        &mut scope,
        r#"
            let fs_opts = FilesystemOptions()
                .local(true)
                .build();
            let filesystems = Filesystems(fs_opts).filesystems();
            for fs in filesystems {
                return fs.fs_device;
            }
            "#,
    )?;

    assert!(
        !result.is_empty(),
        "Expected a non-empty filesystem device name"
    );

    Ok(())
}

/// Given: A Cedar policy that denies permission to read /proc/mounts
/// When: Attempting to create a new Filesystems instance
/// Then: The operation fails with a PermissionDenied error
#[test]
fn test_filesystems_permission_denied_proc_mounts() {
    let principal = rex_cedar_auth::test_utils::get_test_rex_principal();
    let deny_policy = format!(
        r#"
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"/proc/mounts"
        );"#,
        rex_cedar_auth::fs::actions::FilesystemAction::Read.to_string()
    );
    let engine = create_test_engine_and_register_with_policy(&deny_policy);

    let result = engine.eval::<()>(
        r#"
        let fs_opts = FilesystemOptions().build();
        let filesystems = Filesystems(fs_opts).filesystems();
        "#,
    );

    assert!(result.is_err(), "Expected an error but got success");
    let error_msg = result.unwrap_err().to_string();
    let expected_error = format!("Permission denied: {principal} unauthorized to perform");
    assert!(
        error_msg.contains(&expected_error),
        "Error message should contain permission denied"
    );
    assert!(
        error_msg.contains("read"),
        "Error message should contain read action"
    );
}

/// Given: A system with available filesystems
/// When: Accessing mount_options property on a Filesystem object
/// Then: Mount options are returned as an array
#[test]
fn test_filesystem_mount_options_getter() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();

    let mut scope = Scope::new();

    let result = engine.eval_with_scope::<bool>(
        &mut scope,
        r#"
            let fs_opts = FilesystemOptions().build();
            let filesystems = Filesystems(fs_opts).filesystems();
            let fs = filesystems[0];
            let options = fs.mount_options;
            type_of(options) == "array" && options.len() >= 0
            "#,
    )?;

    assert!(result, "Expected mount_options to be an array");

    Ok(())
}

/// Given: A system with available filesystems
/// When: to_map is called on a filesystem
/// Then: the map representation matches the expected value
#[test]
fn test_filesystem_to_map() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    let result = engine.eval_with_scope::<Map>(
        &mut scope,
        r#"
            let fs_opts = FilesystemOptions().build();
            let filesystems = Filesystems(fs_opts).filesystems();
            let fs = filesystems[0];

            let expected = #{
                "fs_device": fs.fs_device,
                "fs_kind": fs.fs_kind,
                "inodes": fs.inodes.to_int(),
                "iused": fs.iused.to_int(),
                "ifree": fs.ifree.to_int(),
                "iuse_percent": fs.iuse_percent,
                "block_used": fs.block_used.to_int(),
                "block_available": fs.block_available.to_int(),
                "block_use_percent": fs.block_use_percent,
                "mounted_on": fs.mounted_on,
                "kb_blocks": fs.kb_blocks.to_int(),
                "mb_blocks": fs.mb_blocks.to_int(),
                "size": fs.size.to_int(),
                "mount_options": fs.mount_options,
            };

            #{
                "expected": expected.to_json(),
                "actual": fs.to_map().to_json()
            }"#,
    )?;

    let expected: String = result.get("expected").unwrap().clone().into_string()?;
    let actual: String = result.get("actual").unwrap().clone().into_string()?;
    assert_eq!(expected, actual);

    Ok(())
}

/// Given: A Cedar policy that allows reading /proc/mounts but denies stat operations
/// When: Attempting to get filesystem information
/// Then: The operation fails with a PermissionDenied error for stat operation
#[test]
fn test_filesystems_permission_denied_stat() {
    let principal = rex_cedar_auth::test_utils::get_test_rex_principal();
    let mixed_policy = format!(
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

    let engine = create_test_engine_and_register_with_policy(&mixed_policy);

    let result = engine.eval::<()>(
        r#"
        let fs_opts = FilesystemOptions().build();
        let filesystems = Filesystems(fs_opts).filesystems();
        "#,
    );

    assert!(result.is_err(), "Expected an error but got success");
    let error_msg = result.unwrap_err().to_string();
    let expected_error = format!("Permission denied: {principal} unauthorized to perform");
    assert!(
        error_msg.contains(&expected_error),
        "Error message should contain permission denied"
    );
    assert!(
        error_msg.contains("stat"),
        "Error message should contain stat action"
    );
}
