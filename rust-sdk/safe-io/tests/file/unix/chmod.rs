use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::io::create_temp_dir_and_path;
use rust_safe_io::error_constants::INVALID_PERMISSIONS_ERR;
use rust_safe_io::options::OpenFileOptionsBuilder;

use anyhow::Result;
use assert_fs::fixture::{FileWriteStr, PathChild, SymlinkToFile};
use std::fs::{Permissions, metadata, set_permissions, symlink_metadata};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use crate::test_common::{PERMISSION_EXTRACT_BITMASK, open_dir_and_file, open_test_dir_handle};

/// Given: A file that is a real file and an authorized user who is the owner
/// When: The file permissions are changed with safe_chmod
/// Then: The permissions are changed successfully
#[test]
#[cfg(unix)]
fn test_safe_chmod_file_success() -> Result<()> {
    let test_contents = open_dir_and_file()?;
    let full_path = Path::new(&test_contents.dir_name).join(&test_contents.file_name);
    let original_perms = metadata(&full_path)?.mode() & PERMISSION_EXTRACT_BITMASK;
    let new_perms = 0o600;

    test_contents
        .file_handle
        .safe_chmod(&DEFAULT_TEST_CEDAR_AUTH, new_perms)?;

    let actual_mode = metadata(full_path)?.mode() & PERMISSION_EXTRACT_BITMASK;

    assert_ne!(
        original_perms, actual_mode,
        "Expected permissions to be changed from original"
    );
    assert_eq!(
        actual_mode, new_perms as u32,
        "Expected permissions to match new permissions value 0o{:o}",
        new_perms
    );

    Ok(())
}

/// Given: A file and a user without chmod permission
/// When: The file permissions are changed with safe_chmod
/// Then: Access is denied
#[test]
#[cfg(unix)]
fn test_unauthorized_safe_chmod_file() -> Result<()> {
    let test_contents = open_dir_and_file()?;
    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"forbid(
            principal == User::"{principal}",
            action == {},
            resource
        );"#,
        FilesystemAction::Chmod
    );
    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .expect("Failed to build TestCedarAuth")
        .create();

    let result = test_contents
        .file_handle
        .safe_chmod(&test_cedar_auth, 0o644);

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Chmod
    );
    assert_error_contains(result, &expected_error);

    Ok(())
}

/// Given: A file that exists and an attempt to set invalid permissions
/// When: The safe_chmod function is called with permissions > 0o777
/// Then: An error is returned from the safe_chmod function
#[test]
#[cfg(unix)]
fn test_safe_chmod_file_invalid_permissions() -> Result<()> {
    let test_contents = open_dir_and_file()?;
    let invalid_perms = 0o1000;

    let result = test_contents
        .file_handle
        .safe_chmod(&DEFAULT_TEST_CEDAR_AUTH, invalid_perms);

    assert_error_contains(result, INVALID_PERMISSIONS_ERR);

    Ok(())
}

/// Given: A file that exists and an attempt to set negative perms
/// When: The safe_chmod function is called with permissions that are negative
/// Then: An error is returned from the safe_chmod function
#[test]
#[cfg(unix)]
fn test_safe_chmod_negative_permissions() -> Result<()> {
    let test_contents = open_dir_and_file()?;

    let result = test_contents
        .file_handle
        .safe_chmod(&DEFAULT_TEST_CEDAR_AUTH, -10);

    assert_error_contains(result, "out of range integral type conversion attempted");

    Ok(())
}

/// Given: A symlink opened with follow_symlinks=true and restrictive Cedar policies
/// When: safe_chmod is called on the file handle
/// Then: The target file permissions are changed, not the symlink (Unix chmod behavior)
#[test]
#[cfg(target_os = "linux")]
fn test_safe_chmod_symlink_changes_target_permissions() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let (target_dir, _target_dir_path) = create_temp_dir_and_path()?;

    let target_file = target_dir.child("chmod_target.txt");
    target_file.write_str("chmod test content")?;
    let target_absolute_path = target_file.path().to_string_lossy().to_string();

    let initial_perms = 0o644;
    set_permissions(&target_absolute_path, Permissions::from_mode(initial_perms))?;

    let symlink_file = temp_dir.child("chmod_link");
    symlink_file.symlink_to_file(&target_absolute_path)?;
    let symlink_path = symlink_file.path().to_string_lossy().to_string();

    let initial_symlink_metadata = symlink_metadata(&symlink_path)?;
    let initial_symlink_perms = initial_symlink_metadata.mode() & PERMISSION_EXTRACT_BITMASK;

    let principal = get_test_rex_principal();

    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{symlink_path}"
        );
        permit(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{target_absolute_path}"
        );
        permit(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{target_absolute_path}"
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{symlink_path}"
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Open,
        FilesystemAction::Chmod,
        FilesystemAction::Chmod
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let file_handle = dir_handle.safe_open_file(
        &test_cedar_auth,
        "chmod_link",
        OpenFileOptionsBuilder::default()
            .read(true)
            .follow_symlinks(true)
            .build()
            .unwrap(),
    )?;

    let new_perms = 0o600;
    file_handle.safe_chmod(&test_cedar_auth, new_perms)?;

    let target_metadata = metadata(&target_absolute_path)?;
    let target_final_perms = target_metadata.mode() & PERMISSION_EXTRACT_BITMASK;
    assert_eq!(target_final_perms as i64, new_perms);

    let symlink_metadata = symlink_metadata(&symlink_path)?;
    let symlink_final_perms = symlink_metadata.mode() & PERMISSION_EXTRACT_BITMASK;
    assert_eq!(symlink_final_perms, initial_symlink_perms);

    Ok(())
}
