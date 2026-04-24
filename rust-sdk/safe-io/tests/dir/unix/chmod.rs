use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::io::create_temp_dir_and_path;
use rust_safe_io::error_constants::INVALID_PERMISSIONS_ERR;
use rust_safe_io::options::ChmodDirOptionsBuilder;

use anyhow::Result;
use assert_fs::fixture::FileWriteStr;
use assert_fs::prelude::{PathChild, PathCreateDir};
use rstest::rstest;
use std::fs::{Permissions, metadata, set_permissions};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use crate::test_common::{PERMISSION_EXTRACT_BITMASK, init_test_logger, open_test_dir_handle};

/// Given: A directory that exists and an authorized user who is the owner
/// When: The directory permissions are changed with safe_chmod
/// Then: The permissions are changed successfully
#[test]
fn test_safe_chmod_dir_success() -> Result<()> {
    let (_temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let original_perms = metadata(&temp_dir_path)?.mode() & PERMISSION_EXTRACT_BITMASK;
    let new_perms = 0o600;

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    dir_handle.safe_chmod(
        &DEFAULT_TEST_CEDAR_AUTH,
        ChmodDirOptionsBuilder::default()
            .permissions(new_perms)
            .build()
            .unwrap(),
    )?;

    let actual_mode = metadata(temp_dir_path)?.mode() & PERMISSION_EXTRACT_BITMASK;

    assert_ne!(
        original_perms, actual_mode,
        "Expected directory permissions to be changed from original"
    );
    assert_eq!(
        actual_mode, new_perms as u32,
        "Expected directory permissions to match new permissions value 0o{:o}",
        new_perms
    );

    let _ = _temp_dir.close();
    Ok(())
}

/// Given: A directory and a user without chmod permission
/// When: The directory permissions are changed with safe_chmod
/// Then: Access is denied
#[test]
fn test_unauthorized_safe_chmod_dir() -> Result<()> {
    let (_temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
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

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let result = dir_handle.safe_chmod(
        &test_cedar_auth,
        ChmodDirOptionsBuilder::default()
            .permissions(0o755)
            .build()
            .unwrap(),
    );

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Chmod
    );
    assert_error_contains(result, &expected_error);

    Ok(())
}

/// Given: A directory that exists and an attempt to set invalid permissions
/// When: The safe_chmod function is called with permissions > 0o777
/// Then: An error is returned from the safe_chmod function
#[test]
fn test_safe_chmod_dir_invalid_permissions() -> Result<()> {
    let (_temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let invalid_perms = 0o1000;

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let result = dir_handle.safe_chmod(
        &DEFAULT_TEST_CEDAR_AUTH,
        ChmodDirOptionsBuilder::default()
            .permissions(invalid_perms)
            .build()
            .unwrap(),
    );

    assert_error_contains(result, INVALID_PERMISSIONS_ERR);

    Ok(())
}

/// Given: A directory with subdirectories and files
/// When: The directory permissions are changed recursively with safe_chmod
/// Then: All directories and files have their permissions changed
#[test]
fn test_safe_chmod_dir_recursive_success() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let subdir = temp_dir.child("subdir");
    subdir.create_dir_all()?;
    let file1 = temp_dir.child("file1.txt");
    file1.write_str("content1")?;
    let file2 = subdir.child("file2.txt");
    file2.write_str("content2")?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let root_original_mode = metadata(&temp_dir_path)?.mode() & PERMISSION_EXTRACT_BITMASK;
    let subdir_orignal_mode = metadata(subdir.path())?.mode() & PERMISSION_EXTRACT_BITMASK;
    let file1_orignal_mode = metadata(file1.path())?.mode() & PERMISSION_EXTRACT_BITMASK;
    let file2_orignal_mode = metadata(file2.path())?.mode() & PERMISSION_EXTRACT_BITMASK;
    let new_perms = 0o700 as u32;

    dir_handle.safe_chmod(
        &DEFAULT_TEST_CEDAR_AUTH,
        ChmodDirOptionsBuilder::default()
            .permissions(new_perms as i64)
            .recursive(true)
            .build()
            .unwrap(),
    )?;

    let root_mode = metadata(&temp_dir_path)?.mode() & PERMISSION_EXTRACT_BITMASK;
    assert_eq!(root_mode, new_perms);
    assert_ne!(root_mode, root_original_mode);

    let subdir_mode = metadata(subdir.path())?.mode() & PERMISSION_EXTRACT_BITMASK;
    assert_eq!(subdir_mode, new_perms);
    assert_ne!(subdir_mode, subdir_orignal_mode);

    let file1_mode = metadata(file1.path())?.mode() & PERMISSION_EXTRACT_BITMASK;
    assert_eq!(file1_mode, new_perms);
    assert_ne!(file1_mode, file1_orignal_mode);

    let file2_mode = metadata(file2.path())?.mode() & PERMISSION_EXTRACT_BITMASK;
    assert_eq!(file2_mode, new_perms);
    assert_ne!(file2_mode, file2_orignal_mode);

    Ok(())
}

/// Given: A directory with an unreadable subdirectory
/// When: Recursive chmod is performed
/// Then: The operation continues despite the error and changes accessible items
#[test]
fn test_safe_chmod_dir_recursive_with_unreadable_subdir() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let subdir = temp_dir.child("unreadable");
    subdir.create_dir_all()?;
    let accessible_file = temp_dir.child("accessible.txt");
    accessible_file.write_str("content")?;

    let root_original_mode = metadata(&temp_dir_path)?.mode() & PERMISSION_EXTRACT_BITMASK;
    let file_original_mode = metadata(accessible_file.path())?.mode() & PERMISSION_EXTRACT_BITMASK;

    set_permissions(subdir.path(), Permissions::from_mode(0o000))?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let new_perms = 0o700;

    let result = dir_handle.safe_chmod(
        &DEFAULT_TEST_CEDAR_AUTH,
        ChmodDirOptionsBuilder::default()
            .permissions(new_perms)
            .recursive(true)
            .build()
            .unwrap(),
    );

    assert!(result.is_ok());

    let root_mode = metadata(&temp_dir_path)?.mode() & PERMISSION_EXTRACT_BITMASK;
    assert_eq!(root_mode, new_perms as u32);
    assert_ne!(root_mode, root_original_mode);

    let file_mode = metadata(accessible_file.path())?.mode() & PERMISSION_EXTRACT_BITMASK;
    assert_eq!(file_mode, new_perms as u32);
    assert_ne!(file_mode, file_original_mode);

    let subdir_mode = metadata(subdir.path())?.mode() & PERMISSION_EXTRACT_BITMASK;
    assert_eq!(subdir_mode, 0o000);

    // Restore permissions so TempDir::close() can clean up on macOS
    set_permissions(subdir.path(), Permissions::from_mode(0o755))?;
    temp_dir.close()?;

    Ok(())
}

/// Given: A directory that becomes unreadable after opening
/// When: Recursive chmod attempts to list its contents
/// Then: The error is logged and operation continues with empty iterator
#[test]
fn test_safe_chmod_dir_recursive_unreadable_root() -> Result<()> {
    init_test_logger();

    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let file = temp_dir.child("test.txt");
    file.write_str("content")?;

    let file_original_mode = metadata(file.path())?.mode() & PERMISSION_EXTRACT_BITMASK;

    let dir_handle = open_test_dir_handle(&temp_dir_path);

    set_permissions(&temp_dir_path, Permissions::from_mode(0o000))?;

    let result = dir_handle.safe_chmod(
        &DEFAULT_TEST_CEDAR_AUTH,
        ChmodDirOptionsBuilder::default()
            .permissions(0o755)
            .recursive(true)
            .build()
            .unwrap(),
    );

    assert!(result.is_ok());

    let root_current_mode = metadata(&temp_dir_path)?.mode() & PERMISSION_EXTRACT_BITMASK;
    assert_eq!(root_current_mode, 0o000);

    set_permissions(&temp_dir_path, Permissions::from_mode(0o755))?;

    let file_current_mode = metadata(file.path())?.mode() & PERMISSION_EXTRACT_BITMASK;
    assert_eq!(file_current_mode, file_original_mode);

    Ok(())
}

/// Given: A directory with a subdirectory that fails Cedar authorization during traversal
/// When: Recursive chmod tries to open the subdirectory with restricted permissions
/// Then: The error is logged and traversal continues
#[test]
fn test_safe_chmod_dir_recursive_cedar_denied_subdir() -> Result<()> {
    init_test_logger();

    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let subdir = temp_dir.child("restricted_subdir");
    subdir.create_dir_all()?;

    let file_in_subdir = subdir.child("test_file.txt");
    file_in_subdir.write_str("test content")?;

    let root_original_mode = metadata(&temp_dir_path)?.mode() & PERMISSION_EXTRACT_BITMASK;
    let subdir_original_mode = metadata(subdir.path())?.mode() & PERMISSION_EXTRACT_BITMASK;
    let file_original_mode = metadata(file_in_subdir.path())?.mode() & PERMISSION_EXTRACT_BITMASK;

    let principal = get_test_rex_principal();
    let subdir_path = subdir.path().to_string_lossy();
    let test_policy = format!(
        r#"
        permit(
            principal == User::"{principal}",
            action,
            resource
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::Dir::"{subdir_path}"
        );
        "#,
        FilesystemAction::Open
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .expect("Failed to build TestCedarAuth")
        .create();

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let new_perms = 0o700;

    let result = dir_handle.safe_chmod(
        &test_cedar_auth,
        ChmodDirOptionsBuilder::default()
            .permissions(new_perms)
            .recursive(true)
            .build()
            .unwrap(),
    );

    assert!(result.is_ok());

    let root_new_mode = metadata(&temp_dir_path)?.mode() & PERMISSION_EXTRACT_BITMASK;
    assert_eq!(root_new_mode, new_perms as u32);
    assert_ne!(root_new_mode, root_original_mode);

    let subdir_new_mode = metadata(subdir.path())?.mode() & PERMISSION_EXTRACT_BITMASK;
    assert_eq!(subdir_new_mode, subdir_original_mode);

    let file_new_mode = metadata(file_in_subdir.path())?.mode() & PERMISSION_EXTRACT_BITMASK;
    assert_eq!(file_new_mode, file_original_mode);

    Ok(())
}

/// Given: A directory with a file that fails Cedar authorization during traversal
/// When: Recursive chmod tries to access the file with restricted permissions
/// Then: The error is logged and traversal continues
#[rstest]
#[case::open_denied(FilesystemAction::Open)]
#[case::chmod_denied(FilesystemAction::Chmod)]
fn test_safe_chmod_dir_recursive_cedar_denied_file(
    #[case] forbidden_action: FilesystemAction,
) -> Result<()> {
    init_test_logger();

    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let restricted_file = temp_dir.child("restricted_file.txt");
    restricted_file.write_str("test content")?;

    let accessible_file = temp_dir.child("accessible_file.txt");
    accessible_file.write_str("accessible content")?;

    let root_original_mode = metadata(&temp_dir_path)?.mode() & PERMISSION_EXTRACT_BITMASK;
    let restricted_file_original_mode =
        metadata(restricted_file.path())?.mode() & PERMISSION_EXTRACT_BITMASK;
    let accessible_file_original_mode =
        metadata(accessible_file.path())?.mode() & PERMISSION_EXTRACT_BITMASK;

    let principal = get_test_rex_principal();
    let file_path = restricted_file.path().to_string_lossy();
    let test_policy = format!(
        r#"
        permit(
            principal == User::"{principal}",
            action,
            resource
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{file_path}"
        );
        "#,
        forbidden_action
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .expect("Failed to build TestCedarAuth")
        .create();

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let new_perms = 0o700;

    let result = dir_handle.safe_chmod(
        &test_cedar_auth,
        ChmodDirOptionsBuilder::default()
            .permissions(new_perms)
            .recursive(true)
            .build()
            .unwrap(),
    );

    assert!(result.is_ok());

    let root_new_mode = metadata(&temp_dir_path)?.mode() & PERMISSION_EXTRACT_BITMASK;
    assert_eq!(root_new_mode, new_perms as u32);
    assert_ne!(root_new_mode, root_original_mode);

    let accessible_file_new_mode =
        metadata(accessible_file.path())?.mode() & PERMISSION_EXTRACT_BITMASK;
    assert_eq!(accessible_file_new_mode, new_perms as u32);
    assert_ne!(accessible_file_new_mode, accessible_file_original_mode);

    let restricted_file_new_mode =
        metadata(restricted_file.path())?.mode() & PERMISSION_EXTRACT_BITMASK;
    assert_eq!(restricted_file_new_mode, restricted_file_original_mode);

    Ok(())
}

/// Given: A directory structure where permissions are denied on a parent directory
/// When: Recursive chmod is performed starting from the root
/// Then: The operation skips the forbidden parent directory and its children
#[rstest]
#[case::open_denied(FilesystemAction::Open)]
#[case::chmod_denied(FilesystemAction::Chmod)]
fn test_safe_chmod_dir_recursive_with_forbidden_parent_allowed_child(
    #[case] forbidden_action: FilesystemAction,
) -> Result<()> {
    init_test_logger();

    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let parent_dir = temp_dir.child("parent");
    parent_dir.create_dir_all()?;

    let child_dir = parent_dir.child("child");
    child_dir.create_dir_all()?;

    let child_file = child_dir.child("file.txt");
    child_file.write_str("test content")?;

    let principal = get_test_rex_principal();
    let parent_path = parent_dir.path().to_string_lossy();

    let test_policy = format!(
        r#"
        permit(
            principal == User::"{principal}",
            action,
            resource
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource in file_system::Dir::"{parent_path}"
        );
        "#,
        forbidden_action
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .expect("Failed to build TestCedarAuth")
        .create();

    let root_original_mode = metadata(&temp_dir_path)?.mode() & PERMISSION_EXTRACT_BITMASK;
    let parent_original_mode = metadata(parent_dir.path())?.mode() & PERMISSION_EXTRACT_BITMASK;
    let child_original_mode = metadata(child_dir.path())?.mode() & PERMISSION_EXTRACT_BITMASK;
    let file_original_mode = metadata(child_file.path())?.mode() & PERMISSION_EXTRACT_BITMASK;

    let new_perms = 0o700;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let result = dir_handle.safe_chmod(
        &test_cedar_auth,
        ChmodDirOptionsBuilder::default()
            .permissions(new_perms)
            .recursive(true)
            .build()
            .unwrap(),
    );

    assert!(result.is_ok());

    let root_new_mode = metadata(&temp_dir_path)?.mode() & PERMISSION_EXTRACT_BITMASK;
    assert_eq!(root_new_mode, new_perms as u32);
    assert_ne!(root_new_mode, root_original_mode);

    let parent_new_mode = metadata(parent_dir.path())?.mode() & PERMISSION_EXTRACT_BITMASK;
    assert_eq!(parent_new_mode, parent_original_mode);

    let child_new_mode = metadata(child_dir.path())?.mode() & PERMISSION_EXTRACT_BITMASK;
    assert_eq!(child_new_mode, child_original_mode);

    let file_new_mode = metadata(child_file.path())?.mode() & PERMISSION_EXTRACT_BITMASK;
    assert_eq!(file_new_mode, file_original_mode);

    Ok(())
}
