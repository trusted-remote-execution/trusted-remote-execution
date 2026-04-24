use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::io::create_temp_dir_and_path;
use rust_safe_io::error_constants::{DIR_NED_ERR, FILE_DNE_ERR};
use rust_safe_io::options::{DeleteDirOptionsBuilder, OpenFileOptionsBuilder};

use anyhow::Result;
use assert_fs::prelude::{PathChild, PathCreateDir};
use rstest::rstest;
use std::fs::{Permissions, metadata, set_permissions};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use crate::test_common::{PERMISSION_EXTRACT_BITMASK, open_test_dir_handle};

/// Given: An empty directory
/// When: The directory is deleted with [`rust_safe_io::DirConfig::recursive`] and [`rust_safe_io::DirConfig::force`] combinations
/// Then: The directory is deleted successfully in all cases
#[rstest]
#[case::non_recursive_and_no_force(false, false)]
#[case::recursive_and_no_force(true, false)]
#[case::non_recursive_and_force(false, true)]
#[case::recursive_and_force(true, true)]
fn test_safe_delete_dir_empty_directory(
    #[case] recursive: bool,
    #[case] force: bool,
) -> Result<(), anyhow::Error> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let result = dir_handle.safe_delete(
        &DEFAULT_TEST_CEDAR_AUTH,
        DeleteDirOptionsBuilder::default()
            .force(force)
            .recursive(recursive)
            .build()
            .unwrap(),
    );

    assert!(
        result.is_ok(),
        "Expected empty directory deletion to succeed, but received {:?}",
        result
    );
    assert!(
        !temp_dir.exists(),
        "Expected directory to be deleted, but it still exists"
    );

    Ok(())
}

/// Given: A non-existent directory
/// When: The directory is deleted with [`rust_safe_io::DirConfig::recursive`] and [`rust_safe_io::DirConfig::force`] combinations
/// Then: The directory is deleted successfully with no errors when [`rust_safe_io::DirConfig::force`] = true. An error is thrown when [`rust_safe_io::DirConfig::force`] = false
#[rstest]
#[case::non_recursive_and_no_force(false, false, FILE_DNE_ERR)]
#[case::recursive_and_no_force(true, false, FILE_DNE_ERR)]
#[case::non_recursive_and_force(false, true, "")]
#[case::recursive_and_force(true, true, "")]
fn test_safe_delete_dir_nonexistent_directory(
    #[case] recursive: bool,
    #[case] force: bool,
    #[case] expected_error: &str,
) -> Result<(), anyhow::Error> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let _ = dir_handle.safe_delete(
        &DEFAULT_TEST_CEDAR_AUTH,
        DeleteDirOptionsBuilder::default()
            .force(true)
            .recursive(true)
            .build()
            .unwrap(),
    );
    assert!(
        !temp_dir.exists(),
        "Expected directory to be deleted, but it still exists"
    );

    let result = dir_handle.safe_delete(
        &DEFAULT_TEST_CEDAR_AUTH,
        DeleteDirOptionsBuilder::default()
            .force(force)
            .recursive(recursive)
            .build()
            .unwrap(),
    );

    if force {
        assert!(
            result.is_ok(),
            "Expected non-existent directory deletion with force to succeed, but received {:?}",
            result
        );
    } else {
        assert_error_contains(result, expected_error);
    }

    Ok(())
}

/// Given: A directory containing a subdirectory and files
/// When: The directory is deleted with [`rust_safe_io::DirConfig::recursive`] and [`rust_safe_io::DirConfig::force`] combinations
/// Then: The directory and its contents are deleted successfully when [`rust_safe_io::DirConfig::recursive`] = true, an error is thrown when [`rust_safe_io::DirConfig::recursive`] = false
#[rstest]
#[case::non_recursive_and_no_force(false, false, DIR_NED_ERR)]
#[case::recursive_and_no_force(true, false, "")]
#[case::non_recursive_and_force(false, true, DIR_NED_ERR)]
#[case::recursive_and_force(true, true, "")]
fn test_safe_delete_directory_with_files(
    #[case] recursive: bool,
    #[case] force: bool,
    #[case] expected_error: &str,
) -> Result<(), anyhow::Error> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let subdir = temp_dir.child("subdir");
    subdir.create_dir_all().unwrap();

    let test_file = "test_file.txt";
    let file = temp_dir.child(test_file);
    let _ = dir_handle
        .safe_open_file(
            &DEFAULT_TEST_CEDAR_AUTH,
            test_file,
            OpenFileOptionsBuilder::default()
                .create(true)
                .build()
                .unwrap(),
        )
        .unwrap();

    let result = dir_handle.safe_delete(
        &DEFAULT_TEST_CEDAR_AUTH,
        DeleteDirOptionsBuilder::default()
            .force(force)
            .recursive(recursive)
            .build()
            .unwrap(),
    );

    if recursive {
        assert!(
            result.is_ok(),
            "Expected directory deletion with recursive flag to succeed, but received {:?}",
            result
        );
        assert!(
            !temp_dir.exists(),
            "Expected parent directory to be deleted, but it still exists"
        );
        assert!(
            !subdir.exists(),
            "Expected subdirectory to be deleted, but it still exists"
        );
        assert!(
            !file.exists(),
            "Expected file to be deleted, but it still exists"
        );
    } else {
        assert_error_contains(result, expected_error);
        assert!(
            temp_dir.exists(),
            "Expected parent directory to still exist"
        );
        assert!(subdir.exists(), "Expected subdirectory to still exist");
        assert!(file.exists(), "Expected file to still exist");
    }

    Ok(())
}

/// Given: A directory that is a read-only directory
/// When: The directory is deleted with [`rust_safe_io::DirConfig::recursive`] and [`rust_safe_io::DirConfig::force`] combinations
/// Then: The directory is not deleted an error is thrown.
#[rstest]
#[case::non_recursive_and_no_force(false, false)]
#[case::recursive_and_no_force(true, false)]
#[case::non_recursive_and_force(false, true)]
#[case::recursive_and_force(true, true)]
fn test_safe_delete_permission_denied(
    #[case] recursive: bool,
    #[case] force: bool,
) -> Result<(), anyhow::Error> {
    let (_temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let readonly_mode = 0o644;
    let original_mode = metadata(&temp_dir_path)?.mode() & PERMISSION_EXTRACT_BITMASK;
    set_permissions(&temp_dir_path, Permissions::from_mode(readonly_mode))?;

    let result = dir_handle.safe_delete(
        &DEFAULT_TEST_CEDAR_AUTH,
        DeleteDirOptionsBuilder::default()
            .force(force)
            .recursive(recursive)
            .build()
            .unwrap(),
    );

    // restore original permissions to allow cleanup as dir is not deletable otherwise
    set_permissions(&temp_dir_path, Permissions::from_mode(original_mode))?;

    assert_error_contains(result, "Error removing directory:");

    Ok(())
}

/// Given: A directory and an unauthorized user
/// When: The directory is deleted with [`rust_safe_io::DirConfig::recursive`] and [`rust_safe_io::DirConfig::force`] combinations
/// Then: Access is denied
#[rstest]
#[case::non_recursive_no_force(false, false)]
#[case::recursive_no_force(true, false)]
#[case::non_recursive_force(false, true)]
#[case::recursive_force(true, true)]
fn test_unauthorized_safe_delete_dir(#[case] recursive: bool, #[case] force: bool) -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"forbid(
            principal == User::"{principal}",
            action == {},
            resource
        );"#,
        FilesystemAction::Delete,
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let result = dir_handle.safe_delete(
        &test_cedar_auth,
        DeleteDirOptionsBuilder::default()
            .force(force)
            .recursive(recursive)
            .build()
            .unwrap(),
    );

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Delete
    );
    assert_error_contains(result, &expected_error);
    assert!(
        temp_dir.exists(),
        "Expected directory to still exist after unauthorized deletion attempt"
    );

    Ok(())
}
