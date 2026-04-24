use crate::test_common::*;
use anyhow::Result;
use assert_fs::fixture::{FileWriteStr, PathChild, SymlinkToFile};
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::io::create_temp_dir_and_path;
use rstest::rstest;
use rust_safe_io::error_constants::FILE_DNE_ERR;
use rust_safe_io::options::{DeleteFileOptionsBuilder, OpenFileOptionsBuilder};
use std::fs::{Permissions, metadata, read_to_string, set_permissions};
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;

const PERMISSION_EXTRACT_BITMASK: u32 = 0o777;

/// Given: A file that is a real file and is in a real directory and an authorized user
/// When: [`rust_safe_io::delete_file`] is called to delete a file with both `force` = true/false case
/// Then: The file is deleted successfully with no errors
#[rstest]
#[case::no_force(true)]
#[case::force(false)]
fn test_delete_file_success(#[case] force: bool) -> Result<(), anyhow::Error> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let test_file = "test_file.txt";
    let _ = temp_dir.child(test_file);

    let file_handle = dir_handle
        .safe_open_file(
            &DEFAULT_TEST_CEDAR_AUTH,
            test_file,
            OpenFileOptionsBuilder::default()
                .create(true)
                .build()
                .unwrap(),
        )
        .unwrap();

    let result = file_handle.safe_delete(
        &DEFAULT_TEST_CEDAR_AUTH,
        DeleteFileOptionsBuilder::default()
            .force(force)
            .build()
            .unwrap(),
    );

    assert!(
        result.is_ok(),
        "Expected file deletion to succeed, but received {:?}",
        result
    );
    assert!(
        !temp_dir.child(test_file).exists(),
        "Expected file to be deleted, but it still exists"
    );

    Ok(())
}

/// Given: A file that is opened without the write option
/// When: [`rust_safe_io::delete_file`] is called to delete a file with both `force` = true/false case
/// Then: The file is deleted successfully
#[rstest]
#[case::no_force(false)]
#[case::force(true)]
fn test_safe_delete_file_without_write_option_success(
    #[case] force: bool,
) -> Result<(), anyhow::Error> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let test_file = "test_file_no_write.txt";
    let _ = temp_dir.child(test_file);

    // initial open to create the file
    // Use a closure to auto-close file after it is written
    {
        let _ = dir_handle.safe_open_file(
            &DEFAULT_TEST_CEDAR_AUTH,
            test_file,
            OpenFileOptionsBuilder::default().create(true).build()?,
        )?;
    }

    // open the file again, but without the write flag this time
    let file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        test_file,
        OpenFileOptionsBuilder::default()
            .read(true)
            .write(false)
            .build()?,
    )?;

    let result = file_handle.safe_delete(
        &DEFAULT_TEST_CEDAR_AUTH,
        DeleteFileOptionsBuilder::default()
            .force(force)
            .build()
            .unwrap(),
    );

    assert!(
        result.is_ok(),
        "Expected file deletion without write option to succeed, but received {:?}",
        result
    );
    assert!(
        !temp_dir.child(test_file).exists(),
        "Expected file to be deleted, but it still exists"
    );

    Ok(())
}

/// Given: A file that is in a non-existent directory
/// When: [`rust_safe_io::delete_file`] is called to delete a file with both `force` = true/false case
/// Then: The file is deleted successfully with no errors when `force` = true. An error is thrown when `force` = false
#[rstest]
#[case::non_existent_dir_no_force(true, false, FILE_DNE_ERR)]
#[case::non_existent_dir_force(true, true, "")]
#[case::non_existent_file_no_force(false, false, FILE_DNE_ERR)]
#[case::non_existent_file_force(false, true, "")]
fn test_safe_delete_file_non_existent(
    #[case] delete_dir: bool,
    #[case] force: bool,
    #[case] expected_error: &str,
) -> Result<(), anyhow::Error> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let test_file = "test_file.txt";
    let file = temp_dir.child(test_file);

    let file_handle = dir_handle
        .safe_open_file(
            &DEFAULT_TEST_CEDAR_AUTH,
            test_file,
            OpenFileOptionsBuilder::default()
                .create(true)
                .build()
                .unwrap(),
        )
        .unwrap();

    if delete_dir {
        use rust_safe_io::options::DeleteDirOptionsBuilder;
        let _ = dir_handle.safe_delete(
            &DEFAULT_TEST_CEDAR_AUTH,
            DeleteDirOptionsBuilder::default()
                .force(true)
                .recursive(true)
                .build()
                .unwrap(),
        );
        assert!(!temp_dir.exists());
        assert!(!temp_dir.child(file).exists());
    } else {
        let _ = file_handle.safe_delete(
            &DEFAULT_TEST_CEDAR_AUTH,
            DeleteFileOptionsBuilder::default().build().unwrap(),
        );
        assert!(!temp_dir.child(file).exists());
    }

    let result = file_handle.safe_delete(
        &DEFAULT_TEST_CEDAR_AUTH,
        DeleteFileOptionsBuilder::default()
            .force(force)
            .build()
            .unwrap(),
    );

    if force {
        assert!(
            result.is_ok(),
            "Expected file deletion with force flag to succeed, but received {:?}",
            result
        );
    } else {
        assert_error_contains(result, expected_error);
    }

    Ok(())
}

/// Given: A file that is in a read-only directory
/// When: [`rust_safe_io::delete_file`] is called to delete a file with both `force` = true/false case
/// Then: The file is not deleted an error is thrown
#[rstest]
#[case::no_force(false)]
#[case::force(true)]
fn test_safe_delete_file_permission_denied(#[case] force: bool) -> Result<(), anyhow::Error> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let test_file = "test_file.txt";
    let _ = temp_dir.child(test_file);

    let file_handle = dir_handle
        .safe_open_file(
            &DEFAULT_TEST_CEDAR_AUTH,
            test_file,
            OpenFileOptionsBuilder::default()
                .create(true)
                .build()
                .unwrap(),
        )
        .unwrap();

    let readonly_mode = 0o555;
    let original_mode = metadata(&temp_dir_path)?.mode() & PERMISSION_EXTRACT_BITMASK;

    set_permissions(&temp_dir_path, Permissions::from_mode(readonly_mode))?;

    let result = file_handle.safe_delete(
        &DEFAULT_TEST_CEDAR_AUTH,
        DeleteFileOptionsBuilder::default()
            .force(force)
            .build()
            .unwrap(),
    );

    // restore original permissions to allow cleanup as dir is not deletable otherwise
    set_permissions(&temp_dir_path, Permissions::from_mode(original_mode))?;

    assert_error_contains(result, "Error removing file");

    Ok(())
}

/// Given: A file and an unauthorized user
/// When: [`rust_safe_io::delete_file`] is called to delete a file with both `force` = true/false case
/// Then: The file is not deleted an error is thrown
#[rstest]
#[case::no_force(false)]
#[case::force(true)]
fn test_unauthorized_safe_delete_file(#[case] force: bool) -> Result<(), anyhow::Error> {
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

    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let test_file = "test_file.txt";
    let _ = temp_dir.child(test_file);

    let file_handle = dir_handle
        .safe_open_file(
            &DEFAULT_TEST_CEDAR_AUTH,
            test_file,
            OpenFileOptionsBuilder::default()
                .create(true)
                .build()
                .unwrap(),
        )
        .unwrap();

    let result = file_handle.safe_delete(
        &test_cedar_auth,
        DeleteFileOptionsBuilder::default()
            .force(force)
            .build()
            .unwrap(),
    );

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Delete
    );
    assert_error_contains(result, &expected_error);

    Ok(())
}

/// Given: A symlink opened with follow_symlinks=true and restrictive Cedar policies
/// When: safe_delete is called on the file handle
/// Then: The symlink itself is deleted, not the target (Unix rm behavior)
#[test]
#[cfg(target_os = "linux")]
fn test_safe_delete_symlink_deletes_symlink_not_target() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let target_content = "target to preserve";
    let target_file = temp_dir.child("preserve_target.txt");
    target_file.write_str(target_content)?;
    let target_absolute_path = target_file.path().to_string_lossy().to_string();

    let symlink_file = temp_dir.child("delete_link");
    symlink_file.symlink_to_file("preserve_target.txt")?;
    let symlink_absolute_path = symlink_file.path().to_string_lossy().to_string();

    let principal = get_test_rex_principal();

    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{symlink_absolute_path}"
        );
        permit(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{target_absolute_path}"
        );
        permit(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{symlink_absolute_path}"
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{target_absolute_path}"
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Open,
        FilesystemAction::Delete,
        FilesystemAction::Delete
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let file_handle = dir_handle.safe_open_file(
        &test_cedar_auth,
        "delete_link",
        OpenFileOptionsBuilder::default()
            .read(true)
            .follow_symlinks(true)
            .build()
            .unwrap(),
    )?;

    file_handle.safe_delete(
        &test_cedar_auth,
        DeleteFileOptionsBuilder::default().build().unwrap(),
    )?;

    assert!(!symlink_file.exists(), "Expected symlink to be deleted");
    assert!(target_file.exists(), "Expected target file to be preserved");

    let preserved_content = read_to_string(target_file.path())?;
    assert_eq!(preserved_content, target_content);

    Ok(())
}
