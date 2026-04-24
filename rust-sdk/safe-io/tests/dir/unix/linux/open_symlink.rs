use anyhow::Result;
use assert_fs::prelude::{FileWriteStr, PathChild, SymlinkToFile};
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::io::create_temp_dir_and_path;
use rstest::rstest;
use rust_safe_io::error_constants::{
    FILE_DNE_ERR, FILE_PATH_INVALID, NOT_A_SYMLINK, PATH_TRAVERSAL,
};

use crate::test_common::open_test_dir_handle;

/// Given: A symlink name that contains bad paths or invalid types
/// When: safe_open_symlink is called
/// Then: The symlink is not opened and an error is thrown
#[rstest]
#[case::file_does_not_exist("nonexistent_symlink", FILE_DNE_ERR)]
#[case::path_with_slash("symlink/nested", FILE_PATH_INVALID)]
#[case::path_with_dot_syntax("./test_symlink", FILE_PATH_INVALID)]
#[case::path_traversal("../test_symlink", PATH_TRAVERSAL)]
#[case::empty_name("", FILE_DNE_ERR)]
fn test_open_symlink_errors(#[case] symlink_name: &str, #[case] expected_err: &str) -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let target_file = temp_dir.child("target.txt");
    target_file.write_str("target content")?;
    let symlink = temp_dir.child("test_symlink");
    symlink.symlink_to_file("target.txt")?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let result = dir_handle.safe_open_symlink(&DEFAULT_TEST_CEDAR_AUTH, symlink_name);

    assert_error_contains(result, expected_err);

    Ok(())
}

/// Given: A symlink and unauthorized user
/// When: safe_open_symlink is called without Open permission
/// Then: An authorization error is returned
#[test]
fn test_unauthorized_open_symlink() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let principal = get_test_rex_principal();

    let target_file = temp_dir.child("target.txt");
    target_file.write_str("target content")?;
    let symlink = temp_dir.child("test_symlink");
    symlink.symlink_to_file("target.txt")?;

    let symlink_path = symlink.path().to_string_lossy().to_string();

    let test_policy = format!(
        r#"permit(
            principal,
            action,
            resource
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{symlink_path}"
        );"#,
        FilesystemAction::Open
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()?
        .create();

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let result = dir_handle.safe_open_symlink(&test_cedar_auth, "test_symlink");

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Open
    );
    assert_error_contains(result, &expected_error);

    Ok(())
}

/// Given: A regular file (not a symlink)
/// When: safe_open_symlink is called on the regular file
/// Then: The operation fails with NOT_A_SYMLINK error
#[test]
fn test_open_regular_file_fails() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let regular_file = temp_dir.child("regular_file.txt");
    regular_file.write_str("not a symlink")?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let result = dir_handle.safe_open_symlink(&DEFAULT_TEST_CEDAR_AUTH, "regular_file.txt");

    assert_error_contains(result, NOT_A_SYMLINK);

    Ok(())
}
