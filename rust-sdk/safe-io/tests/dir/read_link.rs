use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::io::{create_temp_dir, create_temp_dir_and_path};
use rust_safe_io::DirConfigBuilder;
use rust_safe_io::options::OpenDirOptionsBuilder;

use anyhow::Result;
use assert_fs::fixture::FileWriteStr;
use assert_fs::prelude::{PathChild, PathCreateDir, SymlinkToFile};

/// Given: A symlink and an unauthorized user
/// When: The symlink is read with safe I/O
/// Then: Access is denied
#[test]
fn test_unauthorized_safe_read_link_target() -> Result<()> {
    let temp_dir = create_temp_dir()?;
    let temp_dir_path = temp_dir.path().to_str().unwrap().to_string();
    let real_dir = temp_dir.child("real_dir");
    real_dir.create_dir_all()?;

    let target_file = real_dir.child("target_file.txt");
    let target_content = "target file content";
    target_file.write_str(target_content)?;

    let symlink_file = temp_dir.child("valid_link");

    symlink_file.symlink_to_file(target_file.path())?;

    let principal = get_test_rex_principal();
    let policy = format!(
        r#"forbid(
            principal == User::"{principal}",
            action == {},
            resource
        );"#,
        FilesystemAction::Read
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(policy)
        .build()
        .unwrap()
        .create();

    // Open directory
    let dir_config = DirConfigBuilder::default().path(temp_dir_path).build()?;
    let dir_handle = dir_config.safe_open(
        &DEFAULT_TEST_CEDAR_AUTH,
        OpenDirOptionsBuilder::default().build().unwrap(),
    )?;

    // Directly assert that we get an error containing the expected message
    let result = dir_handle.safe_read_link_target(&test_cedar_auth, "symlink");

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Read
    );
    assert_error_contains(result, &expected_error);

    Ok(())
}

/// Given: A file that is not a symlink
/// When: Attempting to resolve it as a symlink
/// Then: An error is returned indicating the file is not a symlink
#[test]
fn test_safe_read_link_target_not_a_symlink() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let regular_file = temp_dir.child("regular_file.txt");
    let target_content = "target file content";
    regular_file.write_str(target_content)?;

    let dir_config = DirConfigBuilder::default()
        .path(temp_dir_path.clone())
        .build()?;
    let dir_handle = dir_config.safe_open(
        &DEFAULT_TEST_CEDAR_AUTH,
        OpenDirOptionsBuilder::default().build().unwrap(),
    )?;

    let result = dir_handle.safe_read_link_target(&DEFAULT_TEST_CEDAR_AUTH, "regular_file.txt");

    assert_error_contains(result, "Invalid argument");
    Ok(())
}

/// Given: A file that is a symlink
/// When: Attempting to resolve its path as a symlink
/// Then: The path to the target of the symlink is returned
#[test]
fn test_safe_read_link_target_path() -> Result<()> {
    let temp_dir = create_temp_dir()?;
    let temp_dir_path = temp_dir.path().to_str().unwrap().to_string();

    let target_file = temp_dir.child("target_file.txt");
    let target_content = "target file content";
    target_file.write_str(target_content)?;

    let symlink_file = temp_dir.child("valid_link");

    symlink_file.symlink_to_file(target_file.path())?;

    let dir_config = DirConfigBuilder::default()
        .path(temp_dir_path.clone())
        .build()?;
    let dir_handle = dir_config.safe_open(
        &DEFAULT_TEST_CEDAR_AUTH,
        OpenDirOptionsBuilder::default().build().unwrap(),
    )?;

    let result = dir_handle.safe_read_link_target(&DEFAULT_TEST_CEDAR_AUTH, "valid_link")?;
    let full_target_path = format!("{temp_dir_path}/target_file.txt");
    assert_eq!(result, full_target_path);
    Ok(())
}
