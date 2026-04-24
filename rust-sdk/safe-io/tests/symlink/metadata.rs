#![cfg(target_os = "linux")]
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::io::create_temp_dir;
use rust_safe_io::DirConfigBuilder;
use rust_safe_io::options::OpenDirOptionsBuilder;

use anyhow::Result;
use assert_fs::fixture::FileWriteStr;
use assert_fs::prelude::{PathChild, SymlinkToFile};

/// Given: an opened RcSymlinkHandle and an authorized user
/// When: the user calls metadata for the symlink
/// Then: The metadata is returned successfully and indicates it's a symlink
#[test]
fn test_metadata_symlink_success() -> Result<()> {
    let temp_dir = create_temp_dir()?;
    let temp_dir_path = temp_dir.path().to_str().unwrap().to_string();

    let target_file = temp_dir.child("target_file.txt");
    let target_content = "target file content";
    target_file.write_str(target_content)?;

    let symlink_file = temp_dir.child("test_symlink");
    symlink_file.symlink_to_file(target_file.path())?;

    let dir_config = DirConfigBuilder::default()
        .path(temp_dir_path.clone())
        .build()?;
    let dir_handle = dir_config.safe_open(
        &DEFAULT_TEST_CEDAR_AUTH,
        OpenDirOptionsBuilder::default().build().unwrap(),
    )?;

    let symlink_handle = dir_handle.safe_open_symlink(&DEFAULT_TEST_CEDAR_AUTH, "test_symlink")?;
    let metadata = symlink_handle.metadata(&DEFAULT_TEST_CEDAR_AUTH)?;

    assert!(metadata.cap_std_metadata().is_symlink());

    let expected_target = format!("{}/target_file.txt", temp_dir_path);
    assert_eq!(metadata.symlink_target(), Some(expected_target));

    Ok(())
}

/// Given: an opened RcSymlinkHandle and a user with Stat permission but no Read permission
/// When: the user calls metadata for the symlink
/// Then: The metadata is returned successfully but with symlink_target set to None
#[test]
fn test_metadata_symlink_stat_only_no_read() -> Result<()> {
    let temp_dir = create_temp_dir()?;
    let temp_dir_path = temp_dir.path().to_str().unwrap().to_string();

    let target_file = temp_dir.child("target_file.txt");
    let target_content = "target file content";
    target_file.write_str(target_content)?;

    let symlink_file = temp_dir.child("test_symlink");
    symlink_file.symlink_to_file(target_file.path())?;

    let principal = get_test_rex_principal();
    // Allow Stat but forbid Read - this will allow getting metadata but prevent reading the symlink target
    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action == {},
            resource
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource
        );"#,
        FilesystemAction::Stat,
        FilesystemAction::Read
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let dir_config = DirConfigBuilder::default()
        .path(temp_dir_path.clone())
        .build()?;
    let dir_handle = dir_config.safe_open(
        &DEFAULT_TEST_CEDAR_AUTH,
        OpenDirOptionsBuilder::default().build().unwrap(),
    )?;

    let symlink_handle = dir_handle.safe_open_symlink(&DEFAULT_TEST_CEDAR_AUTH, "test_symlink")?;
    let metadata = symlink_handle.metadata(&test_cedar_auth)?;

    // Metadata should be returned successfully
    assert!(metadata.cap_std_metadata().is_symlink());
    // But symlink_target should be None since Read permission is denied
    assert_eq!(metadata.symlink_target(), None);

    Ok(())
}

/// Given: an opened RcSymlinkHandle and an unauthorized user
/// When: the user calls metadata for the symlink
/// Then: An authorization error is returned
#[test]
fn test_unauthorized_metadata_symlink() -> Result<()> {
    let temp_dir = create_temp_dir()?;
    let temp_dir_path = temp_dir.path().to_str().unwrap().to_string();

    let target_file = temp_dir.child("target_file.txt");
    let target_content = "target file content";
    target_file.write_str(target_content)?;

    let symlink_file = temp_dir.child("test_symlink");
    symlink_file.symlink_to_file(target_file.path())?;

    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"forbid(
            principal == User::"{principal}",
            action == {},
            resource
        );"#,
        FilesystemAction::Stat
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let dir_config = DirConfigBuilder::default()
        .path(temp_dir_path.clone())
        .build()?;
    let dir_handle = dir_config.safe_open(
        &DEFAULT_TEST_CEDAR_AUTH,
        OpenDirOptionsBuilder::default().build().unwrap(),
    )?;

    let symlink_handle = dir_handle.safe_open_symlink(&DEFAULT_TEST_CEDAR_AUTH, "test_symlink")?;
    let result = symlink_handle.metadata(&test_cedar_auth);

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Stat
    );
    assert_error_contains(result, &expected_error);

    Ok(())
}
