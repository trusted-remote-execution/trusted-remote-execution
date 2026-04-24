use crate::test_common::*;
use anyhow::Result;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rex_test_utils::assertions::assert_error_contains;
use std::fs::metadata;
use std::path::Path;

/// Given: A file to get the last modified time
/// When: The file's last modified time is retrieved with safe I/O
/// Then: The last modified time is returned correctly
#[test]
#[cfg(unix)]
fn test_safe_get_last_modified_time_success() -> Result<()> {
    let test_contents = open_dir_and_file()?;

    let full_path = Path::new(&test_contents.dir_name).join(&test_contents.file_name);
    let expected_mtime = metadata(&full_path)?
        .modified()?
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos() as i64;

    let actual_mtime = test_contents
        .file_handle
        .safe_get_last_modified_time(&DEFAULT_TEST_CEDAR_AUTH)?;

    assert_eq!(
        actual_mtime, expected_mtime,
        "Expected last modified time to match filesystem metadata"
    );

    Ok(())
}

/// Given: A file but an unauthorized user
/// When: The file's last modified time is retrieved with safe I/O
/// Then: Access is denied
#[test]
#[cfg(unix)]
fn test_unauthorized_safe_get_last_modified_time() -> Result<()> {
    let test_contents = open_dir_and_file()?;
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

    let result = test_contents
        .file_handle
        .safe_get_last_modified_time(&test_cedar_auth);

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Stat
    );
    assert_error_contains(result, &expected_error);

    Ok(())
}

/// Given: an opened RcFileHandle and an authorized user
/// When: the user calls get metadata for the file
/// Then: The metadata is returned successfully
#[test]
fn test_metadata_file_success() -> Result<()> {
    let test_contents = open_dir_and_file()?;
    let metadata = test_contents
        .file_handle
        .metadata(&DEFAULT_TEST_CEDAR_AUTH)?;

    assert!(metadata.cap_std_metadata().is_file());
    Ok(())
}

/// Given: an opened RcFileHandle and an unauthorized user
/// When: the user calls get metadata for the file
/// Then: An authorization error is returned
#[test]
fn test_unauthorized_metadata_file() -> Result<()> {
    let test_contents = open_dir_and_file()?;

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

    let result = test_contents.file_handle.metadata(&test_cedar_auth);

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Stat
    );
    assert_error_contains(result, &expected_error);
    Ok(())
}
