use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::io::create_temp_dir_and_path;

use anyhow::Result;

use crate::test_common::open_test_dir_handle;

/// Given: an opened RcDirHandle and an authorized user
/// When: the user calls get metadata for the directory
/// Then: The metadata is returned successfully
#[test]
fn test_metadata_dir_success() -> Result<()> {
    let (_temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let metadata = dir_handle.metadata(&DEFAULT_TEST_CEDAR_AUTH)?;
    assert!(metadata.cap_std_metadata().is_dir());
    Ok(())
}

/// Given: an opened RcDirHandle and an unauthorized user
/// When: the user calls get metadata for the directory
/// Then: An authorization error is returned
#[test]
fn test_unauthorized_metadata_dir() -> Result<()> {
    let (_temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

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
        .build()?
        .create();

    let result = dir_handle.metadata(&test_cedar_auth);

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Stat
    );
    assert_error_contains(result, &expected_error);
    Ok(())
}
