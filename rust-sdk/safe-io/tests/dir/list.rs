use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::io::{create_file_with_content, create_temp_dir_and_path};

use anyhow::Result;
use assert_fs::fixture::{PathChild, PathCreateDir};

use crate::test_common::open_test_dir_handle;
use rex_cedar_auth::test_utils::{TestCedarAuthBuilder, get_test_rex_principal};

/// Given: A directory with files and subdirectories
/// When: Listing the directory contents
/// Then: The correct entries should be returned
#[test]
fn test_safe_list_dir() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let _file1_path = create_file_with_content(&temp_dir.path(), "file1.txt", "content1")?;
    let _file2_path = create_file_with_content(&temp_dir.path(), "file2.txt", "content2")?;

    let subdir = temp_dir.child("subdir");
    subdir.create_dir_all()?;

    let principal = get_test_rex_principal();
    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [{},{}],
            resource
        );"#,
        &FilesystemAction::Open,
        &FilesystemAction::Read
    );
    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(policy)
        .build()?
        .create();

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let entries = dir_handle.safe_list_dir(&test_cedar_auth)?;

    assert_eq!(entries.len(), 3);

    let file_count = entries.iter().filter(|e| e.is_file()).count();
    let dir_count = entries.iter().filter(|e| e.is_dir()).count();
    assert_eq!(file_count, 2);
    assert_eq!(dir_count, 1);

    Ok(())
}

/// Given: A directory and a user with only open permission but not list permission
/// When: Attempting to list the directory contents
/// Then: Access is denied
#[test]
fn test_unauthorized_safe_list_dir() -> Result<()> {
    let (_temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let principal = get_test_rex_principal();
    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action == {},
            resource
        );"#,
        &FilesystemAction::Open
    );
    let cedar_auth = TestCedarAuthBuilder::default()
        .policy(policy)
        .build()?
        .create();

    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let result = dir_handle.safe_list_dir(&cedar_auth);
    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Read
    );
    assert_error_contains(result, &expected_error);

    Ok(())
}
