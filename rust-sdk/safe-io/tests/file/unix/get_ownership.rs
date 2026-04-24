use crate::test_common::open_dir_and_file;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rex_test_utils::assertions::assert_error_contains;

use anyhow::Result;
use std::os::unix::fs::MetadataExt;
use sysinfo::{Groups, Users};

/// Get the user id from user name. Panics if the user name is invalid
fn get_uid(user: &str) -> u32 {
    let users = Users::new_with_refreshed_list();
    **users.iter().find(|u| u.name() == user).unwrap().id()
}

/// Get the group id from group name. Panics if the group name is invalid
fn get_gid(group: &str) -> u32 {
    let groups = Groups::new_with_refreshed_list();
    **groups.iter().find(|g| g.name() == group).unwrap().id()
}

/// Given: A file and an authorized user
/// When: Calling safe_get_ownership on the file
/// Then: The file owner and group are returned successfully in a FileOwnership struct
#[test]
#[cfg(unix)]
fn test_safe_get_ownership_file_success() -> Result<()> {
    let test_contents = open_dir_and_file()?;

    let ownership = test_contents
        .file_handle
        .safe_get_ownership(&DEFAULT_TEST_CEDAR_AUTH)?;
    let user = ownership.user();
    let group = ownership.group();

    let temp_dir = &test_contents._tempdir;
    let actual_uid = temp_dir.metadata().unwrap().uid();
    let actual_gid = temp_dir.metadata().unwrap().gid();

    assert_eq!(get_uid(user.as_str()), actual_uid);
    assert_eq!(get_gid(group.as_str()), actual_gid);

    Ok(())
}

/// Given: A file and an unauthorized user
/// When: Calling safe_get_ownership on the file
/// Then: An authorization error is returned
#[test]
#[cfg(unix)]
fn test_unauthorized_safe_get_ownership_file() -> Result<()> {
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
        .safe_get_ownership(&test_cedar_auth);

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Stat
    );
    assert_error_contains(result, &expected_error);

    Ok(())
}
