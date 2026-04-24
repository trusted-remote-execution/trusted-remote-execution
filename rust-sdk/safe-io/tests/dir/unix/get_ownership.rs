use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::io::create_temp_dir_and_path;

use anyhow::Result;
use std::os::unix::fs::MetadataExt;
use sysinfo::{Groups, Users};

use crate::test_common::open_test_dir_handle;

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

/// Given: A directory and an authorized user
/// When: Calling safe_get_ownership on the directory
/// Then: The directory owner and group are returned successfully in a DirOwnership struct
#[test]
fn test_safe_get_ownership_success() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let ownership = dir_handle.safe_get_ownership(&DEFAULT_TEST_CEDAR_AUTH)?;
    let user = ownership.user();
    let group = ownership.group();

    let actual_uid = temp_dir.metadata().unwrap().uid();
    let actual_gid = temp_dir.metadata().unwrap().gid();

    assert_eq!(get_uid(user.as_str()), actual_uid);
    assert_eq!(get_gid(group.as_str()), actual_gid);

    temp_dir.close()?;
    Ok(())
}

/// Given: A directory and an unauthorized user
/// When: Calling safe_get_ownership on the directory
/// Then: An authorization error is returned
#[test]
fn test_unauthorized_safe_get_ownership() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
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

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let result = dir_handle.safe_get_ownership(&test_cedar_auth);

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Stat
    );
    assert_error_contains(result, &expected_error);

    temp_dir.close()?;
    Ok(())
}
