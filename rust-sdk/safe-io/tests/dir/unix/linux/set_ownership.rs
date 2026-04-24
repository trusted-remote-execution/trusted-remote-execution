use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::io::create_temp_dir_and_path;
use rust_safe_io::RcDirHandle;
use rust_safe_io::options::SetOwnershipOptionsBuilder;

use anyhow::Result;
use assert_fs::fixture::FileWriteStr;
use assert_fs::prelude::{PathChild, PathCreateDir};
use rstest::rstest;

use crate::test_common::{init_test_logger, open_test_dir_handle};

/// Helper to get Dir ownership as a tuple instead of an Ownership struct
fn get_dir_ownership(dir_handle: &RcDirHandle) -> (String, String) {
    let ownership = dir_handle
        .safe_get_ownership(&DEFAULT_TEST_CEDAR_AUTH)
        .unwrap();
    let user = ownership.user();
    let group = ownership.group();
    (user.to_string(), group.to_string())
}

/// NB: we can't create new users and groups in Rust integration tests because we don't have control over the test environment
/// More thorough testing will be performed in REX integration tests
/// Given: A directory and an authorized user
/// When: `set_ownership` is called with the current group and user
/// Then: The ownership is unchanged and the function returns successfully
#[rstest]
#[case::neither_provided(false, false, false)]
#[case::user_provided(true, false, false)]
#[case::group_provided(false, true, false)]
#[case::both_provided(true, true, false)]
#[case::both_provided_recursive(true, true, true)]
fn test_set_ownership_dir(
    #[case] user_provided: bool,
    #[case] group_provided: bool,
    #[case] is_recursive: bool,
) -> Result<()> {
    init_test_logger();

    let (_temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let (user_before, group_before) = get_dir_ownership(&dir_handle);

    let mut set_ownership_options_builder = SetOwnershipOptionsBuilder::default();

    if user_provided {
        set_ownership_options_builder.user(user_before.clone());
    }
    if group_provided {
        set_ownership_options_builder.group(group_before.clone());
    }

    set_ownership_options_builder.recursive(is_recursive);

    let set_ownership_options = set_ownership_options_builder.build()?;

    let result = dir_handle.set_ownership(&DEFAULT_TEST_CEDAR_AUTH, set_ownership_options);

    assert!(
        result.is_ok(),
        "Expected directory set_ownership ok, but received {:?}",
        result
    );
    let (user_after, group_after) = get_dir_ownership(&dir_handle);
    assert_eq!(user_after, user_before);
    assert_eq!(group_after, group_before);

    Ok(())
}

/// Given: A directory and an unauthorized user
/// When: `set_ownership` is called
/// Then: An error is returned
#[test]
fn test_set_ownership_dir_unauthorized() -> Result<()> {
    let (_temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"forbid(
            principal == User::"{principal}",
            action == {},
            resource
        );"#,
        FilesystemAction::Chown
    );
    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()?
        .create();

    let set_ownership_options = SetOwnershipOptionsBuilder::default()
        .user(principal.clone())
        .build()?;

    let result = dir_handle.set_ownership(&test_cedar_auth, set_ownership_options);

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Chown
    );
    assert_error_contains(result, &expected_error);
    Ok(())
}

/// Given: A directory with a subdirectory that fails Cedar authorization during traversal
/// When: Recursive set_ownership tries to open the subdirectory with restricted permissions
/// Then: The error is logged and traversal continues
#[rstest]
#[case::open_denied(FilesystemAction::Open)]
#[case::chown_denied(FilesystemAction::Chown)]
fn test_set_ownership_dir_recursive_cedar_denied_subdir(
    #[case] forbidden_action: FilesystemAction,
) -> Result<()> {
    init_test_logger();

    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let subdir = temp_dir.child("restricted_subdir");
    subdir.create_dir_all()?;

    let file_in_subdir = subdir.child("test_file.txt");
    file_in_subdir.write_str("test content")?;

    let (root_user, root_group) = get_dir_ownership(&open_test_dir_handle(&temp_dir_path));

    let principal = get_test_rex_principal();
    let subdir_path = subdir.path().to_string_lossy();
    let test_policy = format!(
        r#"
        permit(
            principal == User::"{principal}",
            action,
            resource
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::Dir::"{subdir_path}"
        );
        "#,
        forbidden_action
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()?
        .create();

    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let result = dir_handle.set_ownership(
        &test_cedar_auth,
        SetOwnershipOptionsBuilder::default()
            .user(root_user.clone())
            .group(root_group.clone())
            .recursive(true)
            .build()?,
    );

    assert!(result.is_ok());

    let (root_new_user, root_new_group) = get_dir_ownership(&open_test_dir_handle(&temp_dir_path));
    assert_eq!(root_new_user, root_user);
    assert_eq!(root_new_group, root_group);

    Ok(())
}

/// Given: A directory with a file that fails Cedar authorization during traversal
/// When: Recursive set_ownership tries to access the file with restricted permissions
/// Then: The error is logged and traversal continues
#[rstest]
#[case::open_denied(FilesystemAction::Open)]
#[case::chown_denied(FilesystemAction::Chown)]
fn test_set_ownership_dir_recursive_cedar_denied_file(
    #[case] forbidden_action: FilesystemAction,
) -> Result<()> {
    init_test_logger();

    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let restricted_file = temp_dir.child("restricted_file.txt");
    restricted_file.write_str("test content")?;

    let accessible_file = temp_dir.child("accessible_file.txt");
    accessible_file.write_str("accessible content")?;

    let (root_user, root_group) = get_dir_ownership(&open_test_dir_handle(&temp_dir_path));

    let principal = get_test_rex_principal();
    let file_path = restricted_file.path().to_string_lossy();
    let test_policy = format!(
        r#"
        permit(
            principal == User::"{principal}",
            action,
            resource
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{file_path}"
        );
        "#,
        forbidden_action
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()?
        .create();

    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let result = dir_handle.set_ownership(
        &test_cedar_auth,
        SetOwnershipOptionsBuilder::default()
            .user(root_user.clone())
            .group(root_group.clone())
            .recursive(true)
            .build()?,
    );

    assert!(result.is_ok());

    let (root_new_user, root_new_group) = get_dir_ownership(&open_test_dir_handle(&temp_dir_path));
    assert_eq!(root_new_user, root_user);
    assert_eq!(root_new_group, root_group);

    Ok(())
}

/// Given: A directory with a symlink that fails Cedar authorization during traversal
/// When: Recursive set_ownership tries to access the symlink with restricted permissions
/// Then: The error is logged and traversal continues
#[rstest]
#[case::open_denied(FilesystemAction::Open)]
#[case::chown_denied(FilesystemAction::Chown)]
fn test_set_ownership_dir_recursive_cedar_denied_symlink(
    #[case] forbidden_action: FilesystemAction,
) -> Result<()> {
    init_test_logger();

    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let target_file = temp_dir.child("target.txt");
    target_file.write_str("target content")?;

    let symlink = temp_dir.child("restricted_symlink");
    std::os::unix::fs::symlink(target_file.path(), symlink.path())?;

    let accessible_file = temp_dir.child("accessible_file.txt");
    accessible_file.write_str("accessible content")?;

    let (root_user, root_group) = get_dir_ownership(&open_test_dir_handle(&temp_dir_path));

    let principal = get_test_rex_principal();
    let symlink_path = symlink.path().to_string_lossy();
    let test_policy = format!(
        r#"
        permit(
            principal == User::"{principal}",
            action,
            resource
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{symlink_path}"
        );
        "#,
        forbidden_action
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()?
        .create();

    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let result = dir_handle.set_ownership(
        &test_cedar_auth,
        SetOwnershipOptionsBuilder::default()
            .user(root_user.clone())
            .group(root_group.clone())
            .recursive(true)
            .build()?,
    );

    assert!(result.is_ok());

    let (root_new_user, root_new_group) = get_dir_ownership(&open_test_dir_handle(&temp_dir_path));
    assert_eq!(root_new_user, root_user);
    assert_eq!(root_new_group, root_group);

    Ok(())
}
