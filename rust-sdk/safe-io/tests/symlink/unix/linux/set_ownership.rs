use anyhow::Result;
use assert_fs::prelude::{FileWriteStr, PathChild, SymlinkToFile};
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::io::create_temp_dir_and_path;
use rust_safe_io::options::SetOwnershipOptionsBuilder;

use crate::test_common::open_test_dir_handle;

/// NB: we can't create new users and groups in Rust integration tests because we don't have control over the test environment.
/// Given: A symlink and an authorized user
/// When: `set_ownership` is called with the current user and group
/// Then: The ownership remains unchanged and the function returns successfully
#[rstest::rstest]
#[case::neither_provided(false, false)]
#[case::user_provided(true, false)]
#[case::group_provided(false, true)]
#[case::both_provided(true, true)]
fn test_set_ownership_symlink(
    #[case] user_provided: bool,
    #[case] group_provided: bool,
) -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let target_file = temp_dir.child("target.txt");
    target_file.write_str("target content")?;
    let symlink = temp_dir.child("test_symlink");
    symlink.symlink_to_file("target.txt")?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let symlink_handle = dir_handle.safe_open_symlink(&DEFAULT_TEST_CEDAR_AUTH, "test_symlink")?;

    let ownership_before = symlink_handle.get_ownership_unchecked()?;
    let user_before = ownership_before.user().to_string();
    let group_before = ownership_before.group().to_string();

    let mut set_ownership_options_builder = SetOwnershipOptionsBuilder::default();

    if user_provided {
        set_ownership_options_builder.user(user_before.clone());
    }
    if group_provided {
        set_ownership_options_builder.group(group_before.clone());
    }

    let set_ownership_options = set_ownership_options_builder.build()?;

    let result = symlink_handle.set_ownership(&DEFAULT_TEST_CEDAR_AUTH, set_ownership_options);

    assert!(
        result.is_ok(),
        "Expected symlink set_ownership ok, got {:?}",
        result
    );

    let ownership_after = symlink_handle.get_ownership_unchecked()?;
    let user_after = ownership_after.user().to_string();
    let group_after = ownership_after.group().to_string();

    assert_eq!(
        user_after, user_before,
        "Expected user ownership to remain unchanged"
    );
    assert_eq!(
        group_after, group_before,
        "Expected group ownership to remain unchanged"
    );

    Ok(())
}

/// Given: A symlink and an unauthorized user
/// When: `set_ownership` is called
/// Then: An auth error is returned
#[test]
fn test_set_ownership_symlink_unauthorized() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let target_file = temp_dir.child("target.txt");
    target_file.write_str("target content")?;
    let symlink = temp_dir.child("test_symlink");
    symlink.symlink_to_file("target.txt")?;

    let symlink_path = symlink.path().to_string_lossy().to_string();

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let symlink_handle = dir_handle.safe_open_symlink(&DEFAULT_TEST_CEDAR_AUTH, "test_symlink")?;

    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action,
            resource
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{symlink_path}"
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

    let result = symlink_handle.set_ownership(&test_cedar_auth, set_ownership_options);

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Chown
    );
    assert_error_contains(result, &expected_error);

    Ok(())
}
