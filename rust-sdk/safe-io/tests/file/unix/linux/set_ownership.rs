use crate::test_common::open_dir_and_file;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rex_test_utils::assertions::assert_error_contains;

use anyhow::Result;
use rust_safe_io::options::SetOwnershipOptionsBuilder;
use std::rc::Rc;

/// Helper to get File ownership as a tuple instead of an Ownership struct
fn get_file_ownership(test_contents: &Rc<crate::test_common::TestContents>) -> (String, String) {
    let ownership = test_contents
        .file_handle
        .safe_get_ownership(&DEFAULT_TEST_CEDAR_AUTH)
        .unwrap();
    let user = ownership.user();
    let group = ownership.group();
    (user.to_string(), group.to_string())
}

/// NB: we can't create new users and groups in Rust integration tests because we don't have control over the test environment
/// More thorough testing will be performed in REX integration tests
/// Given: A file and an authorized user
/// When: `set_ownership` is called with the current user and group
/// Then: The ownership is unchanged and the function returns successfully
#[rstest::rstest]
#[case::neither_provided(false, false)]
#[case::user_provided(true, false)]
#[case::group_provided(false, true)]
#[case::both_provided(true, true)]
fn test_set_ownership_file(
    #[case] user_provided: bool,
    #[case] group_provided: bool,
) -> Result<()> {
    let test_contents = open_dir_and_file()?;
    let (user_before, group_before) = get_file_ownership(&test_contents);

    let mut set_ownership_options_builder = SetOwnershipOptionsBuilder::default();

    if user_provided {
        set_ownership_options_builder.user(user_before.clone());
    }
    if group_provided {
        set_ownership_options_builder.group(group_before.clone());
    }

    let set_ownership_options = set_ownership_options_builder.build()?;

    let result = test_contents
        .file_handle
        .set_ownership(&DEFAULT_TEST_CEDAR_AUTH, set_ownership_options);

    assert!(
        result.is_ok(),
        "Expected file set_ownership ok, got {:?}",
        result
    );

    let (user_after, group_after) = get_file_ownership(&test_contents);
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

/// Given: A file and an unauthorized user
/// When: `set_ownership` is called
/// Then: An error is returned
#[test]
fn test_set_ownership_file_unauthorized() -> Result<()> {
    let test_contents = open_dir_and_file()?;

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

    let result = test_contents
        .file_handle
        .set_ownership(&test_cedar_auth, set_ownership_options);

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Chown
    );
    assert_error_contains(result, &expected_error);
    Ok(())
}
