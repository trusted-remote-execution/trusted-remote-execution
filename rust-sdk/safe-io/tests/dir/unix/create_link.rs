use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::io::create_temp_dir_and_path;
use rust_safe_io::error_constants::PATH_TRAVERSAL;
use rust_safe_io::options::CreateSymlinkOptionsBuilder;

use anyhow::Result;
use assert_fs::fixture::{PathChild, PathCreateDir, SymlinkToDir, SymlinkToFile};
use rstest::rstest;
use std::fs::{read_dir, read_link};
use std::path::Path;

use crate::test_common::open_test_dir_handle;

/// Given: A directory handle and valid target/link names with authorized user
/// When: safe_create_symlink is called
/// Then: Symlink is created successfully
#[rstest]
#[case::relative_path("target.txt")]
#[case::absolute_path("/tmp")]
#[cfg(unix)]
fn test_safe_create_symlink_success(#[case] target: &str) -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let options = CreateSymlinkOptionsBuilder::default()
        .force(false)
        .build()
        .unwrap();

    let result =
        dir_handle.safe_create_symlink(&DEFAULT_TEST_CEDAR_AUTH, target, "link.txt", options);

    assert!(result.is_ok());

    let link_path = temp_dir.path().join("link.txt");
    assert!(link_path.is_symlink());

    let target_path = read_link(&link_path)?;
    assert_eq!(target_path, Path::new(target));

    Ok(())
}

/// Given: A directory handle and a unauthorized user to create
/// When: safe_create_symlink is called
/// Then: Access is denied for Create action
#[test]
#[cfg(unix)]
fn test_unauthorized_safe_create_symlink() -> Result<()> {
    let (_temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"forbid(
            principal == User::"{principal}",
            action == {},
            resource
        );"#,
        FilesystemAction::Create
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let options = CreateSymlinkOptionsBuilder::default()
        .force(false)
        .build()
        .unwrap();

    let result =
        dir_handle.safe_create_symlink(&test_cedar_auth, "target.txt", "link.txt", options);

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Create
    );
    assert_error_contains(result, &expected_error);

    Ok(())
}

/// Given: A directory handle and user with Create but not Delete permission
/// When: safe_create_symlink is called with force=true on existing symlink
/// Then: Access is denied for Delete action
#[test]
#[cfg(unix)]
fn test_unauthorized_safe_create_symlink_delete_permission() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let existing_link = temp_dir.child("existing_link.txt");
    existing_link.symlink_to_file("target.txt")?;

    let principal = get_test_rex_principal();
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
        FilesystemAction::Create,
        FilesystemAction::Delete
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let options = CreateSymlinkOptionsBuilder::default()
        .force(true)
        .build()
        .unwrap();

    let result = dir_handle.safe_create_symlink(
        &test_cedar_auth,
        "target.txt",
        "existing_link.txt",
        options,
    );

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Delete
    );
    assert_error_contains(result, &expected_error);

    Ok(())
}

/// Given: A directory handle with existing symlink
/// When: safe_create_symlink is called with different force flag values
/// Then: success result varies based on force flag and atomic replacement occurs
#[rstest]
#[case::force_false_existing_fails(false, true)]
#[case::force_true_existing_succeeds(true, false)]
#[cfg(unix)]
fn test_safe_create_symlink_force_behavior(
    #[case] force: bool,
    #[case] should_fail: bool,
) -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let existing_link = temp_dir.child("existing_link.txt");
    existing_link.symlink_to_file("old_target.txt")?;

    let link_path = temp_dir.path().join("existing_link.txt");
    assert!(link_path.is_symlink());
    let initial_target = std::fs::read_link(&link_path)?;
    assert_eq!(initial_target, Path::new("old_target.txt"));

    let options = CreateSymlinkOptionsBuilder::default()
        .force(force)
        .build()
        .unwrap();

    let result = dir_handle.safe_create_symlink(
        &DEFAULT_TEST_CEDAR_AUTH,
        "new_target.txt",
        "existing_link.txt",
        options,
    );

    if should_fail {
        assert!(result.is_err());
        assert_error_contains(result, "File exists");

        assert!(link_path.is_symlink());
        let unchanged_target = read_link(&link_path)?;
        assert_eq!(unchanged_target, Path::new("old_target.txt"));
    } else {
        assert!(result.is_ok());

        assert!(link_path.is_symlink());
        let updated_target = read_link(&link_path)?;
        assert_eq!(updated_target, Path::new("new_target.txt"));
    }

    Ok(())
}

/// Given: A directory handle with various invalid link path inputs
/// When: safe_create_symlink is called
/// Then: Path traversal is detected and rejected
#[rstest]
#[case::path_traversal_relative("../../../etc")]
#[case::path_traversal_absolute("/subdir/../../../etc")]
#[cfg(unix)]
fn test_safe_create_symlink_path_traversal(#[case] link_name: &str) -> Result<()> {
    let (_temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let options = CreateSymlinkOptionsBuilder::default()
        .force(false)
        .build()
        .unwrap();

    let result =
        dir_handle.safe_create_symlink(&DEFAULT_TEST_CEDAR_AUTH, "target.txt", link_name, options);

    assert!(result.is_err());
    let error_result = result.as_ref();
    let contains_traversal = error_result
        .map_err(|e| e.to_string())
        .unwrap_err()
        .contains(PATH_TRAVERSAL);
    let cap_std_contains_traversal = error_result
        .map_err(|e| e.to_string())
        .unwrap_err()
        .contains("a path led outside of the filesystem");

    assert!(contains_traversal || cap_std_contains_traversal);

    Ok(())
}

/// Given: A directory with an existing symlink pointing to a subdirectory
/// When: safe_create_symlink is called with force=true to replace the existing symlink
/// Then: The symlink is replaced directly without following it, preventing the attack (Unix ln would follow the symlink and create files inside the target directory)
#[test]
#[cfg(unix)]
fn test_safe_create_symlink_security_no_follow_directory_symlink() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let subdir = temp_dir.child("subdir");
    subdir.create_dir_all()?;

    let dir_symlink = temp_dir.child("dir-symlink");
    dir_symlink.symlink_to_dir("subdir")?;

    let symlink_path = temp_dir.path().join("dir-symlink");
    assert!(symlink_path.is_symlink());
    let initial_target = read_link(&symlink_path)?;
    assert_eq!(initial_target, Path::new("subdir"));

    let options = CreateSymlinkOptionsBuilder::default()
        .force(true)
        .build()
        .unwrap();

    let result = dir_handle.safe_create_symlink(
        &DEFAULT_TEST_CEDAR_AUTH,
        "new-target.txt",
        "dir-symlink",
        options,
    );

    assert!(result.is_ok());

    assert!(symlink_path.is_symlink());
    let new_target = read_link(&symlink_path)?;
    assert_eq!(new_target, Path::new("new-target.txt"));

    let subdir_contents: Vec<_> =
        read_dir(temp_dir.path().join("subdir"))?.collect::<std::result::Result<Vec<_>, _>>()?;
    assert!(subdir_contents.is_empty());

    Ok(())
}
