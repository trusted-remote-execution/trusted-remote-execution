use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::io::{create_temp_dir_and_path, create_write_return_test_file};
use rex_test_utils::random::get_rand_string;

use anyhow::Result;
use rust_safe_io::error_constants::{SPECIAL_FILE_ATOMIC_WRITE_ERR, WRITE_FILE_FLAG_ERR};
use rust_safe_io::options::OpenFileOptionsBuilder;
use std::fs::{Permissions, metadata, set_permissions};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::Command;

use crate::test_common::{open_dir_and_file, open_test_dir_handle};

const PERMISSION_EXTRACT_BITMASK: u32 = 0o777;
const RWX_OWNER_RWX_GROUP_BITMASK: u32 = 0o770;

/// Given: A real directory
/// When: Text file is written to the directory with safe I/O
/// Then: Text file contains expected content
#[test]
fn test_write_file_happy_case() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let test_file = get_rand_string();
    let (_, test_content) = create_write_return_test_file(&temp_dir, &test_file)?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        &test_file,
        OpenFileOptionsBuilder::default()
            .read(true)
            .write(true)
            .build()
            .unwrap(),
    )?;

    let file_handle = file_handle.safe_write(&DEFAULT_TEST_CEDAR_AUTH, &test_content)?;

    let actual_content = file_handle.safe_read(&DEFAULT_TEST_CEDAR_AUTH)?;
    assert_eq!(
        actual_content, test_content,
        "Expected file contents to match test content after write"
    );

    Ok(())
}

/// Given: A file opened without write option
/// When: Try to write to the file
/// Then: An error is returned
#[test]
fn test_write_file_no_write_option_fails() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let test_file = get_rand_string();
    let (_, test_content) = create_write_return_test_file(&temp_dir, &test_file)?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        &test_file,
        OpenFileOptionsBuilder::default()
            .read(true)
            .write(false)
            .build()
            .unwrap(),
    )?;
    let result = file_handle.safe_write(&DEFAULT_TEST_CEDAR_AUTH, &test_content);

    assert_error_contains(result, WRITE_FILE_FLAG_ERR);

    Ok(())
}

/// Given: A file and a directory to write
/// When: Text file is written to the directory
/// Then: Text file contains expected default permissions
#[test]
#[cfg(unix)] // MetadataExt::mode() is available in unix-like systems only
fn test_write_new_file_default_permissions() -> Result<(), anyhow::Error> {
    let test_contents = open_dir_and_file()?;
    let full_path = Path::new(&test_contents.dir_name).join(&test_contents.file_name);

    test_contents
        .file_handle
        .safe_write(&DEFAULT_TEST_CEDAR_AUTH, &get_rand_string())?;

    // Leave only bits responsible for file permissions, clear out other bits
    let actual_mode = metadata(full_path)?.mode() & PERMISSION_EXTRACT_BITMASK;

    // Default permissions can vary based on the system umask. Get the umask from the shell
    // and compute the expected default file permissions (0o666 & !umask).
    let output = Command::new("sh")
        .args(["-c", "umask"])
        .output()
        .expect("Failed to run umask command");
    let umask_str = String::from_utf8(output.stdout).unwrap();
    let umask = u32::from_str_radix(umask_str.trim().trim_start_matches('0'), 8).unwrap();
    let expected_mode = 0o666 & !umask;

    assert_eq!(
        actual_mode, expected_mode,
        "Expected file permissions to be default 0o{:o}, but got 0o{:o}",
        expected_mode, actual_mode
    );

    Ok(())
}

/// Given: A file with some contents
/// When: The file is overwritten atomically
/// Then: An atomic write occurred and the returned file handle can be used directly
#[test]
fn test_write_file_overwrite_file() -> Result<(), anyhow::Error> {
    let test_contents = open_dir_and_file()?;
    let updated_content = get_rand_string();

    let new_file_handle = test_contents
        .file_handle
        .safe_write(&DEFAULT_TEST_CEDAR_AUTH, &updated_content)?;

    // Read directly from the new file handle without reopening
    let actual_content = new_file_handle.safe_read(&DEFAULT_TEST_CEDAR_AUTH)?;
    assert_eq!(
        actual_content, updated_content,
        "Expected file contents to match updated content after write"
    );
    assert_eq!(
        new_file_handle.path(),
        test_contents.file_name,
        "Expected file path to remain unchanged"
    );

    // Verify that the content was actually written to the file by opening it again
    let dir_handle = open_test_dir_handle(&test_contents.dir_name);
    let verify_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        &test_contents.file_name,
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;
    let verify_content = verify_handle.safe_read(&DEFAULT_TEST_CEDAR_AUTH)?;
    assert_eq!(
        verify_content, updated_content,
        "Expected reopened file contents to match updated content"
    );

    Ok(())
}

/// Given: An existing file with group-write permissions
/// When: New content is written into existing file
/// Then: The permissions remain the same
#[test]
#[cfg(unix)] // MetadataExt::mode() is available in unix-like systems only
fn test_write_existing_file_retain_permissions() -> Result<()> {
    let test_contents = open_dir_and_file()?;

    // Update permissions for existing file
    let permissions = Permissions::from_mode(RWX_OWNER_RWX_GROUP_BITMASK);
    let full_path = Path::new(&test_contents.dir_name).join(&test_contents.file_name);
    set_permissions(&full_path, permissions)?;

    // Get the new file handle after writing
    let _test_contents = test_contents
        .file_handle
        .safe_write(&DEFAULT_TEST_CEDAR_AUTH, &get_rand_string())?;

    // Leave only bits responsible for file permissions, clear out other bits
    let actual_mode = metadata(full_path)?.mode() & PERMISSION_EXTRACT_BITMASK;
    assert_eq!(
        actual_mode, RWX_OWNER_RWX_GROUP_BITMASK,
        "Expected file permissions to be preserved as 0o770, but got 0o{:o}",
        actual_mode
    );

    Ok(())
}

/// Given: A valid file but an unauthorized user
/// When: Text file is written with safe I/O
/// Then: Access is denied
#[test]
fn test_unauthorized_write_file() -> Result<()> {
    let test_contents = open_dir_and_file()?;
    let updated_content = get_rand_string();
    let principal = get_test_rex_principal();

    let test_policy = format!(
        r#"forbid(
            principal == User::"{principal}",
            action == {},
            resource
        );"#,
        FilesystemAction::Write
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let result = test_contents
        .file_handle
        .safe_write(&test_cedar_auth, &updated_content);

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Write
    );
    assert_error_contains(result, &expected_error);

    Ok(())
}

/// Given: A file opened with special_file=true
/// When: Attempting to use safe_write (atomic write)
/// Then: Returns error rejecting special_file for atomic writes
#[test]
fn test_safe_write_rejects_special_file() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let test_file = get_rand_string();
    create_write_return_test_file(&temp_dir, &test_file)?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        &test_file,
        OpenFileOptionsBuilder::default()
            .read(true)
            .write(true)
            .special_file(true)
            .build()
            .unwrap(),
    )?;

    let result = file_handle.safe_write(&DEFAULT_TEST_CEDAR_AUTH, "test content");

    assert_error_contains(result, SPECIAL_FILE_ATOMIC_WRITE_ERR);
    Ok(())
}
