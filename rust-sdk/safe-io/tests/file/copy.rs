use crate::test_common::*;
use anyhow::Result;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::io::create_temp_dir_and_path;
use rex_test_utils::random::{get_rand_string, get_rand_string_of_len};
use rstest::rstest;
use rust_safe_io::error_constants::{
    DEST_FILE_NOT_EMPTY_ERR, READ_FILE_FLAG_ERR, WRITE_FILE_FLAG_ERR,
};
use rust_safe_io::options::{CopyFileOptionsBuilder, OpenFileOptionsBuilder};
use std::fs::{Permissions, metadata, set_permissions};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use tracing::Level;
use tracing_subscriber::fmt;

const PERMISSION_EXTRACT_BITMASK: u32 = 0o777;

/// Enables code coverage for `tracing::debug` calls.
fn init_test_logger() {
    let _ = fmt::Subscriber::builder()
        .with_max_level(Level::DEBUG)
        .with_test_writer()
        .try_init();
}

/// Given: A source file with content and a destination file
/// When: The source file is copied to the destination using safe_copy
/// Then: The destination file contains the same content as the source
#[test]
fn test_safe_copy_success() -> Result<()> {
    init_test_logger();
    let test_contents = open_dir_and_file()?;

    let dir_handle = open_test_dir_handle(&test_contents.dir_name);

    let dest_filename = get_rand_string();
    let dest_file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        &dest_filename,
        OpenFileOptionsBuilder::default()
            .read(true)
            .create(true)
            .build()
            .unwrap(),
    )?;

    let copy_file_options = CopyFileOptionsBuilder::default().build().unwrap();

    let result_file = test_contents.file_handle.safe_copy(
        &DEFAULT_TEST_CEDAR_AUTH,
        dest_file_handle,
        copy_file_options,
    )?;

    let dest_content = result_file.safe_read(&DEFAULT_TEST_CEDAR_AUTH)?;
    assert_eq!(dest_content, test_contents._content);

    // ensure that the original file is rewound to the beginning by reading it again
    let src_content = test_contents
        .file_handle
        .safe_read(&DEFAULT_TEST_CEDAR_AUTH)?;
    assert_eq!(src_content, test_contents._content);

    Ok(())
}

/// Given: A file that is a real file and a real directory but unauthorized user for reading source file
/// When: The file is copied with safe I/O
/// Then: Access is denied for read permission
#[test]
fn test_unauthorized_safe_copy_read() -> Result<()> {
    let test_contents = open_dir_and_file()?;

    let dir_handle = open_test_dir_handle(&test_contents.dir_name);

    let dest_filename = get_rand_string();
    let dest_file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        &dest_filename,
        OpenFileOptionsBuilder::default()
            .read(true)
            .create(true)
            .build()
            .unwrap(),
    )?;

    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"forbid(
            principal == User::"{principal}",
            action == {},
            resource is file_system::File in file_system::Dir::"/tmp"
        );"#,
        FilesystemAction::Read
    );
    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let copy_file_options = CopyFileOptionsBuilder::default().build().unwrap();

    let result =
        test_contents
            .file_handle
            .safe_copy(&test_cedar_auth, dest_file_handle, copy_file_options);

    assert_error_contains(result, &FilesystemAction::Read.to_string());

    Ok(())
}

/// Given: A file that is a real file and a real directory but unauthorized user for writing dest file
/// When: The file is copied with safe I/O
/// Then: Access is denied for write permission
#[test]
#[cfg(target_os = "linux")]
fn test_unauthorized_safe_copy_write() -> Result<()> {
    let test_contents = open_dir_and_file()?;

    let dir_handle = open_test_dir_handle(&test_contents.dir_name);

    let dest_filename = get_rand_string();
    let dest_file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        &dest_filename,
        OpenFileOptionsBuilder::default()
            .read(true)
            .create(true)
            .build()
            .unwrap(),
    )?;

    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action == {},
            resource is file_system::File in file_system::Dir::"/tmp"
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource is file_system::File in file_system::Dir::"/tmp"
        );"#,
        FilesystemAction::Read,
        FilesystemAction::Write
    );
    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let copy_file_options = CopyFileOptionsBuilder::default().build().unwrap();

    let result =
        test_contents
            .file_handle
            .safe_copy(&test_cedar_auth, dest_file_handle, copy_file_options);

    assert_error_contains(result, &FilesystemAction::Write.to_string());

    Ok(())
}

/// Given: A source file opened without read option
/// When: The source file is copied to the destination using safe_copy
/// Then: An error is returned indicating missing read option
#[test]
fn test_safe_copy_no_read_option_fails() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let test_file = "test_read_file.txt";
    use rex_test_utils::io::create_test_file;
    create_test_file(&temp_dir, test_file, b"test content")?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let source_file = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        test_file,
        OpenFileOptionsBuilder::default()
            .write(true)
            .build()
            .unwrap(),
    )?;

    let dest_file = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "dest_file.txt",
        OpenFileOptionsBuilder::default()
            .read(true)
            .create(true)
            .build()
            .unwrap(),
    )?;

    let copy_file_options = CopyFileOptionsBuilder::default().build().unwrap();

    let result = source_file.safe_copy(&DEFAULT_TEST_CEDAR_AUTH, dest_file, copy_file_options);

    assert_error_contains(result, READ_FILE_FLAG_ERR);

    Ok(())
}

/// Given: A a destination file opened without write option
/// When: The file is copied using safe_copy
/// Then: An error is returned indicating missing write option
#[test]
fn test_safe_copy_no_write_option_fails() -> Result<()> {
    let test_contents = open_dir_and_file()?;

    let dir_handle = open_test_dir_handle(&test_contents.dir_name);

    let dest_file_name = get_rand_string();
    let _ = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        &dest_file_name,
        OpenFileOptionsBuilder::default()
            .create(true)
            .build()
            .unwrap(),
    )?;

    let dest_file = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        &dest_file_name,
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let copy_file_options = CopyFileOptionsBuilder::default().build().unwrap();

    let result =
        test_contents
            .file_handle
            .safe_copy(&DEFAULT_TEST_CEDAR_AUTH, dest_file, copy_file_options);

    assert_error_contains(result, WRITE_FILE_FLAG_ERR);

    Ok(())
}

/// Given: A source file and a non-empty destination file
/// When: The source file is copied with different force flag values
/// Then: The operation succeeds or fails as expected
#[rstest]
#[case::no_force_non_empty_dest(false, true)]
#[case::force_non_empty_dest(true, false)]
fn test_safe_copy_force_flag(#[case] force: bool, #[case] should_fail: bool) -> Result<()> {
    let test_contents = open_dir_and_file()?;

    let dir_handle = open_test_dir_handle(&test_contents.dir_name);

    let dest_filename = get_rand_string();
    let dest_file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        &dest_filename,
        OpenFileOptionsBuilder::default()
            .read(true)
            .create(true)
            .build()
            .unwrap(),
    )?;

    let dest_file_handle =
        dest_file_handle.safe_write(&DEFAULT_TEST_CEDAR_AUTH, &get_rand_string_of_len(32))?;

    let copy_file_options = CopyFileOptionsBuilder::default()
        .force(force)
        .build()
        .unwrap();

    let result = test_contents.file_handle.safe_copy(
        &DEFAULT_TEST_CEDAR_AUTH,
        dest_file_handle,
        copy_file_options,
    );

    if should_fail {
        assert_error_contains(result, DEST_FILE_NOT_EMPTY_ERR);
    } else {
        assert!(
            result.is_ok(),
            "Expected file copy with force flag to succeed, but received {:?}",
            result
        );
        let result_file = result.unwrap();
        let dest_content = result_file.safe_read(&DEFAULT_TEST_CEDAR_AUTH)?;
        assert_eq!(
            dest_content, test_contents._content,
            "Expected destination file contents to match source file contents after copy"
        );
    }

    Ok(())
}

/// Given: A source file with specific metadata and a destination file
/// When: The source file is copied with different preserve flag values
/// Then: The destination file has the expected metadata
#[rstest]
#[cfg(unix)]
#[case::preserve_true(true, true)]
#[case::preserve_false(false, false)]
fn test_safe_copy_preserve_metadata(
    #[case] preserve: bool,
    #[case] should_match: bool,
) -> Result<()> {
    let test_contents = open_dir_and_file()?;
    let full_path = Path::new(&test_contents.dir_name).join(&test_contents.file_name);
    let custom_perms = 0o640;
    set_permissions(&full_path, Permissions::from_mode(custom_perms))?;

    let dir_handle = open_test_dir_handle(&test_contents.dir_name);

    let dest_filename = get_rand_string();
    let dest_file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        &dest_filename,
        OpenFileOptionsBuilder::default()
            .read(true)
            .create(true)
            .build()
            .unwrap(),
    )?;

    let copy_file_options = CopyFileOptionsBuilder::default()
        .preserve(preserve)
        .build()
        .unwrap();

    let result = test_contents.file_handle.safe_copy(
        &DEFAULT_TEST_CEDAR_AUTH,
        dest_file_handle,
        copy_file_options,
    );

    assert!(
        result.is_ok(),
        "Expected file copy with preserve metadata to succeed, but received {:?}",
        result
    );

    let dest_path = Path::new(&test_contents.dir_name).join(dest_filename);
    let dest_mode = metadata(dest_path)?.mode() & PERMISSION_EXTRACT_BITMASK;

    if should_match {
        assert_eq!(
            dest_mode, custom_perms,
            "Expected destination file permissions to match source permissions 0o{:o}",
            custom_perms
        );
    } else {
        assert_ne!(
            dest_mode, custom_perms,
            "Expected destination file permissions to differ from source permissions 0o{:o}",
            custom_perms
        );
    }

    Ok(())
}
