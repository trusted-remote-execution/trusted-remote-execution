#![cfg(target_os = "linux")]

use anyhow::Result;
use assert_fs::TempDir;
use assert_fs::prelude::{FileWriteStr, PathChild};
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::{io::create_temp_dir_and_path, random::get_rand_string};
use rust_safe_io::error_constants::INVALID_SIZE;
use rust_safe_io::options::{OpenDirOptionsBuilder, OpenFileOptionsBuilder, SizeUnit};
use rust_safe_io::{DirConfigBuilder, RcFileHandle};
use rust_safe_io::{RcDirHandle, truncate::TruncateOptionsBuilder};
use std::rc::Rc;
use std::{fs, path::PathBuf};

use rstest::rstest;

struct TestContents {
    file_handle: RcFileHandle,
    _tempdir: TempDir,
    _content: String,
}

fn open_dir_and_file_with_contents(contents: String) -> Result<Rc<TestContents>> {
    let (temp, temp_dir_path) = create_temp_dir_and_path()?;

    let rand_path = get_rand_string();
    temp.child(&rand_path).write_str(&contents)?;

    let dir = open_test_dir_handle(&temp_dir_path);
    let file = dir.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        &rand_path,
        OpenFileOptionsBuilder::default()
            .read(true)
            .write(true)
            .build()
            .unwrap(),
    )?;

    let test_contents = TestContents {
        file_handle: file,
        _tempdir: temp,
        _content: contents,
    };

    Ok(Rc::new(test_contents))
}

// this will create the test elements and return content
// that's written to a temp file (test_str)
fn open_dir_and_file() -> Result<Rc<TestContents>> {
    let test_str = get_rand_string();
    open_dir_and_file_with_contents(test_str)
}

fn metadata_validate_helper(full_path: &PathBuf, expected_size: i64) {
    let metadata_res = fs::metadata(full_path);
    assert!(metadata_res.is_ok());

    // ensure old size is what we expect
    assert_eq!(metadata_res.unwrap().len() as i64, expected_size);
}

/// Open a dir using the default cedar auth and default open options.
fn open_test_dir_handle(temp_dir_path: &String) -> RcDirHandle {
    DirConfigBuilder::default()
        .path(temp_dir_path.clone())
        .build()
        .unwrap()
        .safe_open(
            &DEFAULT_TEST_CEDAR_AUTH,
            OpenDirOptionsBuilder::default().build().unwrap(),
        )
        .unwrap()
}

/// Given: Different formats for truncate
/// When: Truncation occurs
/// Then: The file is truncated to match expected size
#[rstest]
#[case::byte(SizeUnit::Bytes, false, 10, 10)]
#[case::kibibyte(SizeUnit::Kibibytes, false, 10, 10*1024)]
#[case::byte(SizeUnit::Bytes, false, 0, 0)]
#[case::kibibyte(SizeUnit::Kibibytes, false, 0, 0)]
#[case::omit_byte_option(SizeUnit::Bytes, true, 10, 10)]
#[case::omit_byte_option_zero(SizeUnit::Bytes, true, 0, 0)]
fn test_ftruncate(
    #[case] requested_size_unit: SizeUnit,
    #[case] omit_byte_option: bool,
    #[case] input_size: i64,
    #[case] expected_size: i64,
) -> Result<(), anyhow::Error> {
    let (temp, temp_dir_path) = create_temp_dir_and_path()?;

    let rand_path = get_rand_string();
    temp.child(&rand_path).write_str(&rand_path)?;
    let full_path = temp.path().join(&rand_path);

    // truncate file within a block to ensure truncation actually happened
    // after FD is closed
    let result = {
        let dir_handle = open_test_dir_handle(&temp_dir_path);
        let file_handle_result = dir_handle.safe_open_file(
            &DEFAULT_TEST_CEDAR_AUTH,
            &rand_path,
            OpenFileOptionsBuilder::default()
                .read(true)
                .write(true)
                .build()
                .unwrap(),
        );
        assert!(file_handle_result.is_ok());
        let file_handle = file_handle_result.unwrap();

        // ensure original file matches what we expect
        metadata_validate_helper(&full_path, 16);

        let truncate_opts = if omit_byte_option {
            TruncateOptionsBuilder::default()
                .size(input_size)
                .build()
                .unwrap()
        } else {
            TruncateOptionsBuilder::default()
                .format(requested_size_unit)
                .size(input_size)
                .build()
                .unwrap()
        };

        file_handle.safe_truncate(&DEFAULT_TEST_CEDAR_AUTH, truncate_opts)
    };

    assert!(result.is_ok());
    // ensure new size matches expected size
    metadata_validate_helper(&full_path, expected_size);

    Ok(())
}

/// Given: A file and an unauthorized user
/// When: The truncate function is called
/// Then: Access is denied
#[test]
fn test_unauthorized_truncate() -> Result<()> {
    let test_contents = open_dir_and_file()?;
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

    let truncate_opts = TruncateOptionsBuilder::default().size(10).build().unwrap();

    let result = test_contents
        .file_handle
        .safe_truncate(&test_cedar_auth, truncate_opts);

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Write
    );
    assert_error_contains(result, &expected_error);

    Ok(())
}

/// Given: A file to truncate
/// When: The truncate function is called with negative size
/// Then: An error occurs
#[test]
fn test_truncate_negative_size() -> Result<(), anyhow::Error> {
    let (temp, temp_dir_path) = create_temp_dir_and_path()?;

    let rand_path = get_rand_string();
    temp.child(&rand_path).write_str(&rand_path)?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let file_handle_result = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        &rand_path,
        OpenFileOptionsBuilder::default()
            .read(true)
            .write(true)
            .build()
            .unwrap(),
    );
    assert!(file_handle_result.is_ok());
    let file_handle = file_handle_result.unwrap();

    let truncate_opts = TruncateOptionsBuilder::default().size(-10).build().unwrap();

    let result = file_handle.safe_truncate(&DEFAULT_TEST_CEDAR_AUTH, truncate_opts);

    assert_error_contains(result, INVALID_SIZE);

    Ok(())
}
