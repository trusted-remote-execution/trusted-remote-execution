#![cfg(target_os = "linux")]

use anyhow::Result;
use assert_fs::prelude::{FileWriteStr, PathChild};
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::io::create_temp_dir_and_path;
use rex_test_utils::random::get_rand_string;
use rstest::rstest;
use rust_safe_io::DiskAllocationOptionsBuilder;
use rust_safe_io::error_constants::INVALID_LENGTH;
use rust_safe_io::options::{OpenFileOptionsBuilder, SizeUnit};
use std::{fs, path::PathBuf};

use crate::test_common::{open_dir_and_file, open_test_dir_handle};

const ONE_KIB: i64 = 1_024;
const ONE_MB: i64 = 1_000_000;
const ONE_MIB: i64 = 1_048_576;
const TEN_MB: i64 = 10_000_000;
const TEN_GIB: i64 = 10_737_418_240;

fn metadata_validate_helper(full_path: &PathBuf, expected_size: i64) {
    let metadata_res = fs::metadata(full_path);
    assert!(metadata_res.is_ok());
    assert_eq!(metadata_res.unwrap().len() as i64, expected_size);
}

/// Given: Different size units for initialize_bytes_on_disk
/// When: initialize_bytes_on_disk is called
/// Then: The file is allocated to match expected size
#[rstest]
#[case::bytes(SizeUnit::Bytes, ONE_KIB, ONE_KIB)]
#[case::kibibytes(SizeUnit::Kibibytes, 1, ONE_KIB)]
#[case::megabytes(SizeUnit::Megabytes, 1, ONE_MB)]
#[case::mebibytes(SizeUnit::Mebibytes, 1, ONE_MIB)]
#[case::bytes_2kib(SizeUnit::Bytes, 2048, 2048)]
fn test_initialize_bytes_on_disk_size_units(
    #[case] size_unit: SizeUnit,
    #[case] input_size: i64,
    #[case] expected_size: i64,
) -> Result<()> {
    let (temp, temp_dir_path) = create_temp_dir_and_path()?;

    let rand_path = get_rand_string();
    temp.child(&rand_path).write_str("")?;
    let full_path = temp.path().join(&rand_path);

    let result = {
        let dir_handle = open_test_dir_handle(&temp_dir_path);
        let file_handle = dir_handle.safe_open_file(
            &DEFAULT_TEST_CEDAR_AUTH,
            &rand_path,
            OpenFileOptionsBuilder::default()
                .write(true)
                .build()
                .unwrap(),
        )?;

        let disk_allocation_opts = DiskAllocationOptionsBuilder::default()
            .format(size_unit)
            .length(input_size)
            .build()
            .unwrap();

        file_handle.safe_initialize_bytes_on_disk(&DEFAULT_TEST_CEDAR_AUTH, disk_allocation_opts)
    };

    assert!(result.is_ok());
    metadata_validate_helper(&full_path, expected_size);

    Ok(())
}

/// Given: An empty file
/// When: initialize_bytes_on_disk is called
/// Then: The file is allocated to the specified size
#[test]
fn test_initialize_bytes_on_disk_empty_file() -> Result<()> {
    let (temp, temp_dir_path) = create_temp_dir_and_path()?;

    let rand_path = get_rand_string();
    temp.child(&rand_path).write_str("")?;
    let full_path = temp.path().join(&rand_path);

    metadata_validate_helper(&full_path, 0);

    let result = {
        let dir_handle = open_test_dir_handle(&temp_dir_path);
        let file_handle = dir_handle.safe_open_file(
            &DEFAULT_TEST_CEDAR_AUTH,
            &rand_path,
            OpenFileOptionsBuilder::default()
                .write(true)
                .build()
                .unwrap(),
        )?;

        let disk_allocation_opts = DiskAllocationOptionsBuilder::default()
            .length(10)
            .format(SizeUnit::Megabytes)
            .build()
            .unwrap();

        file_handle.safe_initialize_bytes_on_disk(&DEFAULT_TEST_CEDAR_AUTH, disk_allocation_opts)
    };

    assert!(result.is_ok());
    metadata_validate_helper(&full_path, TEN_MB);

    Ok(())
}

/// Given: A file smaller than the allocation size
/// When: initialize_bytes_on_disk is called
/// Then: The file is extended to the specified size
#[test]
fn test_initialize_bytes_on_disk_extends_small_file() -> Result<()> {
    let (temp, temp_dir_path) = create_temp_dir_and_path()?;

    let rand_path = get_rand_string();
    let initial_content = "small content";
    temp.child(&rand_path).write_str(initial_content)?;
    let full_path = temp.path().join(&rand_path);

    let initial_size = initial_content.len() as i64;
    metadata_validate_helper(&full_path, initial_size);

    let result = {
        let dir_handle = open_test_dir_handle(&temp_dir_path);
        let file_handle = dir_handle.safe_open_file(
            &DEFAULT_TEST_CEDAR_AUTH,
            &rand_path,
            OpenFileOptionsBuilder::default()
                .write(true)
                .build()
                .unwrap(),
        )?;

        let disk_allocation_opts = DiskAllocationOptionsBuilder::default()
            .length(1)
            .format(SizeUnit::Megabytes)
            .build()
            .unwrap();

        file_handle.safe_initialize_bytes_on_disk(&DEFAULT_TEST_CEDAR_AUTH, disk_allocation_opts)
    };

    assert!(result.is_ok());
    metadata_validate_helper(&full_path, ONE_MB);

    Ok(())
}

/// Given: A file larger than the allocation size
/// When: initialize_bytes_on_disk is called
/// Then: The file size remains unchanged (no-op)
#[test]
fn test_initialize_bytes_on_disk_larger_file_no_op() -> Result<()> {
    let (temp, temp_dir_path) = create_temp_dir_and_path()?;

    let rand_path = get_rand_string();
    let large_content = "x".repeat(2000);
    temp.child(&rand_path).write_str(&large_content)?;
    let full_path = temp.path().join(&rand_path);

    let initial_size = large_content.len() as i64;
    metadata_validate_helper(&full_path, initial_size);

    let result = {
        let dir_handle = open_test_dir_handle(&temp_dir_path);
        let file_handle = dir_handle.safe_open_file(
            &DEFAULT_TEST_CEDAR_AUTH,
            &rand_path,
            OpenFileOptionsBuilder::default()
                .write(true)
                .build()
                .unwrap(),
        )?;

        let disk_allocation_opts = DiskAllocationOptionsBuilder::default()
            .length(1024)
            .format(SizeUnit::Bytes)
            .build()
            .unwrap();

        file_handle.safe_initialize_bytes_on_disk(&DEFAULT_TEST_CEDAR_AUTH, disk_allocation_opts)
    };

    assert!(result.is_ok());
    metadata_validate_helper(&full_path, initial_size);

    Ok(())
}

/// Given: A file and an unauthorized user
/// When: initialize_bytes_on_disk is called
/// Then: Access is denied
#[test]
fn test_unauthorized_initialize_bytes_on_disk() -> Result<()> {
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

    let disk_allocation_opts = DiskAllocationOptionsBuilder::default()
        .length(1024)
        .build()
        .unwrap();

    let result = test_contents
        .file_handle
        .safe_initialize_bytes_on_disk(&test_cedar_auth, disk_allocation_opts);

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Write
    );
    assert_error_contains(result, &expected_error);

    Ok(())
}

/// Given: DiskAllocationOptionsBuilder with negative length
/// When: Building the options
/// Then: A validation error occurs
#[test]
fn test_initialize_bytes_on_disk_negative_length() -> Result<()> {
    let result = DiskAllocationOptionsBuilder::default().length(-10).build();

    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains(INVALID_LENGTH));
    assert!(error_msg.contains("Length must be greater than 0"));

    Ok(())
}

/// Given: DiskAllocationOptionsBuilder with zero length
/// When: Building the options
/// Then: A validation error occurs
#[test]
fn test_initialize_bytes_on_disk_zero_length() -> Result<()> {
    let result = DiskAllocationOptionsBuilder::default().length(0).build();

    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains(INVALID_LENGTH));
    assert!(error_msg.contains("Length must be greater than 0"));

    Ok(())
}

/// Given: A file opened with read-only permission
/// When: initialize_bytes_on_disk is called
/// Then: An error occurs indicating write permission is required
#[test]
fn test_initialize_bytes_on_disk_read_only_file() -> Result<()> {
    let (temp, temp_dir_path) = create_temp_dir_and_path()?;

    let rand_path = get_rand_string();
    temp.child(&rand_path).write_str("test")?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        &rand_path,
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let disk_allocation_opts = DiskAllocationOptionsBuilder::default()
        .length(1024)
        .build()
        .unwrap();

    let result =
        file_handle.safe_initialize_bytes_on_disk(&DEFAULT_TEST_CEDAR_AUTH, disk_allocation_opts);

    assert_error_contains(
        result,
        "Attempted to write a file without opening it with the write option",
    );

    Ok(())
}

/// Given: A newly created file
/// When: initialize_bytes_on_disk is called to create a swap file (DA use case)
/// Then: The file is preallocated successfully
#[test]
fn test_initialize_bytes_on_disk_swap_file_use_case() -> Result<()> {
    let (temp, temp_dir_path) = create_temp_dir_and_path()?;

    let swapfile_name = "swapfile";
    let full_path = temp.path().join(swapfile_name);

    let result = {
        let dir_handle = open_test_dir_handle(&temp_dir_path);

        let file_handle = dir_handle.safe_open_file(
            &DEFAULT_TEST_CEDAR_AUTH,
            swapfile_name,
            OpenFileOptionsBuilder::default()
                .create(true)
                .build()
                .unwrap(),
        )?;

        let disk_allocation_opts = DiskAllocationOptionsBuilder::default()
            .length(10)
            .format(SizeUnit::Gibibytes)
            .build()
            .unwrap();

        file_handle.safe_initialize_bytes_on_disk(&DEFAULT_TEST_CEDAR_AUTH, disk_allocation_opts)
    };

    assert!(result.is_ok());

    metadata_validate_helper(&full_path, TEN_GIB);

    let metadata = fs::metadata(&full_path)?;
    assert!(metadata.is_file());

    Ok(())
}

/// Given: A file and an extremely large allocation size that exceeds available disk space
/// When: initialize_bytes_on_disk is called
/// Then: An error is returned from the fallocate system call
#[test]
fn test_initialize_bytes_on_disk_exceeds_disk_space() -> Result<()> {
    let (temp, temp_dir_path) = create_temp_dir_and_path()?;

    let rand_path = get_rand_string();
    temp.child(&rand_path).write_str("")?;

    let result = {
        let dir_handle = open_test_dir_handle(&temp_dir_path);
        let file_handle = dir_handle.safe_open_file(
            &DEFAULT_TEST_CEDAR_AUTH,
            &rand_path,
            OpenFileOptionsBuilder::default()
                .write(true)
                .build()
                .unwrap(),
        )?;

        // Allocate an impossibly large amount (1 exabyte)
        let disk_allocation_opts = DiskAllocationOptionsBuilder::default()
            .length(1_000_000)
            .format(SizeUnit::Gibibytes)
            .build()
            .unwrap();

        file_handle.safe_initialize_bytes_on_disk(&DEFAULT_TEST_CEDAR_AUTH, disk_allocation_opts)
    };

    assert!(
        result.is_err(),
        "Expected error when allocating beyond disk capacity"
    );
    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("File too large") || error_msg.contains("No space left on device"),
        "Expected 'File too large' or 'No space left on device', got: {}",
        error_msg
    );

    Ok(())
}
