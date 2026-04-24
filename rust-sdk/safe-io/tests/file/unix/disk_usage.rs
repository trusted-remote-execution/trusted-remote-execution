use crate::test_common::open_test_dir_handle;
use anyhow::Result;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::io::{create_temp_dir_and_path, create_test_file};
use rstest::rstest;
use rust_safe_io::options::{DiskUsageOptionsBuilder, OpenFileOptionsBuilder};
use std::process::Command;

/// Helper to compare file safe_disk_usage results with actual du command
fn compare_file_with_du(
    test_path: &str,
    file_name: &str,
    apparent_size: bool,
    inodes: bool,
) -> Result<()> {
    let dir_handle = open_test_dir_handle(&test_path.to_string());

    let file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        file_name,
        OpenFileOptionsBuilder::default().read(true).build()?,
    )?;

    let options = DiskUsageOptionsBuilder::default()
        .apparent_size(apparent_size)
        .build()?;

    let safe_result = file_handle.safe_disk_usage(&DEFAULT_TEST_CEDAR_AUTH, options)?;

    let file_path = format!("{}/{}", test_path, file_name);
    let mut cmd = Command::new("du");
    if inodes {
        cmd.arg("--inodes");
    } else {
        cmd.arg("--block-size=1");
        if apparent_size {
            cmd.arg("--apparent-size");
        }
    }
    cmd.arg(&file_path);

    let du_output = cmd.output()?;
    let stdout = String::from_utf8(du_output.stdout)?;

    let du_line = stdout
        .lines()
        .next()
        .expect("du should return at least one line");
    let parts: Vec<&str> = du_line.split_whitespace().collect();
    assert!(parts.len() >= 2, "du output should have at least 2 parts");

    let du_value: u64 = parts[0].parse().expect("First part should be a number");
    let du_path = parts[1..].join(" ");

    let metric_name = if inodes { "inode count" } else { "size" };

    assert_eq!(
        safe_result.path(),
        &du_path,
        "Path mismatch: safe_disk_usage='{}' vs du='{}'",
        safe_result.path(),
        du_path
    );

    let safe_value = if inodes {
        *safe_result.inode_count()
    } else {
        *safe_result.size_bytes()
    };

    assert_eq!(
        safe_value,
        du_value,
        "{} mismatch for {}: safe_disk_usage={}, du={}",
        metric_name,
        safe_result.path(),
        safe_value,
        du_value
    );

    Ok(())
}

/// Given: Files of specific sizes (empty or small)
/// When: safe_disk_usage is called with different options
/// Then: Results match du output for both apparent_size and block-based calculations
#[rstest]
#[case::empty_apparent(0, true)]
#[case::empty_blocks(0, false)]
#[case::small_file_apparent(10, true)]
#[case::small_file_blocks(10, false)]
fn test_file_disk_usage_files(#[case] size: usize, #[case] apparent_size: bool) -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let file_name = "test_file.txt";
    let file_content = vec![b'X'; size];
    let _ = create_test_file(&temp_dir, file_name, &file_content)?;

    compare_file_with_du(&temp_dir_path, file_name, apparent_size, false)?;

    Ok(())
}

/// Given: A file
/// When: safe_disk_usage is called to check inode count
/// Then: The returned inode count is 1 and matches du --inodes output
#[test]
fn test_file_disk_usage_inode_count() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let file_name = "test_file.txt";
    let file_content = b"Test content";
    let _ = create_test_file(&temp_dir, file_name, file_content)?;

    compare_file_with_du(&temp_dir_path, file_name, false, true)?;

    Ok(())
}

/// Given: A file with Cedar Stat permission denied
/// When: safe_disk_usage is called
/// Then: An authorization error is returned
#[test]
fn test_file_disk_usage_stat_denied() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let file_name = "test_file.txt";
    let file_content = b"Test content";
    let _ = create_test_file(&temp_dir, file_name, file_content)?;

    let principal = get_test_rex_principal();
    let file_path = format!("{}/{}", temp_dir_path, file_name);

    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action,
            resource
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{file_path}"
        );"#,
        FilesystemAction::Stat
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()?
        .create();

    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        file_name,
        OpenFileOptionsBuilder::default().read(true).build()?,
    )?;

    let options = DiskUsageOptionsBuilder::default().build()?;
    let result = file_handle.safe_disk_usage(&test_cedar_auth, options);

    assert!(result.is_err());

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Stat
    );

    assert_error_contains(result, &expected_error);

    Ok(())
}
