use crate::test_common::{
    open_dir_and_file, open_dir_and_file_with_contents, open_test_dir_handle,
};
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rex_test_utils::io::create_temp_dir_and_path;
use rex_test_utils::random::get_rand_string;
use rex_test_utils::random::get_rand_string_of_len;
use rex_test_utils::{assertions::assert_error_contains, io::create_write_return_test_file};

use anyhow::Result;
use rust_safe_io::error_constants::WRITE_FILE_FLAG_ERR;
use rust_safe_io::options::OpenFileOptionsBuilder;

// safe_write_in_place tests: this is what we assume the filesystem block size to be. Tests may fail
// if actual block size is larger than this.
const BLOCK_SIZE: usize = 4096;

/// Given: A file but an unauthorized user
/// When: writing to the file in place with safe I/O
/// Then: Access is denied
#[test]
#[cfg(unix)]
fn unauthorized_safe_write_in_place() -> Result<()> {
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
        .safe_write_in_place(&test_cedar_auth, &updated_content);

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Write
    );
    assert_error_contains(result, &expected_error);

    Ok(())
}

/// Given: A file opened without write option
/// When: Try to write to the file in place
/// Then: An error is returned
#[test]
fn test_write_file_in_place_no_write_option_fails() -> Result<()> {
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
    let result = file_handle.safe_write_in_place(&DEFAULT_TEST_CEDAR_AUTH, &test_content);

    assert_error_contains(result, WRITE_FILE_FLAG_ERR);

    Ok(())
}

/// Given: a file with existing contents
/// When:  we try to write the file in place and the new contents are less than or equal to the block size and the user is authorized, and we read from the same file handle
/// Then:  the new contents match the expected contents.
#[rstest::rstest]
#[case::when_new_contents_are_longer_than_original(
    String::from("my old short string"),
    String::from("my new longer string")
)]
// Specifically in the long -> short case, new contents shouldn't have leftover bytes from the original contents.
#[case::when_new_contents_are_shorter_than_original(
    String::from("my old longer string"),
    String::from("my new short string")
)]
#[case::when_new_contents_are_equal_to_block_size(
    String::from("original contents"),
    get_rand_string_of_len(BLOCK_SIZE)
)]
#[case::when_contents_are_larger_than_one_block_size(
    String::from("original contents"),
    get_rand_string_of_len(BLOCK_SIZE + 1)
)]
#[cfg(unix)]
fn safe_write_in_place_replaces_old_contents(
    #[case] original_contents: String,
    #[case] updated_contents: String,
) -> Result<()> {
    let test_contents = open_dir_and_file_with_contents(original_contents)?;

    test_contents
        .file_handle
        .safe_write_in_place(&DEFAULT_TEST_CEDAR_AUTH, &updated_contents)?;

    let actual_content = test_contents
        .file_handle
        .safe_read(&DEFAULT_TEST_CEDAR_AUTH)?;
    assert_eq!(
        updated_contents, actual_content,
        "Expected file contents to match updated contents after in-place write"
    );

    Ok(())
}

/// Given: A file opened with special_file=true
/// When: Using safe_write_in_place
/// Then: Write succeeds without truncate/sync/rewind operations
#[test]
#[cfg(unix)]
fn test_safe_write_in_place_accepts_special_file() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let test_file = get_rand_string();
    create_write_return_test_file(&temp_dir, &test_file)?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        &test_file,
        OpenFileOptionsBuilder::default()
            .write(true)
            .special_file(true)
            .build()
            .unwrap(),
    )?;

    let new_content = "special file content";
    let result = file_handle.safe_write_in_place(&DEFAULT_TEST_CEDAR_AUTH, new_content);

    assert!(
        result.is_ok(),
        "safe_write_in_place should accept special_file=true"
    );
    Ok(())
}
