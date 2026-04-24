use crate::test_common::*;
use anyhow::Result;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::io::{create_temp_dir_and_path, create_test_file};
use rstest::rstest;
use rust_safe_io::error_constants::READ_FILE_FLAG_ERR;
use rust_safe_io::options::OpenFileOptionsBuilder;

/// Given: A file with known content
/// When: The count function is called
/// Then: The correct line, word, and byte counts are returned
#[rstest]
#[case::no_trailing_newline("abc\ndef \nghi\n jkl", 3, 4)]
#[case::with_trailing_newline("abc\ndef \nghi\n jkl\n", 4, 4)]
#[case::multiple_tabs_and_spaces(
    "  Multiple   spaces \t and tabs\n\nEmpty line above\nLast line without newline",
    3,
    11
)]
#[case::empty_file("", 0, 0)]
#[case::file_with_single_new_line("\n", 1, 0)]
#[case::file_with_two_new_lines("\n\n", 2, 0)]
fn test_count_success(
    #[case] file_contents: &str,
    #[case] expected_line_count: usize,
    #[case] expected_word_count: usize,
) -> Result<()> {
    let test_contents = open_dir_and_file_with_contents(file_contents.to_string())?;

    let counts = test_contents.file_handle.counts(&DEFAULT_TEST_CEDAR_AUTH)?;

    assert_eq!(
        *counts.line_count(),
        expected_line_count,
        "Expected {expected_line_count} lines"
    );
    assert_eq!(
        *counts.word_count(),
        expected_word_count,
        "Expected {expected_word_count} words"
    );
    let expected_byte_count = file_contents.len();
    assert_eq!(
        *counts.byte_count(),
        expected_byte_count,
        "Expected {expected_byte_count} bytes",
    );

    // Validate that counting again returns the same result (we rewinded the file after exiting the first time)
    let counts = test_contents.file_handle.counts(&DEFAULT_TEST_CEDAR_AUTH)?;

    assert_eq!(
        *counts.line_count(),
        expected_line_count,
        "Expected {expected_line_count} lines"
    );
    assert_eq!(
        *counts.word_count(),
        expected_word_count,
        "Expected {expected_word_count} words"
    );
    let expected_byte_count = file_contents.len();
    assert_eq!(
        *counts.byte_count(),
        expected_byte_count,
        "Expected {expected_byte_count} bytes",
    );

    Ok(())
}

/// Given: A file opened without read permissions
/// When: The count function is called
/// Then: An error is returned
#[test]
fn test_count_no_read_permission() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let test_file = "test_file.txt";
    create_test_file(&temp_dir, test_file, b"test content")?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        test_file,
        OpenFileOptionsBuilder::default()
            .write(true)
            .build()
            .unwrap(),
    )?;

    let result = file_handle.counts(&DEFAULT_TEST_CEDAR_AUTH);

    assert_error_contains(result, READ_FILE_FLAG_ERR);

    Ok(())
}

/// Given: A file and an unauthorized user
/// When: The count function is called
/// Then: Access is denied
#[test]
fn test_unauthorized_count() -> Result<()> {
    let test_contents = open_dir_and_file()?;
    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"forbid(
            principal == User::"{principal}",
            action == {},
            resource
        );"#,
        FilesystemAction::Read
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let result = test_contents.file_handle.counts(&test_cedar_auth);

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Read
    );
    assert_error_contains(result, &expected_error);

    Ok(())
}
