use crate::test_common::*;
use anyhow::Result;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::io::{create_temp_dir_and_path, create_test_file};
use rust_safe_io::error_constants::READ_FILE_FLAG_ERR;
use rust_safe_io::options::OpenFileOptionsBuilder;

/// Given: a file handle to a file containing some unprintable and printable characters
/// When: The extract_strings function is called
/// Then: a vector of strings containing printable characters that are more than 3 characters long is returned
#[test]
fn test_extract_strings_success() -> Result<()> {
    let content = "Hello\x01World\x02This\x03is\x04a\x05test\x06with\x07printable\x10and\x11unprintable\x08chars";
    let test_contents = open_dir_and_file_with_contents(content.to_string())?;

    let strings = test_contents
        .file_handle
        .extract_strings(&DEFAULT_TEST_CEDAR_AUTH)?;

    // Verify that only printable strings longer than 3 characters are returned
    assert!(strings.contains(&"Hello".to_string()));
    assert!(strings.contains(&"World".to_string()));
    assert!(strings.contains(&"This".to_string()));
    assert!(strings.contains(&"test".to_string()));
    assert!(strings.contains(&"with".to_string()));
    assert!(strings.contains(&"printable".to_string()));
    assert!(strings.contains(&"unprintable".to_string()));
    assert!(strings.contains(&"chars".to_string()));

    // Verify that short strings (like "is", "a") are not included
    assert!(!strings.contains(&"is".to_string()));
    assert!(!strings.contains(&"a".to_string()));
    assert!(!strings.contains(&"and".to_string()));

    Ok(())
}

/// Given: a file handle and a user unauthorized to read the file
/// When: The extract_strings function is called
/// Then: an authorization error is returned
#[test]
fn test_unauthorized_extract_strings() -> Result<()> {
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

    let result = test_contents.file_handle.extract_strings(&test_cedar_auth);

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Read
    );
    assert_error_contains(result, &expected_error);

    Ok(())
}

/// Given: a file handle opened without the read option being true
/// When: The extract_strings function is called
/// Then: an error is returned
#[test]
fn test_extract_strings_no_read_option() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let test_file = "test_extract_strings.txt";
    let file_content = "This is a test file for extract_strings";
    create_test_file(&temp_dir, test_file, file_content.as_bytes())?;

    let file_handle = dir_handle
        .safe_open_file(
            &DEFAULT_TEST_CEDAR_AUTH,
            test_file,
            OpenFileOptionsBuilder::default()
                .write(true) // Only write permission, no read permission
                .build()
                .unwrap(),
        )
        .unwrap();

    let result = file_handle.extract_strings(&DEFAULT_TEST_CEDAR_AUTH);

    assert_error_contains(result, READ_FILE_FLAG_ERR);

    Ok(())
}

/// Given: A file with content
/// When: extract_strings is called followed by safe_read
/// Then: safe_read returns the full original content (proving rewind worked)
#[test]
fn test_extract_strings_rewinds_file_for_subsequent_read() -> Result<()> {
    let content = "Hello\x01World\x02Test\x03Content";
    let test_contents = open_dir_and_file_with_contents(content.to_string())?;

    // Extract strings which reads through the file
    let _strings = test_contents
        .file_handle
        .extract_strings(&DEFAULT_TEST_CEDAR_AUTH)?;

    // Verify file was rewound: safe_read should return full content from beginning
    let read_content = test_contents
        .file_handle
        .safe_read(&DEFAULT_TEST_CEDAR_AUTH)?;
    assert_eq!(
        read_content, content,
        "File should be rewound after extract_strings, allowing full content to be read again"
    );

    Ok(())
}
