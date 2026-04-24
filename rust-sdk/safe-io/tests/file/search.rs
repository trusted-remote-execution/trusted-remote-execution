use crate::test_common::*;
use anyhow::Result;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rex_test_utils::assertions::assert_error_contains;
use rust_safe_io::error_constants::INVALID_REGEX_PATTERN_ERR;
use std::collections::HashMap;

const SENSITIVE_FILE_CONTENT: &str = "Starting application initialization\nnot recorded\nLoading configuration files\ncould not open file \"config.json\" for reading: Permission denied\nUsing default configuration\nDatabase connection not recorded due to timeout\ncould not read file \"data.bin\": I/O error occurred\ncould not read file \"log.txt\": read 512 of 1024\nApplication startup completed";

/// Given: A file with content
/// When: safe_search is called
/// Then: All matches are correctly found with line numbers
#[test]
fn test_safe_search() -> Result<()> {
    let postgres_config = r#"# PostgreSQL Configuration File
log_directory = '/appdata/log/error'
ssl = on
SSL_max_protocol_version = 'TLSv1.3'
port = 5432
max_connections = LEAST(${DBInstanceClassMemory/9531392},5000)
shared_buffers = 128MB
effective_cache_size = 4GB
babelfishpg_tds.port = 1433
log_statement = 'all'"#;

    let test_contents = open_dir_and_file_with_contents(postgres_config.to_string())?;

    // Test case-insensitive SSL matches
    let case_insensitive_matches = test_contents
        .file_handle
        .safe_search(&DEFAULT_TEST_CEDAR_AUTH, "(?i)ssl")?;

    let expected_ssl =
        HashMap::from([(3, "ssl = on"), (4, "SSL_max_protocol_version = 'TLSv1.3'")]);
    let actual_ssl: HashMap<usize, &str> = case_insensitive_matches
        .iter()
        .map(|m| (m.line_number, m.line_content.as_str()))
        .collect();
    assert_eq!(actual_ssl, expected_ssl);

    // Test numeric matches with MB/GB
    let numeric_matches = test_contents
        .file_handle
        .safe_search(&DEFAULT_TEST_CEDAR_AUTH, "\\d+[MG]B")?;

    let expected_numeric = HashMap::from([
        (7, "shared_buffers = 128MB"),
        (8, "effective_cache_size = 4GB"),
    ]);
    let actual_numeric: HashMap<usize, &str> = numeric_matches
        .iter()
        .map(|m| (m.line_number, m.line_content.as_str()))
        .collect();
    assert_eq!(actual_numeric, expected_numeric);

    Ok(())
}

/// Given: A file with content and invalid regex pattern
/// When: safe_search is called
/// Then: An error is returned
#[test]
fn test_safe_search_invalid_pattern() -> Result<()> {
    let test_contents = open_dir_and_file()?;

    let result = test_contents
        .file_handle
        .safe_search(&DEFAULT_TEST_CEDAR_AUTH, "[invalid");

    assert!(
        result.is_err(),
        "Expected safe_search to fail with invalid regex pattern, but it succeeded"
    );
    assert_error_contains(result, INVALID_REGEX_PATTERN_ERR);

    Ok(())
}

/// Given: A file with content and pattern that doesn't match
/// When: safe_search is called
/// Then: Empty vector is returned
#[test]
fn test_safe_search_no_matches() -> Result<()> {
    let test_content = "hello world";
    let test_contents = open_dir_and_file_with_contents(test_content.to_string())?;

    let matches = test_contents
        .file_handle
        .safe_search(&DEFAULT_TEST_CEDAR_AUTH, "xyz")?;

    assert_eq!(
        matches.len(),
        0,
        "Expected no matches for pattern 'xyz', but found {} matches",
        matches.len()
    );

    Ok(())
}

/// Given: A file and unauthorized Cedar context
/// When: safe_search is called
/// Then: Authorization error is returned
#[test]
fn test_unauthorized_safe_search() -> Result<()> {
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

    let result = test_contents
        .file_handle
        .safe_search(&test_cedar_auth, "test");

    assert!(
        result.is_err(),
        "Expected safe_search to fail with unauthorized user, but it succeeded"
    );
    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Read
    );
    assert_error_contains(result, &expected_error);

    Ok(())
}

/// Given: A file with content
/// When: safe_search is called followed by safe_read
/// Then: safe_read returns the full original content (proving rewind worked)
#[test]
fn test_safe_search_rewinds_file_for_subsequent_read() -> Result<()> {
    let test_content = "line1\nline2\nline3\n";
    let test_contents = open_dir_and_file_with_contents(test_content.to_string())?;

    // Perform search which reads through the file
    let _matches = test_contents
        .file_handle
        .safe_search(&DEFAULT_TEST_CEDAR_AUTH, "line")?;

    // Verify file was rewound: safe_read should return full content from beginning
    let read_content = test_contents
        .file_handle
        .safe_read(&DEFAULT_TEST_CEDAR_AUTH)?;
    assert_eq!(
        read_content, test_content,
        "File should be rewound after safe_search, allowing full content to be read again"
    );

    Ok(())
}

/// Given: A file and a user with only RedactedRead permission (no Read permission)
/// When: safe_search is called
/// Then: Authorization error is returned since redaction dictionary cannot be accessed
#[test]
fn test_safe_search_with_redacted_read_permission_dir_permission_deny_error() -> Result<()> {
    let test_contents = open_dir_and_file_with_contents(SENSITIVE_FILE_CONTENT.to_string())?;
    let principal = get_test_rex_principal();
    // Policy grants RedactedRead but not Read, and no permission to open redaction dictionary dir
    let test_policy = format!(
        r#"
        permit (
            principal == User::"{principal}",
            action == file_system::Action::"redacted_read",
            resource is file_system::File
        );"#,
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let result = test_contents
        .file_handle
        .safe_search(&test_cedar_auth, "(?i)error");

    // Should fail because user can't access the redaction dictionary directory
    assert!(
        result.is_err(),
        "Expected safe_search to fail when redaction dictionary dir is inaccessible"
    );
    assert_error_contains(
        result,
        &format!(
            "Permission denied: {} unauthorized to perform file_system::Action::\"open\" for file_system::Dir::/etc/opt/rex",
            principal
        ),
    );

    Ok(())
}

/// Given: A file and a user with RedactedRead permission plus redaction dictionary access
/// When: safe_search is called but redaction dictionary file is missing
/// Then: File not found error is returned
#[test]
fn test_safe_search_with_redacted_read_permission_file_missing_error() -> Result<()> {
    let test_contents = open_dir_and_file_with_contents(SENSITIVE_FILE_CONTENT.to_string())?;
    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"
        permit (
            principal == User::"{principal}",
            action == file_system::Action::"redacted_read",
            resource is file_system::File
        ) when {{
            resource in file_system::Dir::"{}"
        }};
        permit(
            principal == User::"{principal}",
            action == file_system::Action::"open",
            resource
        ) when {{
            resource == file_system::Dir::"/etc/opt/rex" ||
            resource == file_system::Dir::"/private/etc/opt/rex"
        }};
        permit(
            principal == User::"{principal}",
            action in [file_system::Action::"open", file_system::Action::"read"],
            resource
        ) when {{
            resource == file_system::File::"/etc/opt/rex/rex_redaction.config" ||
            resource == file_system::File::"/private/etc/opt/rex/rex_redaction.config"
        }};"#,
        test_contents.dir_name
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let result = test_contents
        .file_handle
        .safe_search(&test_cedar_auth, "(?i)error");

    // Should fail because redaction dictionary file doesn't exist
    assert!(
        result.is_err(),
        "Expected safe_search to fail when redaction dictionary file is missing"
    );
    assert_error_contains(result, "No such file or directory");

    Ok(())
}

/// Given: A user with both Read and RedactedRead permissions
/// When: safe_search is called
/// Then: Search returns unredacted results (Read takes precedence)
#[test]
fn test_safe_search_read_permission_takes_precedence_over_redacted_read() -> Result<()> {
    let test_content =
        "error: something went wrong\ninfo: all systems normal\nerror: another issue";
    let test_contents = open_dir_and_file_with_contents(test_content.to_string())?;
    let principal = get_test_rex_principal();
    // Policy grants both Read and RedactedRead
    let test_policy = format!(
        r#"
        permit (
            principal == User::"{principal}",
            action == file_system::Action::"read",
            resource is file_system::File
        );
        permit (
            principal == User::"{principal}",
            action == file_system::Action::"redacted_read",
            resource is file_system::File
        );"#,
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let matches = test_contents
        .file_handle
        .safe_search(&test_cedar_auth, "error")?;

    // Should return 2 matches with unredacted content
    assert_eq!(matches.len(), 2, "Expected 2 error matches");
    assert_eq!(
        matches[0].line_content, "error: something went wrong",
        "First match should be unredacted"
    );
    assert_eq!(
        matches[1].line_content, "error: another issue",
        "Second match should be unredacted"
    );

    Ok(())
}

/// Given: A file and a user with neither Read nor RedactedRead permission
/// When: safe_search is called
/// Then: Authorization error is returned for the Read action
#[test]
fn test_safe_search_no_read_or_redacted_read_permission_returns_authz_error() -> Result<()> {
    let test_contents = open_dir_and_file_with_contents(SENSITIVE_FILE_CONTENT.to_string())?;
    let principal = get_test_rex_principal();
    // Policy explicitly forbids both Read and RedactedRead
    let test_policy = format!(
        r#"
        permit (
            principal,
            action,
            resource
        );
        forbid (
            principal == User::"{principal}",
            action == file_system::Action::"read",
            resource is file_system::File
        );
        forbid (
            principal == User::"{principal}",
            action == file_system::Action::"redacted_read",
            resource is file_system::File
        );"#,
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let result = test_contents
        .file_handle
        .safe_search(&test_cedar_auth, "(?i)error");

    // Should fail with authorization error for Read action (checked first)
    assert!(
        result.is_err(),
        "Expected safe_search to fail when neither Read nor RedactedRead is permitted"
    );
    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Read
    );
    assert_error_contains(result, &expected_error);

    Ok(())
}
