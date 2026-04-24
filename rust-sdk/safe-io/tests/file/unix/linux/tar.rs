use crate::test_common::open_test_dir_handle;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::io::{ArchiveEntry, create_temp_dir_and_path, create_test_archive};

use anyhow::Result;
use assert_fs::fixture::PathChild;
use assert_fs::fixture::{FileWriteStr, PathCreateDir};
use rstest::rstest;
use rust_safe_io::error_constants::READ_FILE_FLAG_ERR;
use rust_safe_io::options::{ExtractArchiveOptionsBuilder, OpenFileOptionsBuilder};
use std::fs::Permissions;
use std::fs::set_permissions;
use std::fs::{metadata, read_dir, read_to_string};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
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

/// Given: A tar.gz archive with files and a destination directory
/// When: safe_extract_archive is called with default options
/// Then: The archive is extracted successfully with correct file contents
#[test]
fn test_safe_extract_archive_success() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let (dest_dir, dest_dir_path) = create_temp_dir_and_path()?;

    create_test_archive(
        &temp_dir,
        "test.tar.gz",
        vec![
            ArchiveEntry::file("file1.txt", "content of file 1"),
            ArchiveEntry::file("file2.txt", "content of file 2"),
            ArchiveEntry::directory("subdir/"),
            ArchiveEntry::file("subdir/file3.txt", "content of file 3"),
            ArchiveEntry::file("level1/level2/nested_file.txt", "nested content"),
            ArchiveEntry::directory("deep/nested/directory/"),
            ArchiveEntry::file("another/deep/path/deep_file.txt", "deep content"),
        ],
    )?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let dest_handle = open_test_dir_handle(&dest_dir_path);

    let archive_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "test.tar.gz",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let options = ExtractArchiveOptionsBuilder::default().build().unwrap();

    let result =
        archive_handle.safe_extract_archive(&DEFAULT_TEST_CEDAR_AUTH, dest_handle, options);

    assert!(result.is_ok());

    let file1_path = dest_dir.path().join("file1.txt");
    let file2_path = dest_dir.path().join("file2.txt");
    let file3_path = dest_dir.path().join("subdir/file3.txt");

    assert!(file1_path.exists());
    assert!(file2_path.exists());
    assert!(file3_path.exists());

    assert_eq!(read_to_string(file1_path)?, "content of file 1");
    assert_eq!(read_to_string(file2_path)?, "content of file 2");
    assert_eq!(read_to_string(file3_path)?, "content of file 3");

    let nested_file_path = dest_dir.path().join("level1/level2/nested_file.txt");
    let deep_dir_path = dest_dir.path().join("deep/nested/directory");
    let deep_file_path = dest_dir.path().join("another/deep/path/deep_file.txt");

    assert!(nested_file_path.exists());
    assert!(deep_dir_path.exists() && deep_dir_path.is_dir());
    assert!(deep_file_path.exists());

    assert_eq!(read_to_string(nested_file_path)?, "nested content");
    assert_eq!(read_to_string(deep_file_path)?, "deep content");

    Ok(())
}

/// Given: A tar.gz archive and unauthorized user for reading
/// When: safe_extract_archive is called
/// Then: Access is denied for read permission
#[test]
fn test_unauthorized_safe_extract_archive_read() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let (_dest_dir, dest_dir_path) = create_temp_dir_and_path()?;

    create_test_archive(
        &temp_dir,
        "test.tar.gz",
        vec![ArchiveEntry::file("file1.txt", "content")],
    )?;

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

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let dest_handle = open_test_dir_handle(&dest_dir_path);

    let archive_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "test.tar.gz",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let options = ExtractArchiveOptionsBuilder::default().build().unwrap();

    let result = archive_handle.safe_extract_archive(&test_cedar_auth, dest_handle, options);

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Read
    );
    assert_error_contains(result, &expected_error);

    Ok(())
}

/// Given: An archive file opened without read option
/// When: safe_extract_archive is called
/// Then: An error is returned indicating missing read option
#[test]
fn test_safe_extract_archive_no_read_option() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let (_dest_dir, dest_dir_path) = create_temp_dir_and_path()?;

    create_test_archive(
        &temp_dir,
        "test.tar.gz",
        vec![ArchiveEntry::file("file1.txt", "content")],
    )?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let dest_handle = open_test_dir_handle(&dest_dir_path);

    let archive_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "test.tar.gz",
        OpenFileOptionsBuilder::default()
            .write(true)
            .build()
            .unwrap(),
    )?;

    let options = ExtractArchiveOptionsBuilder::default().build().unwrap();

    let result =
        archive_handle.safe_extract_archive(&DEFAULT_TEST_CEDAR_AUTH, dest_handle, options);

    assert_error_contains(result, READ_FILE_FLAG_ERR);

    Ok(())
}

/// Given: A tar.gz archive and unauthorized user for file operations during extraction
/// When: safe_extract_archive is called
/// Then: Extraction behavior varies based on the denied file operation
#[rstest]
#[case::create_denied(FilesystemAction::Create, false)]
#[case::write_denied(FilesystemAction::Write, false)]
#[case::chmod_denied(FilesystemAction::Chmod, true)]
#[case::chown_denied(FilesystemAction::Chown, true)]
fn test_unauthorized_safe_extract_archive_file_operations(
    #[case] denied_action: FilesystemAction,
    #[case] file_should_exist: bool,
) -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let (_dest_dir, dest_dir_path) = create_temp_dir_and_path()?;

    create_test_archive(
        &temp_dir,
        "test.tar.gz",
        vec![ArchiveEntry::file("file1.txt", "content")],
    )?;

    let principal = get_test_rex_principal();
    let dest_file_path = format!("{}/file1.txt", dest_dir_path);

    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action,
            resource
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{dest_file_path}"
        );"#,
        denied_action
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let dest_handle = open_test_dir_handle(&dest_dir_path);

    let archive_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "test.tar.gz",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let options =
        if denied_action == FilesystemAction::Chmod || denied_action == FilesystemAction::Chown {
            ExtractArchiveOptionsBuilder::default()
                .preserve_permissions(true)
                .preserve_ownership(true)
                .build()
                .unwrap()
        } else {
            ExtractArchiveOptionsBuilder::default().build().unwrap()
        };

    let result = archive_handle.safe_extract_archive(&test_cedar_auth, dest_handle, options);

    assert!(result.is_ok());

    let file_path = Path::new(&dest_dir_path).join("file1.txt");
    if file_should_exist {
        assert!(file_path.exists());
        assert_eq!(read_to_string(&file_path)?, "content");
    } else {
        assert!(!file_path.exists());
    }

    Ok(())
}

/// Given: A tar.gz archive with files that already exist in destination
/// When: safe_extract_archive is called
/// Then: Files are overwritten
#[test]
fn test_safe_extract_archive_overwrite_files() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let (dest_dir, dest_dir_path) = create_temp_dir_and_path()?;

    let existing_file = dest_dir.child("file1.txt");
    existing_file.write_str("existing content")?;

    let new_content = "new content";
    create_test_archive(
        &temp_dir,
        "test.tar.gz",
        vec![ArchiveEntry::file("file1.txt", new_content)],
    )?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let dest_handle = open_test_dir_handle(&dest_dir_path);

    let archive_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "test.tar.gz",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let options = ExtractArchiveOptionsBuilder::default().build().unwrap();

    let result =
        archive_handle.safe_extract_archive(&DEFAULT_TEST_CEDAR_AUTH, dest_handle, options);

    assert!(result.is_ok());

    let file_content = read_to_string(existing_file.path())?;
    assert_eq!(file_content, new_content);

    Ok(())
}

/// Given: A tar.gz archive with special file types (symlinks, devices, etc.)
/// When: safe_extract_archive is called
/// Then: Special file types are skipped and regular files are extracted
#[test]
fn test_safe_extract_archive_skip_special_files() -> Result<()> {
    init_test_logger();

    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let (dest_dir, dest_dir_path) = create_temp_dir_and_path()?;

    let content = "regular";

    create_test_archive(
        &temp_dir,
        "special.tar.gz",
        vec![
            ArchiveEntry::file("regular.txt", content),
            ArchiveEntry::special_file("symlink", tar::EntryType::Symlink),
            ArchiveEntry::special_file("chardev", tar::EntryType::Char),
        ],
    )?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let dest_handle = open_test_dir_handle(&dest_dir_path);

    let archive_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "special.tar.gz",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let options = ExtractArchiveOptionsBuilder::default().build().unwrap();

    let result =
        archive_handle.safe_extract_archive(&DEFAULT_TEST_CEDAR_AUTH, dest_handle, options);

    assert!(result.is_ok());

    let regular_file = dest_dir.path().join("regular.txt");
    assert!(regular_file.exists());
    assert_eq!(read_to_string(regular_file)?, "regular");

    assert!(!dest_dir.path().join("symlink").exists());
    assert!(!dest_dir.path().join("chardev").exists());

    Ok(())
}

/// Given: A tar.gz archive with files and directories having specific permissions
/// When: safe_extract_archive is called with preserve_permissions option
/// Then: Permissions are preserved or set to default based on the option
#[rstest::rstest]
#[case::preserve_true(true)]
#[case::preserve_false(false)]
fn test_safe_extract_archive_preserve_permissions(
    #[case] preserve_permissions: bool,
) -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let (dest_dir, dest_dir_path) = create_temp_dir_and_path()?;

    let file_mode = 0o700;
    let dir_mode = 0o700;

    create_test_archive(
        &temp_dir,
        "test.tar.gz",
        vec![
            ArchiveEntry::file("executable.sh", "content").with_mode(file_mode),
            ArchiveEntry::directory("test_directory/").with_mode(dir_mode),
        ],
    )?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let dest_handle = open_test_dir_handle(&dest_dir_path);

    let archive_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "test.tar.gz",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let options = ExtractArchiveOptionsBuilder::default()
        .preserve_permissions(preserve_permissions)
        .build()
        .unwrap();

    let result =
        archive_handle.safe_extract_archive(&DEFAULT_TEST_CEDAR_AUTH, dest_handle, options);
    assert!(result.is_ok());

    let extracted_file = dest_dir.path().join("executable.sh");
    let extracted_dir = dest_dir.path().join("test_directory");

    assert!(extracted_file.exists());
    assert!(extracted_dir.exists() && extracted_dir.is_dir());

    let file_metadata = metadata(&extracted_file)?;
    let dir_metadata = metadata(&extracted_dir)?;

    let actual_file_mode = file_metadata.mode() & PERMISSION_EXTRACT_BITMASK;
    let actual_dir_mode = dir_metadata.mode() & PERMISSION_EXTRACT_BITMASK;

    if preserve_permissions {
        assert_eq!(actual_file_mode, file_mode);
        assert_eq!(actual_dir_mode, dir_mode);
    } else {
        assert_ne!(actual_file_mode, file_mode);
        assert_ne!(actual_dir_mode, dir_mode);
    }

    Ok(())
}

/// Given: A tar.gz archive with files and directories having specific timestamps
/// When: safe_extract_archive is called with preserve_timestamps option
/// Then: Timestamps are preserved or set to current time based on the option
#[rstest::rstest]
#[case::preserve_true(true)]
#[case::preserve_false(false)]
fn test_safe_extract_archive_preserve_timestamps(#[case] preserve_timestamps: bool) -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let (dest_dir, dest_dir_path) = create_temp_dir_and_path()?;

    let custom_mtime = 1609459200;

    create_test_archive(
        &temp_dir,
        "test.tar.gz",
        vec![
            ArchiveEntry::file("timestamped_file.txt", "content").with_mtime(custom_mtime),
            ArchiveEntry::directory("timestamped_directory/").with_mtime(custom_mtime),
        ],
    )?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let dest_handle = open_test_dir_handle(&dest_dir_path);

    let archive_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "test.tar.gz",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let options = ExtractArchiveOptionsBuilder::default()
        .preserve_timestamps(preserve_timestamps)
        .build()
        .unwrap();

    let before_extraction = SystemTime::now() - Duration::from_millis(100);
    let result =
        archive_handle.safe_extract_archive(&DEFAULT_TEST_CEDAR_AUTH, dest_handle, options);
    let after_extraction = SystemTime::now() + Duration::from_millis(100);

    assert!(result.is_ok());

    let extracted_file = dest_dir.path().join("timestamped_file.txt");
    let extracted_dir = dest_dir.path().join("timestamped_directory");

    assert!(extracted_file.exists());
    assert!(extracted_dir.exists() && extracted_dir.is_dir());

    let file_metadata = metadata(&extracted_file)?;
    let dir_metadata = metadata(&extracted_dir)?;

    let file_mtime = file_metadata.modified()?;
    let dir_mtime = dir_metadata.modified()?;

    if preserve_timestamps {
        let expected_time = UNIX_EPOCH + Duration::from_secs(custom_mtime);

        assert_eq!(file_mtime, expected_time);
        assert_eq!(dir_mtime, expected_time);
    } else {
        assert!(file_mtime >= before_extraction);
        assert!(file_mtime <= after_extraction);
        assert!(dir_mtime >= before_extraction);
        assert!(dir_mtime <= after_extraction);
    }

    Ok(())
}

/// Given: A tar.gz archive and unauthorized user for directory operations during extraction
/// When: safe_extract_archive is called
/// Then: Extraction behavior varies based on the denied directory operation
#[rstest]
#[case::create_denied(FilesystemAction::Create, false)]
#[case::chmod_denied(FilesystemAction::Chmod, true)]
#[case::chown_denied(FilesystemAction::Chown, true)]
fn test_unauthorized_safe_extract_archive_directory_operations(
    #[case] denied_action: FilesystemAction,
    #[case] dir_should_exist: bool,
) -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let (_dest_dir, dest_dir_path) = create_temp_dir_and_path()?;

    create_test_archive(
        &temp_dir,
        "test.tar.gz",
        vec![
            ArchiveEntry::directory("test_directory/"),
            ArchiveEntry::file("test_directory/file.txt", "content"),
        ],
    )?;

    let principal = get_test_rex_principal();
    let dest_directory_path = format!("{}/test_directory", dest_dir_path);

    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action,
            resource
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::Dir::"{dest_directory_path}"
        );"#,
        denied_action
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let dest_handle = open_test_dir_handle(&dest_dir_path);

    let archive_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "test.tar.gz",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let options =
        if denied_action == FilesystemAction::Chmod || denied_action == FilesystemAction::Chown {
            ExtractArchiveOptionsBuilder::default()
                .preserve_permissions(true)
                .preserve_ownership(true)
                .build()
                .unwrap()
        } else {
            ExtractArchiveOptionsBuilder::default().build().unwrap()
        };

    let result = archive_handle.safe_extract_archive(&test_cedar_auth, dest_handle, options);

    assert!(result.is_ok());

    let directory_path = std::path::Path::new(&dest_dir_path).join("test_directory");
    let file_path = directory_path.join("file.txt");

    if dir_should_exist {
        assert!(directory_path.exists() && directory_path.is_dir());
        assert!(file_path.exists());
        assert_eq!(read_to_string(&file_path)?, "content");
    } else {
        assert!(!directory_path.exists());
        assert!(!file_path.exists());
    }

    Ok(())
}

/// Given: A tar.gz archive with nested directories and authorization denied for intermediate directory
/// When: safe_extract_archive is called
/// Then: Warning is logged for directory creation failure but extraction continues
#[test]
fn test_safe_extract_archive_nested_directory_creation_failure() -> Result<()> {
    init_test_logger();

    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let (dest_dir, dest_dir_path) = create_temp_dir_and_path()?;

    create_test_archive(
        &temp_dir,
        "test.tar.gz",
        vec![ArchiveEntry::directory("parent/child/grandchild/")],
    )?;

    let principal = get_test_rex_principal();
    let intermediate_dir_path = format!("{}/parent/child", dest_dir_path);
    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action,
            resource
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::Dir::"{intermediate_dir_path}"
        );"#,
        FilesystemAction::Create
    );
    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let dest_handle = open_test_dir_handle(&dest_dir_path);

    let archive_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "test.tar.gz",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let options = ExtractArchiveOptionsBuilder::default().build().unwrap();

    let result = archive_handle.safe_extract_archive(&test_cedar_auth, dest_handle, options);

    assert!(result.is_ok());

    let nested_dir = dest_dir.path().join("parent/child/grandchild");
    assert!(!nested_dir.exists());

    let parent_dir = dest_dir.path().join("parent");
    assert!(!parent_dir.exists());

    Ok(())
}

/// Given: A tar.gz archive with directories having timestamps and permissions that fail to set
/// When: safe_extract_archive is called with preserve_timestamps=true and preserve_permissions=true
/// Then: Warnings are logged but extraction continues successfully
#[test]
fn test_safe_extract_archive_directory_timestamp_and_permission_failure_warning() -> Result<()> {
    init_test_logger();

    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let (dest_dir, dest_dir_path) = create_temp_dir_and_path()?;

    let custom_mtime = 1609459200;
    let custom_mode = 0o700;

    let problem_dir = dest_dir.child("test_dir");
    problem_dir.create_dir_all()?;

    let original_mode = metadata(problem_dir.path())?.mode() & PERMISSION_EXTRACT_BITMASK;

    set_permissions(problem_dir.path(), Permissions::from_mode(0o000))?;

    create_test_archive(
        &temp_dir,
        "test.tar.gz",
        vec![
            ArchiveEntry::directory("test_dir/")
                .with_mtime(custom_mtime)
                .with_mode(custom_mode),
        ],
    )?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let dest_handle = open_test_dir_handle(&dest_dir_path);

    let archive_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "test.tar.gz",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let options = ExtractArchiveOptionsBuilder::default()
        .preserve_timestamps(true)
        .preserve_permissions(true)
        .build()
        .unwrap();

    let result =
        archive_handle.safe_extract_archive(&DEFAULT_TEST_CEDAR_AUTH, dest_handle, options);

    set_permissions(problem_dir.path(), Permissions::from_mode(original_mode))?;

    assert!(result.is_ok());
    assert!(problem_dir.exists());
    assert!(problem_dir.is_dir());

    let final_mode = metadata(problem_dir.path())?.mode() & PERMISSION_EXTRACT_BITMASK;
    assert_ne!(final_mode, custom_mode);

    Ok(())
}

/// Given: An empty tar.gz archive
/// When: safe_extract_archive is called
/// Then: Extraction succeeds with no files created
#[test]
fn test_safe_extract_archive_empty() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let (dest_dir, dest_dir_path) = create_temp_dir_and_path()?;

    create_test_archive(&temp_dir, "empty.tar.gz", vec![])?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let dest_handle = open_test_dir_handle(&dest_dir_path);

    let archive_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "empty.tar.gz",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let options = ExtractArchiveOptionsBuilder::default().build().unwrap();

    let result =
        archive_handle.safe_extract_archive(&DEFAULT_TEST_CEDAR_AUTH, dest_handle, options);

    assert!(result.is_ok());

    let dest_entries: Vec<_> =
        read_dir(dest_dir.path())?.collect::<std::result::Result<Vec<_>, _>>()?;
    assert_eq!(dest_entries.len(), 0);

    Ok(())
}

/// Given: A tar.gz archive with nested directories having specific permissions
/// When: safe_extract_archive is called with preserve_permissions=true
/// Then: Both intermediate and final directory permissions are preserved
#[test]
fn test_safe_extract_archive_preserve_intermediate_directory_permissions() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let (dest_dir, dest_dir_path) = create_temp_dir_and_path()?;

    let parent_mode = 0o755;
    let child_mode = 0o700;
    let grandchild_mode = 0o750;

    create_test_archive(
        &temp_dir,
        "nested.tar.gz",
        vec![
            ArchiveEntry::directory("parent/").with_mode(parent_mode),
            ArchiveEntry::directory("parent/child/").with_mode(child_mode),
            ArchiveEntry::directory("parent/child/grandchild/").with_mode(grandchild_mode),
            ArchiveEntry::file("parent/child/grandchild/file.txt", "content"),
        ],
    )?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let dest_handle = open_test_dir_handle(&dest_dir_path);

    let archive_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "nested.tar.gz",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let options = ExtractArchiveOptionsBuilder::default()
        .preserve_permissions(true)
        .build()
        .unwrap();

    let result =
        archive_handle.safe_extract_archive(&DEFAULT_TEST_CEDAR_AUTH, dest_handle, options);

    assert!(result.is_ok());

    let parent_dir = dest_dir.path().join("parent");
    let child_dir = dest_dir.path().join("parent/child");
    let grandchild_dir = dest_dir.path().join("parent/child/grandchild");
    let nested_file = dest_dir.path().join("parent/child/grandchild/file.txt");

    assert!(parent_dir.exists() && parent_dir.is_dir());
    assert!(child_dir.exists() && child_dir.is_dir());
    assert!(grandchild_dir.exists() && grandchild_dir.is_dir());
    assert!(nested_file.exists() && nested_file.is_file());

    let parent_metadata = metadata(&parent_dir)?;
    let child_metadata = metadata(&child_dir)?;
    let grandchild_metadata = metadata(&grandchild_dir)?;

    let parent_actual_mode = parent_metadata.mode() & PERMISSION_EXTRACT_BITMASK;
    let child_actual_mode = child_metadata.mode() & PERMISSION_EXTRACT_BITMASK;
    let grandchild_actual_mode = grandchild_metadata.mode() & PERMISSION_EXTRACT_BITMASK;

    assert_eq!(parent_actual_mode, parent_mode);
    assert_eq!(child_actual_mode, child_mode);
    assert_eq!(grandchild_actual_mode, grandchild_mode);

    Ok(())
}

/// Given: A file that is not actually gzip compressed
/// When: safe_extract_archive is called
/// Then: Extraction fails gracefully with an "invalid gzip" error
#[test]
fn test_safe_extract_archive_invalid_tar_gz() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let (_dest_dir, dest_dir_path) = create_temp_dir_and_path()?;

    let fake_gz_file = temp_dir.child("fake.tar");
    fake_gz_file.write_str("This is just plain text, not gzip compressed data!")?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let dest_handle = open_test_dir_handle(&dest_dir_path);

    let archive_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "fake.tar",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let options = ExtractArchiveOptionsBuilder::default().build().unwrap();

    let result =
        archive_handle.safe_extract_archive(&DEFAULT_TEST_CEDAR_AUTH, dest_handle, options);

    assert!(result.is_err());
    assert_error_contains(result, "invalid gzip");

    Ok(())
}
