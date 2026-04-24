use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::io::create_temp_dir_and_path;
use rex_test_utils::random::get_rand_string;

use anyhow::Result;
use assert_fs::TempDir;
use assert_fs::fixture::SymlinkToFile;
use assert_fs::prelude::{FileWriteStr, PathChild};
use rust_safe_io::DirConfigBuilder;
use rust_safe_io::options::{MoveOptionsBuilder, OpenDirOptionsBuilder, OpenFileOptionsBuilder};

use std::fs::{read_link, read_to_string};

use crate::test_common::open_test_dir_handle;

fn verify_move_results(
    src_dir: &TempDir,
    src_filename: &str,
    dest_dir: &TempDir,
    dest_filename: &str,
    expected_content: &str,
) -> Result<()> {
    assert!(
        !src_dir.child(src_filename).exists(),
        "Expected source file '{}' to no longer exist after move",
        src_filename
    );

    let dest_file_path = dest_dir.child(dest_filename);
    assert!(
        dest_file_path.exists(),
        "Expected destination file '{}' to exist after move",
        dest_filename
    );

    let content = std::fs::read_to_string(dest_file_path.path())?;

    assert_eq!(
        content, expected_content,
        "Expected moved file content to match original content"
    );

    Ok(())
}

fn setup_move_test() -> Result<(
    TempDir,
    TempDir,
    &'static str,
    &'static str,
    &'static str,
    rust_safe_io::RcDirHandle,
    rust_safe_io::RcDirHandle,
)> {
    let file_content = "test content for move comparison";

    let (src_temp_dir, src_temp_dir_path) = create_temp_dir_and_path()?;
    let src_dir_handle = open_test_dir_handle(&src_temp_dir_path);

    let (dest_temp_dir, dest_temp_dir_path) = create_temp_dir_and_path()?;
    let dest_dir_handle = open_test_dir_handle(&dest_temp_dir_path);

    let src_filename = "safe_move_source.txt";
    let dest_filename = "safe_move_dest.txt";
    let src_file = src_temp_dir.child(src_filename);
    src_file.write_str(file_content)?;

    Ok((
        src_temp_dir,
        dest_temp_dir,
        src_filename,
        dest_filename,
        file_content,
        src_dir_handle,
        dest_dir_handle,
    ))
}

/// Given: A source file and a destination directory
/// When: The file is moved using safe_move
/// Then: The file is successfully moved to the destination with the same content
#[test]
fn test_safe_move_file_success() -> Result<()> {
    let (
        src_temp_dir,
        dest_temp_dir,
        src_filename,
        dest_filename,
        file_content,
        src_dir_handle,
        dest_dir_handle,
    ) = setup_move_test()?;

    let src_file_handle = src_dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        &src_filename,
        OpenFileOptionsBuilder::default()
            .read(true)
            .write(true)
            .build()
            .unwrap(),
    )?;

    let moved_file_handle = src_file_handle.safe_move(
        &DEFAULT_TEST_CEDAR_AUTH,
        dest_dir_handle,
        &dest_filename,
        MoveOptionsBuilder::default().build().unwrap(),
    )?;

    verify_move_results(
        &src_temp_dir,
        &src_filename,
        &dest_temp_dir,
        &dest_filename,
        &file_content,
    )?;

    assert_eq!(
        moved_file_handle.path(),
        dest_filename,
        "Expected moved file handle to have the destination filename"
    );

    Ok(())
}

/// Given: A source file and a destination directory
/// When: The file is moved using safe_move with verbose true
/// Then: The file is successfully moved to the destination with the same content
#[test]
fn test_safe_move_file_verbose_success() -> Result<()> {
    let (
        src_temp_dir,
        dest_temp_dir,
        src_filename,
        dest_filename,
        file_content,
        src_dir_handle,
        dest_dir_handle,
    ) = setup_move_test()?;

    let src_file_handle = src_dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        &src_filename,
        OpenFileOptionsBuilder::default()
            .read(true)
            .write(true)
            .build()
            .unwrap(),
    )?;

    let moved_file_handle = src_file_handle.safe_move(
        &DEFAULT_TEST_CEDAR_AUTH,
        dest_dir_handle,
        &dest_filename,
        MoveOptionsBuilder::default().verbose(true).build().unwrap(),
    )?;

    verify_move_results(
        &src_temp_dir,
        &src_filename,
        &dest_temp_dir,
        &dest_filename,
        &file_content,
    )?;

    assert_eq!(
        moved_file_handle.path(),
        dest_filename,
        "Expected moved file handle to have the destination filename"
    );

    Ok(())
}

/// Given: Two identical source files
/// When: One is moved using safe_move and one using std::process::Command("mv")
/// Then: Both operations should have the same result
#[test]
fn test_safe_move_matches_process_command() -> Result<()> {
    let (
        src_temp_dir,
        dest_temp_dir,
        safe_move_src_filename,
        safe_move_dest_filename,
        file_content,
        src_dir_handle,
        dest_dir_handle,
    ) = setup_move_test()?;

    let src_file_handle = src_dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        &safe_move_src_filename,
        OpenFileOptionsBuilder::default()
            .read(true)
            .write(true)
            .build()
            .unwrap(),
    )?;

    src_file_handle.safe_move(
        &DEFAULT_TEST_CEDAR_AUTH,
        dest_dir_handle,
        &safe_move_dest_filename,
        MoveOptionsBuilder::default().build().unwrap(),
    )?;

    verify_move_results(
        &src_temp_dir,
        &safe_move_src_filename,
        &dest_temp_dir,
        &safe_move_dest_filename,
        &file_content,
    )?;

    let (std_src_temp_dir, std_dest_temp_dir, std_mv_src_filename, std_mv_dest_filename, _, _, _) =
        setup_move_test()?;

    let src_path = std_src_temp_dir
        .child(&std_mv_src_filename)
        .path()
        .to_string_lossy()
        .to_string();
    let dest_path = std_dest_temp_dir
        .child(&std_mv_dest_filename)
        .path()
        .to_string_lossy()
        .to_string();

    let status = std::process::Command::new("mv")
        .arg(&src_path)
        .arg(&dest_path)
        .status()?;

    assert!(status.success(), "mv command failed");

    verify_move_results(
        &std_src_temp_dir,
        &std_mv_src_filename,
        &std_dest_temp_dir,
        &std_mv_dest_filename,
        &file_content,
    )?;

    Ok(())
}
/// Given: A source file and a destination directory but unauthorized user for move operation
/// When: The file is moved using safe_move
/// Then: Access is denied for the move action with context
#[test]
fn test_unauthorized_safe_move_file_with_context() -> Result<()> {
    let (
        src_temp_dir,
        _dest_temp_dir,
        src_filename,
        dest_filename,
        _file_content,
        src_dir_handle,
        dest_dir_handle,
    ) = setup_move_test()?;

    let src_file_handle = src_dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        &src_filename,
        OpenFileOptionsBuilder::default()
            .read(true)
            .write(true)
            .build()
            .unwrap(),
    )?;

    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"forbid(
            principal == User::"{principal}",
            action == {},
            resource
        );"#,
        FilesystemAction::Move
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let result = src_file_handle.safe_move(
        &test_cedar_auth,
        dest_dir_handle,
        &dest_filename,
        MoveOptionsBuilder::default().build().unwrap(),
    );

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Move
    );
    assert_error_contains(result, &expected_error);

    assert!(
        src_temp_dir.child(src_filename).exists(),
        "Expected source file to still exist after failed move"
    );

    Ok(())
}

/// Given: A source file and a destination directory but unauthorized user for create operation
/// When: The file is moved using safe_move
/// Then: Access is denied for the create action
#[test]
fn test_unauthorized_safe_move_file_create() -> Result<()> {
    let (
        src_temp_dir,
        _dest_temp_dir,
        src_filename,
        dest_filename,
        _file_content,
        src_dir_handle,
        dest_dir_handle,
    ) = setup_move_test()?;

    let src_file_handle = src_dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        &src_filename,
        OpenFileOptionsBuilder::default()
            .read(true)
            .write(true)
            .build()
            .unwrap(),
    )?;

    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action == {},
            resource
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource
        );"#,
        FilesystemAction::Move,
        FilesystemAction::Create
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let result = src_file_handle.safe_move(
        &test_cedar_auth,
        dest_dir_handle,
        &dest_filename,
        MoveOptionsBuilder::default().build().unwrap(),
    );

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Create
    );
    assert_error_contains(result, &expected_error);

    assert!(
        src_temp_dir.child(src_filename).exists(),
        "Expected source file to still exist after failed move"
    );

    Ok(())
}

/// Given: A source file and a non-existent destination directory
/// When: The safe_move method is called on the RcFileHandle
/// Then: A FileError is returned with the appropriate error message
#[test]
fn test_safe_move_file_unspecified_error() -> Result<()> {
    let (
        _src_temp_dir,
        dest_temp_dir,
        src_filename,
        dest_filename,
        _file_content,
        src_dir_handle,
        dest_dir_handle,
    ) = setup_move_test()?;

    dest_temp_dir.close()?;

    let src_file_handle = src_dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        &src_filename,
        OpenFileOptionsBuilder::default()
            .read(true)
            .write(true)
            .build()
            .unwrap(),
    )?;

    let result = src_file_handle.safe_move(
        &DEFAULT_TEST_CEDAR_AUTH,
        dest_dir_handle,
        &dest_filename,
        MoveOptionsBuilder::default().build().unwrap(),
    );

    assert!(result.is_err());
    assert_error_contains(result, "Error moving file");

    Ok(())
}

/// Given: A source file name with path traversal and a destination directory
/// When: The file is moved using safe_move with path traversal in the source path
/// Then: A PermissionDeniedError is returned due to path traversal
#[test]
fn test_safe_move_file_src_path_traversal() -> Result<()> {
    let (
        src_temp_dir,
        _dest_temp_dir,
        src_filename,
        dest_filename,
        _file_content,
        src_dir_handle,
        dest_dir_handle,
    ) = setup_move_test()?;

    let regular_filename = "source_file.txt";
    let src_file = src_temp_dir.child(regular_filename);
    src_file.write_str("test content for path traversal")?;

    src_dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        regular_filename,
        OpenFileOptionsBuilder::default()
            .read(true)
            .write(true)
            .build()
            .unwrap(),
    )?;

    let src_filename_with_traversal = "../source_file.txt";

    let result = src_dir_handle
        .safe_open_file(
            &DEFAULT_TEST_CEDAR_AUTH,
            src_filename_with_traversal,
            OpenFileOptionsBuilder::default()
                .read(true)
                .build()
                .unwrap(),
        )
        .and_then(|file_handle| {
            file_handle.safe_move(
                &DEFAULT_TEST_CEDAR_AUTH,
                dest_dir_handle,
                &dest_filename,
                MoveOptionsBuilder::default().build().unwrap(),
            )
        });

    assert_error_contains(result, "Path traversal detected");

    assert!(
        src_temp_dir.child(src_filename).exists(),
        "Expected source file to still exist after failed move"
    );

    Ok(())
}

/// Given: A source file and a destination path with path traversal
/// When: The file is moved using safe_move with path traversal in the destination path
/// Then: A PermissionDeniedError is returned due to path traversal
#[test]
fn test_safe_move_file_dest_path_traversal() -> Result<()> {
    let (
        src_temp_dir,
        _dest_temp_dir,
        src_filename,
        _dest_filename,
        _file_content,
        src_dir_handle,
        dest_dir_handle,
    ) = setup_move_test()?;

    let src_file_handle = src_dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        &src_filename,
        OpenFileOptionsBuilder::default()
            .read(true)
            .write(true)
            .build()
            .unwrap(),
    )?;

    let dest_filename_with_traversal = "../moved_file.txt";

    let result = src_file_handle.safe_move(
        &DEFAULT_TEST_CEDAR_AUTH,
        dest_dir_handle,
        dest_filename_with_traversal,
        MoveOptionsBuilder::default().build().unwrap(),
    );

    assert_error_contains(result, "Path traversal detected");

    assert!(
        src_temp_dir.child(src_filename).exists(),
        "Expected source file to still exist after failed move"
    );

    Ok(())
}

/// Given: A source file in /dev/shm (tmpfs) and a destination directory on a different filesystem
/// When: The safe_move method is called to move the file across filesystems
/// Then: The file is successfully moved using the backup mechanism and content is preserved
#[test]
#[cfg(target_os = "linux")]
fn test_move_file_cross_fs_with_backup_success() -> Result<()> {
    // /dev/shm is a temporary file system
    let src_dir = TempDir::new_in("/dev/shm/")?;
    let src_dir_path = src_dir.path().to_string_lossy().to_string();

    let src_dir_handle = DirConfigBuilder::default()
        .path(src_dir_path)
        .build()
        .unwrap()
        .safe_open(
            &DEFAULT_TEST_CEDAR_AUTH,
            OpenDirOptionsBuilder::default().build().unwrap(),
        )?;

    let src_file_handle = src_dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "src_txt",
        OpenFileOptionsBuilder::default()
            .create(true)
            .write(true)
            .read(true)
            .build()
            .unwrap(),
    )?;

    let content = get_rand_string();
    let src_file_handle = src_file_handle.safe_write(&DEFAULT_TEST_CEDAR_AUTH, &content)?;

    let src_metadata = src_file_handle.metadata(&DEFAULT_TEST_CEDAR_AUTH)?;
    let src_permissions = src_metadata.cap_std_metadata().permissions();

    let (_dst_dir, dst_dir_path) = create_temp_dir_and_path()?;
    let dst_dir_handle = open_test_dir_handle(&dst_dir_path);

    let file_handle = src_file_handle.safe_move(
        &DEFAULT_TEST_CEDAR_AUTH,
        dst_dir_handle,
        "dst_filename",
        MoveOptionsBuilder::default().backup(true).build().unwrap(),
    )?;
    let moved_content = file_handle.safe_read(&DEFAULT_TEST_CEDAR_AUTH)?;
    assert_eq!(
        moved_content, content,
        "Expected moved file content to match original content"
    );

    let dst_metadata = file_handle.metadata(&DEFAULT_TEST_CEDAR_AUTH)?;
    let dst_permissions = dst_metadata.cap_std_metadata().permissions();
    assert_eq!(
        src_permissions, dst_permissions,
        "Expected moved file permissions to match original permissions"
    );
    Ok(())
}

/// Given: A source file in /dev/shm (tmpfs) and a destination directory on a different filesystem
/// When: The safe_move method is called to move the file across filesystems with backup=false
/// Then: The file is successfully moved using the standard mechanism and content is preserved
#[test]
#[cfg(target_os = "linux")]
fn test_move_file_cross_fs_no_backup_success() -> Result<()> {
    let src_dir = TempDir::new_in("/dev/shm/")?;
    let src_dir_path = src_dir.path().to_string_lossy().to_string();

    let src_dir_handle = DirConfigBuilder::default()
        .path(src_dir_path)
        .build()
        .unwrap()
        .safe_open(
            &DEFAULT_TEST_CEDAR_AUTH,
            OpenDirOptionsBuilder::default().build().unwrap(),
        )?;

    let src_file_handle = src_dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "src_txt",
        OpenFileOptionsBuilder::default()
            .create(true)
            .write(true)
            .read(true)
            .build()
            .unwrap(),
    )?;

    let content = get_rand_string();
    let src_file_handle = src_file_handle.safe_write(&DEFAULT_TEST_CEDAR_AUTH, &content)?;

    let src_metadata = src_file_handle.metadata(&DEFAULT_TEST_CEDAR_AUTH)?;
    let src_permissions = src_metadata.cap_std_metadata().permissions();

    let (_dst_dir, dst_dir_path) = create_temp_dir_and_path()?;
    let dst_dir_handle = open_test_dir_handle(&dst_dir_path);

    let file_handle = src_file_handle.safe_move(
        &DEFAULT_TEST_CEDAR_AUTH,
        dst_dir_handle,
        "dst_filename",
        MoveOptionsBuilder::default().backup(false).build().unwrap(),
    )?;
    let moved_content = file_handle.safe_read(&DEFAULT_TEST_CEDAR_AUTH)?;
    assert_eq!(
        moved_content, content,
        "Expected moved file content to match original content"
    );

    let dst_metadata = file_handle.metadata(&DEFAULT_TEST_CEDAR_AUTH)?;
    let dst_permissions = dst_metadata.cap_std_metadata().permissions();
    assert_eq!(
        src_permissions, dst_permissions,
        "Expected moved file permissions to match original permissions"
    );
    Ok(())
}

/// Given: A cedar policy that forbids opening the specific destination file
/// When: A file is moved across filesystems
/// Then: safe_move fails with a PermissionDenied error
#[test]
#[cfg(target_os = "linux")]
fn test_move_file_with_backup_cross_fs_unauthorized() -> Result<()> {
    let principal = get_test_rex_principal();
    let (_dst_dir, dst_dir_path) = create_temp_dir_and_path()?;

    let test_policy = format!(
        r#"permit(
            principal,
            action,
            resource
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{dst_dir_path}/dst_filename"
        );"#,
        FilesystemAction::Open
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let src_dir = TempDir::new_in("/dev/shm/")?;
    let src_dir_path = src_dir.path().to_string_lossy().to_string();

    let src_dir_handle = DirConfigBuilder::default()
        .path(src_dir_path)
        .build()
        .unwrap()
        .safe_open(
            &DEFAULT_TEST_CEDAR_AUTH,
            OpenDirOptionsBuilder::default().build().unwrap(),
        )?;

    let src_file_handle = src_dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "src_txt",
        OpenFileOptionsBuilder::default()
            .create(true)
            .write(true)
            .read(true)
            .build()
            .unwrap(),
    )?;

    let content = get_rand_string();
    let src_file_handle = src_file_handle.safe_write(&DEFAULT_TEST_CEDAR_AUTH, &content)?;

    let dst_dir_handle = open_test_dir_handle(&dst_dir_path);

    let result = src_file_handle.safe_move(
        &test_cedar_auth,
        dst_dir_handle,
        "dst_filename",
        MoveOptionsBuilder::default().backup(true).build().unwrap(),
    );

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {} for file_system::File::{}/dst_filename",
        FilesystemAction::Open,
        dst_dir_path
    );

    assert_error_contains(result, &expected_error);

    Ok(())
}

/// Given: A cedar policy that forbids opening the specific destination file
/// When: A file is moved across filesystems with no backup
/// Then: safe_move fails with a PermissionDenied error
#[test]
#[cfg(target_os = "linux")]
fn test_move_file_no_backup_cross_fs_open_unauthorized() -> Result<()> {
    let principal = get_test_rex_principal();
    let (_dst_dir, dst_dir_path) = create_temp_dir_and_path()?;

    let test_policy = format!(
        r#"permit(
            principal,
            action,
            resource
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{dst_dir_path}/dst_filename"
        );"#,
        FilesystemAction::Open
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let src_dir = TempDir::new_in("/dev/shm/")?;
    let src_dir_path = src_dir.path().to_string_lossy().to_string();

    let src_dir_handle = DirConfigBuilder::default()
        .path(src_dir_path)
        .build()
        .unwrap()
        .safe_open(
            &DEFAULT_TEST_CEDAR_AUTH,
            OpenDirOptionsBuilder::default().build().unwrap(),
        )?;

    let src_file_handle = src_dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "src_txt",
        OpenFileOptionsBuilder::default()
            .create(true)
            .write(true)
            .read(true)
            .build()
            .unwrap(),
    )?;

    let content = get_rand_string();
    let src_file_handle = src_file_handle.safe_write(&DEFAULT_TEST_CEDAR_AUTH, &content)?;

    let dst_dir_handle = open_test_dir_handle(&dst_dir_path);

    let result = src_file_handle.safe_move(
        &test_cedar_auth,
        dst_dir_handle,
        "dst_filename",
        MoveOptionsBuilder::default().backup(false).build().unwrap(),
    );

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {} for file_system::File::{}/dst_filename",
        FilesystemAction::Open,
        dst_dir_path
    );

    assert_error_contains(result, &expected_error);

    Ok(())
}

/// Given: A cedar policy that forbids opening the specific destination file
/// When: A file is moved across filesystems with no backup
/// Then: safe_move fails with a PermissionDenied error
#[test]
#[cfg(target_os = "linux")]
fn test_move_file_no_backup_cross_fs_write_unauthorized() -> Result<()> {
    let principal = get_test_rex_principal();
    let (_dst_dir, dst_dir_path) = create_temp_dir_and_path()?;

    let test_policy = format!(
        r#"permit(
            principal,
            action,
            resource
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{dst_dir_path}/dst_filename"
        );"#,
        FilesystemAction::Write
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let src_dir = TempDir::new_in("/dev/shm/")?;
    let src_dir_path = src_dir.path().to_string_lossy().to_string();

    let src_dir_handle = DirConfigBuilder::default()
        .path(src_dir_path)
        .build()
        .unwrap()
        .safe_open(
            &DEFAULT_TEST_CEDAR_AUTH,
            OpenDirOptionsBuilder::default().build().unwrap(),
        )?;

    let src_file_handle = src_dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "src_txt",
        OpenFileOptionsBuilder::default()
            .create(true)
            .write(true)
            .read(true)
            .build()
            .unwrap(),
    )?;

    let content = get_rand_string();
    let src_file_handle = src_file_handle.safe_write(&DEFAULT_TEST_CEDAR_AUTH, &content)?;

    let dst_dir_handle = open_test_dir_handle(&dst_dir_path);

    let result = src_file_handle.safe_move(
        &test_cedar_auth,
        dst_dir_handle,
        "dst_filename",
        MoveOptionsBuilder::default().backup(false).build().unwrap(),
    );

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {} for file_system::File::{}/dst_filename",
        FilesystemAction::Write,
        dst_dir_path
    );

    assert_error_contains(result, &expected_error);

    Ok(())
}

/// Given: Two identical source files, one in /dev/shm (tmpfs) and one in a regular filesystem
/// When: One is moved using safe_move and one using std::process::Command("mv") across filesystems
/// Then: Both operations should have the same result
#[test]
#[cfg(target_os = "linux")]
fn test_cross_fs_safe_move_matches_process_command() -> Result<()> {
    let file_content = "test content for cross-filesystem move comparison";
    let src_filename = "safe_move_source.txt";
    let dest_filename = "safe_move_dest.txt";

    let src_dir = TempDir::new_in("/dev/shm/")?;
    let src_dir_path = src_dir.path().to_string_lossy().to_string();
    let src_file = src_dir.child(src_filename);
    src_file.write_str(file_content)?;

    let (dest_temp_dir, dest_temp_dir_path) = create_temp_dir_and_path()?;

    let src_dir_handle = DirConfigBuilder::default()
        .path(src_dir_path.clone())
        .build()
        .unwrap()
        .safe_open(
            &DEFAULT_TEST_CEDAR_AUTH,
            OpenDirOptionsBuilder::default().build().unwrap(),
        )?;

    let dest_dir_handle = open_test_dir_handle(&dest_temp_dir_path);

    let src_file_handle = src_dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        src_filename,
        OpenFileOptionsBuilder::default()
            .read(true)
            .write(true)
            .build()
            .unwrap(),
    )?;

    src_file_handle.safe_move(
        &DEFAULT_TEST_CEDAR_AUTH,
        dest_dir_handle,
        dest_filename,
        MoveOptionsBuilder::default().build().unwrap(),
    )?;

    verify_move_results(
        &src_dir,
        src_filename,
        &dest_temp_dir,
        dest_filename,
        file_content,
    )?;

    let std_src_dir = TempDir::new_in("/dev/shm/")?;
    let std_src_filename = "process_move_source.txt";
    let std_dest_filename = "process_move_dest.txt";
    let std_src_file = std_src_dir.child(std_src_filename);
    std_src_file.write_str(file_content)?;

    let (std_dest_temp_dir, _) = create_temp_dir_and_path()?;

    let src_path = std_src_dir
        .child(std_src_filename)
        .path()
        .to_string_lossy()
        .to_string();
    let dest_path = std_dest_temp_dir
        .child(std_dest_filename)
        .path()
        .to_string_lossy()
        .to_string();

    let status = std::process::Command::new("mv")
        .arg(&src_path)
        .arg(&dest_path)
        .status()?;

    assert!(status.success(), "mv command failed");

    verify_move_results(
        &std_src_dir,
        std_src_filename,
        &std_dest_temp_dir,
        std_dest_filename,
        file_content,
    )?;

    Ok(())
}

/// Given: A symlink opened with follow_symlinks=true and restrictive Cedar policies
/// When: safe_move is called on the file handle
/// Then: The symlink itself is moved, not the target (Unix mv behavior)
#[test]
#[cfg(target_os = "linux")]
fn test_safe_move_symlink_moves_symlink_not_target() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let (dest_dir, dest_dir_path) = create_temp_dir_and_path()?;

    let target_content = "target to preserve during move";
    let target_file = temp_dir.child("move_target.txt");
    target_file.write_str(target_content)?;
    let target_absolute_path = target_file.path().to_string_lossy().to_string();

    let symlink_file = temp_dir.child("move_link");
    symlink_file.symlink_to_file(&target_absolute_path)?;
    let symlink_absolute_path = symlink_file.path().to_string_lossy().to_string();
    let moved_symlink_path = dest_dir.path().join("moved_link");
    let moved_symlink_absolute_path = moved_symlink_path.to_string_lossy().to_string();

    let principal = get_test_rex_principal();

    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{symlink_absolute_path}"
        );
        permit(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{target_absolute_path}"
        );
        permit(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{symlink_absolute_path}"
        );
        permit(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{moved_symlink_absolute_path}"
        );
        permit(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{moved_symlink_absolute_path}"
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{target_absolute_path}"
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{target_absolute_path}"
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Open,
        FilesystemAction::Move,
        FilesystemAction::Create,
        FilesystemAction::Open,
        FilesystemAction::Move,
        FilesystemAction::Create
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let dest_dir_handle = open_test_dir_handle(&dest_dir_path);

    let file_handle = dir_handle.safe_open_file(
        &test_cedar_auth,
        "move_link",
        OpenFileOptionsBuilder::default()
            .read(true)
            .write(true)
            .follow_symlinks(true)
            .build()
            .unwrap(),
    )?;

    let _moved_handle = file_handle.safe_move(
        &test_cedar_auth,
        dest_dir_handle,
        "moved_link",
        MoveOptionsBuilder::default().build().unwrap(),
    )?;

    assert!(
        !symlink_file.exists(),
        "Expected original symlink to be moved"
    );
    assert!(
        target_file.exists(),
        "Expected target file to remain in original location"
    );
    assert!(
        moved_symlink_path.exists() && moved_symlink_path.is_symlink(),
        "Expected moved symlink to exist"
    );

    let moved_target = read_link(&moved_symlink_path)?;
    assert_eq!(moved_target.to_string_lossy(), target_absolute_path);

    let preserved_content = read_to_string(target_file.path())?;
    assert_eq!(preserved_content, target_content);

    Ok(())
}
