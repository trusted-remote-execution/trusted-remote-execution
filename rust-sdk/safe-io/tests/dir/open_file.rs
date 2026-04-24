use rex_cedar_auth::fs::actions::FilesystemAction;
use std::path::Path;

use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::io::{create_and_write_to_test_file, create_temp_dir_and_path};
use rex_test_utils::random::get_rand_string;
use rust_safe_io::DirConfigBuilder;
use rust_safe_io::error_constants::{
    FILE_DNE_ERR, FILE_PATH_INVALID, NOT_A_FILE, PATH_TRAVERSAL, TOO_MANY_SYMLINKS,
};
use rust_safe_io::options::{OpenDirOptionsBuilder, OpenFileOptionsBuilder};

use anyhow::Result;
use assert_fs::fixture::{SymlinkToDir, SymlinkToFile};
use assert_fs::prelude::{FileTouch, FileWriteStr, PathChild, PathCreateDir};
use rstest::rstest;
use std::fs::metadata;
use std::os::unix::fs::MetadataExt;
use std::process::Command;

use crate::test_common::{PERMISSION_EXTRACT_BITMASK, open_test_dir_handle};

const RW_OWNER_R_GROUP_R_OTHERS_BITMASK: u32 = 0o644;

/// Given: A file name that contains bad paths
/// When: The file is opened
/// Then: The file is not opened and an error is thrown
#[rstest]
#[case::directory_instead_of_file("real_dir", NOT_A_FILE)]
#[case::filename_with_dot_syntax("./test.txt", FILE_PATH_INVALID)]
#[case::path_traversal("../real_dir/test.txt", PATH_TRAVERSAL)]
#[case::read_symlink_file("link_file", TOO_MANY_SYMLINKS)]
#[case::file_that_does_not_exist("file_that_dne", FILE_DNE_ERR)]
#[case::file_with_no_name("", FILE_DNE_ERR)]
fn test_open_file_errors(#[case] path: &str, #[case] expected_err: &str) -> Result<()> {
    let (parent_dir, parent_dir_path) = create_temp_dir_and_path()?;

    let child_dir = parent_dir.child("real_dir");
    child_dir.create_dir_all()?;
    let real_file = child_dir.child("test.txt");

    // create a symlink from link_file -> test.txt
    parent_dir
        .child("link_file")
        .symlink_to_file(real_file.path())
        .unwrap();

    let dir_handle = open_test_dir_handle(&parent_dir_path);
    let result = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        path,
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    );

    assert_error_contains(result, expected_err);

    Ok(())
}

/// Given: A file but an unauthorized user
/// When: The file is opened with safe I/O
/// Then: Access is denied
#[test]
fn test_unauthorized_open_file() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let test_file = "test_file.txt";
    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"forbid(
            principal == User::"{principal}",
            action == {},
            resource
        );"#,
        FilesystemAction::Open
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let _file_path = create_and_write_to_test_file(&temp_dir, test_file)?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let result = dir_handle.safe_open_file(
        &test_cedar_auth,
        test_file,
        OpenFileOptionsBuilder::default().build().unwrap(),
    );

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Open
    );
    assert_error_contains(result, &expected_error);

    Ok(())
}

mod open_create_file_tests {
    use super::*;

    /// Given: A directory to create the new file and file name
    /// When: Create file is called with directory handle and file name
    /// Then: File is created at the expected path and file handle is returned which can be used for writing
    #[test]
    fn test_safe_create_and_write_to_file() -> Result<(), anyhow::Error> {
        let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
        let dir_handle = open_test_dir_handle(&temp_dir_path);

        let file_name = "test.txt";
        let file_handle = dir_handle.safe_open_file(
            &DEFAULT_TEST_CEDAR_AUTH,
            &file_name,
            OpenFileOptionsBuilder::default()
                .create(true)
                .read(true)
                .write(true)
                .build()
                .unwrap(),
        )?;
        let file_path = temp_dir.path().join(&file_name);
        assert!(
            Path::new(&file_path).exists(),
            "Expected file to be created at path: {:?}",
            file_path
        );
        let content = get_rand_string();

        let file_handle = file_handle.safe_write(&DEFAULT_TEST_CEDAR_AUTH, &content)?;

        let actual_content = file_handle.safe_read(&DEFAULT_TEST_CEDAR_AUTH)?;
        assert_eq!(
            actual_content, content,
            "Expected file contents to match written content"
        );

        Ok(())
    }

    /// Given: A directory with an existing file
    /// When: Open the existing file with create options
    /// Then: The existing file is opened and its contents are not changed (it does not create a new file)
    #[test]
    fn test_safe_create_file_that_already_exists() -> Result<(), anyhow::Error> {
        let original_contents = get_rand_string();
        let (temp, temp_dir_path) = create_temp_dir_and_path()?;
        let existing_file_name = "existing_file";
        let _ = temp.child(existing_file_name).touch().unwrap();
        let dir_handle = open_test_dir_handle(&temp_dir_path);

        // Bound this scope so the original file is closed. This will let us accurately verify that the newly
        // opened file is indeed the same as the original one.
        {
            let original_file_handle = dir_handle.safe_open_file(
                &DEFAULT_TEST_CEDAR_AUTH,
                &existing_file_name,
                OpenFileOptionsBuilder::default()
                    .write(true)
                    .build()
                    .unwrap(),
            )?;

            original_file_handle.safe_write(&DEFAULT_TEST_CEDAR_AUTH, &original_contents)?;
        }

        // Normally we would never re-open the file because that has more potential for TOCTOU issues than just using the same file descriptor.
        // But we need to here for the test to validate the right thing.
        let new_file_handle = dir_handle.safe_open_file(
            &DEFAULT_TEST_CEDAR_AUTH,
            &existing_file_name,
            OpenFileOptionsBuilder::default()
                .create(true)
                .read(true)
                .build()
                .unwrap(),
        )?;

        let new_contents = new_file_handle.safe_read(&DEFAULT_TEST_CEDAR_AUTH)?;
        assert_eq!(
            original_contents, new_contents,
            "Expected reopened file contents to match original contents"
        );

        Ok(())
    }

    /// Since we treat create and write as separate operations for Cedar auth purposes,
    /// validate that create works without the write permission. See documentation for
    /// [`rust_safe_io::options::OpenFileOptions`] for more context on how this can break.
    ///
    /// Given: A directory to create the new file and file name
    /// When: Create file is opened with create flag but not write flag
    /// Then: Create is successful.
    #[test]
    fn test_safe_create_file_without_write_option() -> Result<()> {
        let (_, temp_dir_path) = create_temp_dir_and_path()?;
        let dir_handle = DirConfigBuilder::default()
            .path(temp_dir_path.clone())
            .build()?
            .safe_open(
                &DEFAULT_TEST_CEDAR_AUTH,
                OpenDirOptionsBuilder::default()
                    .create(true)
                    .build()
                    .unwrap(),
            )
            .unwrap();
        let file_name = "test.txt";

        let file_handle = dir_handle.safe_open_file(
            &DEFAULT_TEST_CEDAR_AUTH,
            &file_name,
            OpenFileOptionsBuilder::default()
                .read(true)
                .write(false)
                .create(true)
                .build()?,
        )?;
        let content = get_rand_string();
        file_handle.safe_write(&DEFAULT_TEST_CEDAR_AUTH, &content)?;

        let file_handle = dir_handle.safe_open_file(
            &DEFAULT_TEST_CEDAR_AUTH,
            &file_name,
            OpenFileOptionsBuilder::default().read(true).build()?,
        )?;

        let actual_content = file_handle.safe_read(&DEFAULT_TEST_CEDAR_AUTH)?;
        assert_eq!(
            actual_content, content,
            "Expected file contents to match written content"
        );

        Ok(())
    }

    /// Given: A user with Open permission but without Create permission
    /// When: A file is opened with create=true using safe I/O
    /// Then: Access is denied for the Create action
    #[test]
    fn test_unauthorized_create_file() -> Result<()> {
        let (_temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
        let test_file = "test_file.txt";
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
            FilesystemAction::Open,
            FilesystemAction::Create
        );

        let test_cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy)
            .build()
            .unwrap()
            .create();

        let dir_handle = open_test_dir_handle(&temp_dir_path);

        let result = dir_handle.safe_open_file(
            &test_cedar_auth,
            test_file,
            OpenFileOptionsBuilder::default()
                .create(true)
                .build()
                .unwrap(),
        );
        let expected_error = format!(
            "Permission denied: {principal} unauthorized to perform {}",
            FilesystemAction::Create
        );
        assert_error_contains(result, &expected_error);

        Ok(())
    }

    /// Given: A directory and a file name
    /// When: A file is created with or without custom permissions
    /// Then: The file is created with the specified or default permissions
    #[rstest]
    #[case::default_permissions(None, RW_OWNER_R_GROUP_R_OTHERS_BITMASK)]
    #[case::owner_read_write(Some(0o600), 0o600)]
    #[case::owner_read_only(Some(0o400), 0o400)]
    #[case::ignore_setuid_bits(Some(0o4755), 0o755)]
    #[cfg(unix)]
    fn test_create_file_with_permissions_option(
        #[case] permissions: Option<u32>,
        #[case] expected_mode: u32,
    ) -> Result<()> {
        let (_temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
        let dir_handle = open_test_dir_handle(&temp_dir_path);

        let file_name = "test_permissions.txt";

        let mut options_builder = OpenFileOptionsBuilder::default();
        options_builder.create(true);

        if let Some(perms) = permissions {
            options_builder.permissions(perms as i64);
        }

        let file_handle = dir_handle.safe_open_file(
            &DEFAULT_TEST_CEDAR_AUTH,
            file_name,
            options_builder.build().unwrap(),
        )?;

        file_handle.safe_write(&DEFAULT_TEST_CEDAR_AUTH, "test content")?;

        let full_path = Path::new(&temp_dir_path).join(file_name);
        let actual_mode = metadata(full_path)?.mode() & PERMISSION_EXTRACT_BITMASK;

        // Default permissions can vary based on the system umask. Get the umask from the shell
        // and compute the expected default file permissions (0o666 & !umask).
        let effective_expected = if permissions.is_none() {
            let output = Command::new("sh")
                .args(["-c", "umask"])
                .output()
                .expect("Failed to run umask command");
            let umask_str = String::from_utf8(output.stdout).unwrap();
            let umask = u32::from_str_radix(umask_str.trim().trim_start_matches('0'), 8).unwrap();
            0o666 & !umask
        } else {
            expected_mode
        };

        assert_eq!(
            actual_mode, effective_expected,
            "File should have permissions {:o} but has {:o}",
            effective_expected, actual_mode
        );

        Ok(())
    }
}

mod open_file_symlink_tests {
    use super::*;

    /// Given: A file that is a symlink pointing to a symlink pointing to a text file, using relative paths
    /// When: The file is opened with follow_symlinks=true
    /// Then: We follow the chain of symlinks and return a file handle to the target file
    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_safe_open_symlink_to_file() -> Result<()> {
        let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
        let subdir = temp_dir.child("subdir");
        subdir.create_dir_all().unwrap();
        let subdir2 = subdir.child("subdir2");
        subdir2.create_dir_all().unwrap();

        let target_file = subdir2.child("target_file.txt");
        let target_content = "target file content";
        target_file.write_str(target_content)?;

        let symlink_file = temp_dir.child("valid_link");
        let nested_symlink = subdir.child("nested_symlink");
        symlink_file.symlink_to_file("subdir/nested_symlink")?;
        nested_symlink.symlink_to_file("subdir2/target_file.txt")?;

        let dir_config = DirConfigBuilder::default()
            .path(temp_dir_path.clone())
            .build()?;
        let dir_handle = dir_config.safe_open(
            &DEFAULT_TEST_CEDAR_AUTH,
            OpenDirOptionsBuilder::default().build().unwrap(),
        )?;

        let file_handle = dir_handle.safe_open_file(
            &DEFAULT_TEST_CEDAR_AUTH,
            "valid_link",
            OpenFileOptionsBuilder::default()
                .read(true)
                .follow_symlinks(true)
                .build()
                .unwrap(),
        )?;

        let content = file_handle.safe_read(&DEFAULT_TEST_CEDAR_AUTH)?;
        assert_eq!(content, target_content);
        Ok(())
    }

    /// Given: A file that is a symlink pointing to a directory
    /// When: The file is opened with follow_symlinks=true
    /// Then: An error is returned since the symlink should point to a file
    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_safe_open_file_symlink_to_directory() -> Result<()> {
        use rust_safe_io::error_constants::NOT_A_FILE;

        let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
        let target_dir = temp_dir.child("target_dir");
        target_dir.create_dir_all().unwrap();

        let symlink_file = temp_dir.child("valid_link");
        symlink_file.symlink_to_dir(target_dir.path())?;

        let dir_config = DirConfigBuilder::default()
            .path(temp_dir_path.clone())
            .build()?;
        let dir_handle = dir_config.safe_open(
            &DEFAULT_TEST_CEDAR_AUTH,
            OpenDirOptionsBuilder::default().build().unwrap(),
        )?;

        let result = dir_handle.safe_open_file(
            &DEFAULT_TEST_CEDAR_AUTH,
            "valid_link",
            OpenFileOptionsBuilder::default()
                .read(true)
                .follow_symlinks(true)
                .build()
                .unwrap(),
        );

        assert_error_contains(result, NOT_A_FILE);
        Ok(())
    }

    /// Given: A symlink that points to a target the user is not authorized to access
    /// When: The symlink is opened with follow_symlinks = true
    /// Then: An error is thrown since the symlink target points outside of allowed directory TEMP
    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_unauthorized_safe_open_file_symlink_target() -> Result<()> {
        let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
        let subdir = temp_dir.child("subdir");
        subdir.create_dir_all().unwrap();
        let subdir2 = subdir.child("subdir2");
        subdir2.create_dir_all().unwrap();

        let target_file = subdir2.child("target_file.txt");
        let target_content = "target file content";
        target_file.write_str(target_content)?;

        let symlink_file = temp_dir.child("valid_link");
        symlink_file.symlink_to_file("subdir/subdir2/target_file.txt")?;

        let principal = get_test_rex_principal();
        let test_policy = format!(
            r#"permit(
            principal == User::"{principal}",
            action == {},
            resource is file_system::File in file_system::Dir::"{temp_dir_path}"
            );
            forbid(
                principal == User::"{principal}",
                action == {},
                resource is file_system::File in file_system::Dir::"{temp_dir_path}/subdir/subdir2"
            );"#,
            FilesystemAction::Open,
            FilesystemAction::Open
        );

        let test_cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy)
            .build()
            .unwrap()
            .create();

        let dir_config = DirConfigBuilder::default()
            .path(temp_dir_path.clone())
            .build()?;
        let dir_handle = dir_config.safe_open(
            &DEFAULT_TEST_CEDAR_AUTH,
            OpenDirOptionsBuilder::default().build().unwrap(),
        )?;

        let result = dir_handle.safe_open_file(
            &test_cedar_auth,
            "valid_link",
            OpenFileOptionsBuilder::default()
                .read(true)
                .follow_symlinks(true)
                .build()
                .unwrap(),
        );

        let expected_error = format!(
            "Permission denied: {principal} unauthorized to perform {} for file_system::File::{temp_dir_path}/subdir/subdir2/target_file.txt",
            FilesystemAction::Open
        );
        assert_error_contains(result, &expected_error);

        Ok(())
    }

    /// Given: A regular file (not a symlink)
    /// When: The file is opened with follow_symlinks=true
    /// Then: The file is opened successfully as a regular file
    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_safe_open_regular_file_with_follow_symlinks() -> Result<()> {
        let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

        let regular_file = temp_dir.child("regular_file.txt");
        let file_content = "regular file content";
        regular_file.write_str(file_content)?;

        let dir_config = DirConfigBuilder::default()
            .path(temp_dir_path.clone())
            .build()?;
        let dir_handle = dir_config.safe_open(
            &DEFAULT_TEST_CEDAR_AUTH,
            OpenDirOptionsBuilder::default().build().unwrap(),
        )?;

        let file_handle = dir_handle.safe_open_file(
            &DEFAULT_TEST_CEDAR_AUTH,
            "regular_file.txt",
            OpenFileOptionsBuilder::default()
                .read(true)
                .follow_symlinks(true)
                .build()
                .unwrap(),
        )?;

        let content = file_handle.safe_read(&DEFAULT_TEST_CEDAR_AUTH)?;
        assert_eq!(content, file_content);

        Ok(())
    }

    /// Given: An absolute symlink pointing to a file in a different directory
    /// When: The symlink is opened with follow_symlinks=true
    /// Then: The target file content is read successfully
    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_safe_open_file_follow_absolute_symlink_success() -> Result<()> {
        let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
        let (target_dir, _target_dir_path) = create_temp_dir_and_path()?;

        let target_content = "absolute symlink target content";
        let target_file = target_dir.child("abs_target.txt");
        target_file.write_str(target_content)?;
        let target_absolute_path = target_file.path().to_string_lossy().to_string();

        let symlink_file = temp_dir.child("abs_link");
        symlink_file.symlink_to_file(&target_absolute_path)?;

        let dir_handle = open_test_dir_handle(&temp_dir_path);

        let file_handle = dir_handle.safe_open_file(
            &DEFAULT_TEST_CEDAR_AUTH,
            "abs_link",
            OpenFileOptionsBuilder::default()
                .read(true)
                .follow_symlinks(true)
                .build()
                .unwrap(),
        )?;

        let content = file_handle.safe_read(&DEFAULT_TEST_CEDAR_AUTH)?;
        assert_eq!(content, target_content);
        assert_eq!(file_handle.path(), "abs_link");

        Ok(())
    }

    /// Given: A symlink chain (symlink -> symlink -> file)
    /// When: The first symlink is opened with follow_symlinks=true
    /// Then: The final target file is accessed successfully
    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_safe_open_file_follow_symlink_chain() -> Result<()> {
        let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

        let final_content = "end of symlink chain";
        let final_target = temp_dir.child("final_target.txt");
        final_target.write_str(final_content)?;

        // Create symlink chain: link1 -> link2 -> final_target.txt
        let link2 = temp_dir.child("link2");
        link2.symlink_to_file("final_target.txt")?;

        let link1 = temp_dir.child("link1");
        link1.symlink_to_file("link2")?;

        let dir_handle = open_test_dir_handle(&temp_dir_path);

        let file_handle = dir_handle.safe_open_file(
            &DEFAULT_TEST_CEDAR_AUTH,
            "link1",
            OpenFileOptionsBuilder::default()
                .read(true)
                .follow_symlinks(true)
                .build()
                .unwrap(),
        )?;

        let content = file_handle.safe_read(&DEFAULT_TEST_CEDAR_AUTH)?;
        assert_eq!(content, final_content);

        Ok(())
    }

    /// Given: A symlink pointing to a non-existent file
    /// When: The symlink is opened with follow_symlinks=true
    /// Then: A file not found error is returned
    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_safe_open_file_follow_broken_symlink() -> Result<()> {
        let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

        let broken_link = temp_dir.child("broken_link");
        broken_link.symlink_to_file("nonexistent.txt")?;

        let dir_handle = open_test_dir_handle(&temp_dir_path);

        let result = dir_handle.safe_open_file(
            &DEFAULT_TEST_CEDAR_AUTH,
            "broken_link",
            OpenFileOptionsBuilder::default()
                .read(true)
                .follow_symlinks(true)
                .build()
                .unwrap(),
        );

        assert_error_contains(result, FILE_DNE_ERR);

        Ok(())
    }

    /// Given: A circular symlink (link1 -> link2 -> link1)
    /// When: The symlink is opened with follow_symlinks=true
    /// Then: A "too many symlinks" error is returned
    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_safe_open_file_follow_circular_symlink() -> Result<()> {
        let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

        let link1 = temp_dir.child("circular1");
        let link2 = temp_dir.child("circular2");

        link1.symlink_to_file("circular2")?;
        link2.symlink_to_file("circular1")?;

        let dir_handle = open_test_dir_handle(&temp_dir_path);

        let result = dir_handle.safe_open_file(
            &DEFAULT_TEST_CEDAR_AUTH,
            "circular1",
            OpenFileOptionsBuilder::default()
                .read(true)
                .follow_symlinks(true)
                .build()
                .unwrap(),
        );

        assert_error_contains(result, TOO_MANY_SYMLINKS);

        Ok(())
    }
}

mod open_file_wildcard_tests {
    use super::*;

    /// Given: A Cedar policy allowing files matching /proc/*/status pattern
    /// When: Opening /proc/<pid>/status file
    /// Then: Access is granted because the file path matches the wildcard pattern
    #[test]
    #[cfg(target_os = "linux")]
    fn test_open_file_with_wildcard_path_policy_proc_allow() -> Result<()> {
        let pid = std::process::id();
        let proc_pid_path = format!("/proc/{}", pid);

        let principal = get_test_rex_principal();
        let test_policy = format!(
            r#"permit(
                principal == User::"{principal}",
                action == {},
                resource is file_system::File
            ) when {{
                resource.path like "/proc/*/status"
            }};"#,
            FilesystemAction::Open
        );

        let test_cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy)
            .build()
            .unwrap()
            .create();

        let proc_dir_handle = open_test_dir_handle(&proc_pid_path);

        let result = proc_dir_handle.safe_open_file(
            &test_cedar_auth,
            "status",
            OpenFileOptionsBuilder::default()
                .read(true)
                .build()
                .unwrap(),
        );
        assert!(result.is_ok(), "err: {:?}", result.unwrap_err());

        Ok(())
    }

    /// Given: A Cedar policy allowing only files matching /proc/*/status pattern
    /// When: Opening /proc/<pid>/mem file
    /// Then: Access is denied because the file path does not match the wildcard pattern
    #[test]
    #[cfg(target_os = "linux")]
    fn test_open_file_with_wildcard_path_policy_proc_deny() -> Result<()> {
        let pid = std::process::id();
        let proc_pid_path = format!("/proc/{}", pid);

        let principal = get_test_rex_principal();
        let test_policy = format!(
            r#"permit(
                principal == User::"{principal}",
                action == {},
                resource is file_system::File
            ) when {{
                resource.path like "/proc/*/status"
            }};"#,
            FilesystemAction::Open
        );

        let test_cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy)
            .build()
            .unwrap()
            .create();

        let proc_dir_handle = open_test_dir_handle(&proc_pid_path);

        let result = proc_dir_handle.safe_open_file(
            &test_cedar_auth,
            "mem",
            OpenFileOptionsBuilder::default()
                .read(true)
                .build()
                .unwrap(),
        );

        let expected_error = format!(
            "Permission denied: {principal} unauthorized to perform {} for file_system::File::{}/mem",
            FilesystemAction::Open,
            proc_pid_path
        );
        assert_error_contains(result, &expected_error);

        Ok(())
    }

    /// Given: A Cedar policy allowing files matching *.txt pattern
    /// When: Opening a .txt file
    /// Then: Access is granted because the file extension matches the wildcard pattern
    #[test]
    fn test_open_file_with_wildcard_path_policy_allow() -> Result<()> {
        let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

        create_and_write_to_test_file(&temp_dir, "allowed.txt")?;

        let principal = get_test_rex_principal();
        let test_policy = format!(
            r#"permit(
                principal == User::"{principal}",
                action == {},
                resource is file_system::File
            ) when {{
                resource.path like "{}/*.txt"
            }};"#,
            FilesystemAction::Open,
            temp_dir_path
        );

        let test_cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy)
            .build()
            .unwrap()
            .create();

        let dir_handle = open_test_dir_handle(&temp_dir_path);

        let result = dir_handle.safe_open_file(
            &test_cedar_auth,
            "allowed.txt",
            OpenFileOptionsBuilder::default()
                .read(true)
                .build()
                .unwrap(),
        );
        assert!(result.is_ok(), "err: {:?}", result.unwrap_err());

        Ok(())
    }

    /// Given: A Cedar policy allowing only files matching *.txt pattern
    /// When: Opening a .log file
    /// Then: Access is denied because the file extension does not match the wildcard pattern
    #[test]
    fn test_open_file_with_wildcard_path_policy_deny() -> Result<()> {
        let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

        create_and_write_to_test_file(&temp_dir, "denied.log")?;

        let principal = get_test_rex_principal();
        let test_policy = format!(
            r#"permit(
                principal == User::"{principal}",
                action == {},
                resource is file_system::File
            ) when {{
                resource.path like "{}/*.txt"
            }};"#,
            FilesystemAction::Open,
            temp_dir_path
        );

        let test_cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy)
            .build()
            .unwrap()
            .create();

        let dir_handle = open_test_dir_handle(&temp_dir_path);

        let result = dir_handle.safe_open_file(
            &test_cedar_auth,
            "denied.log",
            OpenFileOptionsBuilder::default()
                .read(true)
                .build()
                .unwrap(),
        );

        let expected_error = format!(
            "Permission denied: {principal} unauthorized to perform {} for file_system::File::{}/denied.log",
            FilesystemAction::Open,
            temp_dir_path
        );
        assert_error_contains(result, &expected_error);

        Ok(())
    }
}
