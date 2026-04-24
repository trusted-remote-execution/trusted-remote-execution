use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::io::create_temp_dir_and_path;

use rust_safe_io::options::MoveOptionsBuilder;

use crate::test_common::{TestMoveSetup, open_test_dir_handle};
use anyhow::Result;
use assert_fs::TempDir;
use assert_fs::fixture::SymlinkToFile;
use assert_fs::prelude::{FileWriteStr, PathChild, PathCreateDir};
use rstest::rstest;
use std::fs::{Permissions, read_link, read_to_string, set_permissions, symlink_metadata};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;

mod same_filesystem_tests {
    use crate::test_common::init_test_logger;

    use super::*;

    /// Given: A source directory and a destination parent directory
    /// When: The directory is moved using safe_move
    /// Then: The directory is successfully moved to the destination with its contents intact
    #[rstest]
    #[case::non_verbose(false)]
    #[case::verbose(true)]
    fn test_safe_move_dir_success(#[case] verbose: bool) -> Result<()> {
        if verbose {
            init_test_logger();
        }

        let src_dirname = "source_dir";
        let file_content = "test content for directory move operation";
        let file_contents = vec![("test_file.txt", file_content)];

        let setup = setup_move_test(src_dirname, file_contents, false)?;
        let src_parent_handle = setup.src_parent_handle;
        let src_dir_handle = setup.src_dir_handle;
        let src_parent_dir = setup.src_parent_dir;
        let dest_parent_dir = setup.dst_parent_dir;
        let dest_parent_handle = setup.dst_parent_handle;

        let dest_dirname = "moved_dir";

        let moved_dir_handle = src_parent_handle.safe_move(
            &DEFAULT_TEST_CEDAR_AUTH,
            src_dir_handle,
            dest_parent_handle,
            dest_dirname,
            MoveOptionsBuilder::default()
                .verbose(verbose)
                .build()
                .unwrap(),
        )?;

        assert!(
            !src_parent_dir.child(src_dirname).exists(),
            "Expected source directory to no longer exist after move"
        );

        let dest_dir_path = dest_parent_dir.path().join(dest_dirname);
        assert!(
            dest_dir_path.exists() && dest_dir_path.is_dir(),
            "Expected destination directory to exist after move"
        );

        let moved_file_path = dest_dir_path.join("test_file.txt");
        assert!(
            moved_file_path.exists(),
            "Expected file inside moved directory to exist"
        );

        let moved_file_content = read_to_string(moved_file_path)?;
        assert_eq!(
            moved_file_content, file_content,
            "Expected moved file content to match original content"
        );

        let entries = moved_dir_handle.safe_list_dir(&DEFAULT_TEST_CEDAR_AUTH)?;
        let has_test_file = entries.iter().any(|entry| entry.name() == "test_file.txt");
        assert!(
            has_test_file,
            "Expected moved directory to contain the test file"
        );

        Ok(())
    }

    /// Given: Two identical source directories
    /// When: One is moved using safe_move and one using std::process::Command("mv")
    /// Then: Both operations should have the same result
    #[test]
    fn test_safe_move_dir_matches_process_command() -> Result<()> {
        let src_dirname = "source_dir";
        let file_content = "test content for directory move operation";
        let file_contents = vec![("test_file.txt", file_content)];

        let setup = setup_move_test(src_dirname, file_contents, false)?;
        let src_parent_handle = setup.src_parent_handle;
        let src_dir_handle = setup.src_dir_handle;
        let src_parent_dir = setup.src_parent_dir;
        let dest_parent_dir = setup.dst_parent_dir;
        let dest_parent_handle = setup.dst_parent_handle;

        let dest_dirname = "moved_dir";

        src_parent_handle.safe_move(
            &DEFAULT_TEST_CEDAR_AUTH,
            src_dir_handle,
            dest_parent_handle,
            dest_dirname,
            MoveOptionsBuilder::default().build().unwrap(),
        )?;

        assert!(
            !src_parent_dir.child(src_dirname).exists(),
            "Expected source directory to no longer exist after safe_move"
        );

        let dest_dir_path = dest_parent_dir.path().join(dest_dirname);
        assert!(
            dest_dir_path.exists() && dest_dir_path.is_dir(),
            "Expected destination directory to exist after safe_move"
        );

        let moved_file_path = dest_dir_path.join("test_file.txt");
        assert!(
            moved_file_path.exists(),
            "Expected file inside moved directory to exist after safe_move"
        );

        let moved_file_content = read_to_string(moved_file_path)?;
        assert_eq!(
            moved_file_content, file_content,
            "Expected moved file content to match original content after safe_move"
        );

        let std_src_parent_dir = create_temp_dir_and_path()?.0;
        let std_dest_parent_dir = create_temp_dir_and_path()?.0;

        let std_src_dirname = "std_source_dir";
        let std_dest_dirname = "std_moved_dir";

        let std_src_dir = std_src_parent_dir.child(std_src_dirname);
        std_src_dir.create_dir_all()?;

        let std_test_file = std_src_dir.child("test_file.txt");
        std_test_file.write_str(file_content)?;

        let src_path = std_src_dir.path().to_string_lossy().to_string();
        let dest_path = std_dest_parent_dir
            .path()
            .join(std_dest_dirname)
            .to_string_lossy()
            .to_string();

        let status = std::process::Command::new("mv")
            .arg(&src_path)
            .arg(&dest_path)
            .status()?;

        assert!(status.success(), "mv command failed");

        assert!(
            !std_src_parent_dir.child(std_src_dirname).exists(),
            "Expected source directory to no longer exist after process mv"
        );

        let std_dest_dir_path = std_dest_parent_dir.path().join(std_dest_dirname);
        assert!(
            std_dest_dir_path.exists() && std_dest_dir_path.is_dir(),
            "Expected destination directory to exist after process mv"
        );

        let std_moved_file_path = std_dest_dir_path.join("test_file.txt");
        assert!(
            std_moved_file_path.exists(),
            "Expected file inside moved directory to exist after process mv"
        );

        let std_moved_file_content = read_to_string(std_moved_file_path)?;
        assert_eq!(
            std_moved_file_content, file_content,
            "Expected moved file content to match original content after process mv"
        );

        Ok(())
    }

    /// Given: A source directory and a destination parent directory but unauthorized user
    /// When: The directory is moved using safe_move
    /// Then: Access is denied for the specified action
    #[rstest]
    #[case::move_denied(FilesystemAction::Move)]
    #[case::create_denied(FilesystemAction::Create)]
    fn test_unauthorized_safe_move_dir(#[case] forbidden_action: FilesystemAction) -> Result<()> {
        let src_dirname = "source_dir";
        let file_contents = vec![("test_file.txt", "test content")];

        let setup = setup_move_test(src_dirname, file_contents, false)?;
        let src_parent_handle = setup.src_parent_handle;
        let src_dir_handle = setup.src_dir_handle;
        let src_parent_dir = setup.src_parent_dir;
        let dest_parent_handle = setup.dst_parent_handle;

        let dest_dirname = "moved_dir";
        let principal = get_test_rex_principal();

        let test_policy = if forbidden_action == FilesystemAction::Create {
            format!(
                "permit(principal == User::\"{}\", action == {}, resource); forbid(principal == User::\"{}\", action == {}, resource);",
                principal,
                FilesystemAction::Move,
                principal,
                forbidden_action
            )
        } else {
            format!(
                "forbid(principal == User::\"{}\", action == {}, resource);",
                principal, forbidden_action
            )
        };

        let test_cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy)
            .build()
            .unwrap()
            .create();

        let result = src_parent_handle.safe_move(
            &test_cedar_auth,
            src_dir_handle,
            dest_parent_handle,
            dest_dirname,
            MoveOptionsBuilder::default().build().unwrap(),
        );

        let expected_error = format!(
            "Permission denied: {principal} unauthorized to perform {}",
            forbidden_action
        );
        assert_error_contains(result, &expected_error);

        assert!(
            src_parent_dir.child(src_dirname).exists(),
            "Expected source directory to still exist after failed move"
        );

        Ok(())
    }

    /// Given: source dir and a dest_parent_dir where dest_parent_dir/dest_dir exists and is not empty
    /// When: The directory is moved using safe_move
    /// Then: source_dir is moved into dest_parent_dir/dest_dir so the result is dest_parent_dir/dest_dir/source_dir
    #[rstest]
    #[case::non_verbose(false)]
    #[case::verbose(true)]
    fn test_safe_move_dir_dest_not_empty(#[case] verbose: bool) -> Result<()> {
        init_test_logger();

        let src_dirname = "source_dir";
        let file_contents = vec![
            ("test_file.txt", "test content for directory move operation"),
            (
                "second_file.txt",
                "second file content for directory move operation",
            ),
        ];

        let setup = setup_move_test(src_dirname, file_contents, false)?;
        let src_parent_handle = setup.src_parent_handle;
        let src_dir_handle = setup.src_dir_handle;
        let src_parent_dir = setup.src_parent_dir;
        let dst_parent_dir = setup.dst_parent_dir;
        let dst_parent_dir_handle = setup.dst_parent_handle;

        let dest_dir = dst_parent_dir.child(src_dirname);
        dest_dir.create_dir_all()?;
        let dest_file = dest_dir.child("dest_file.txt");
        dest_file.write_str("doesn't matter")?;

        let mut move_options_builder = &mut MoveOptionsBuilder::default();
        if verbose {
            move_options_builder = move_options_builder.verbose(verbose);
        }

        let moved_dir_handle = src_parent_handle.safe_move(
            &DEFAULT_TEST_CEDAR_AUTH,
            src_dir_handle,
            dst_parent_dir_handle,
            src_dirname,
            move_options_builder.build().unwrap(),
        )?;

        assert!(
            !src_parent_dir.child(src_dirname).exists(),
            "Expected source directory to no longer exist after move"
        );

        let dest_dir_path = dst_parent_dir.path().join(src_dirname);

        assert!(
            dest_dir_path.exists() && dest_dir_path.is_dir(),
            "Expected destination directory to exist after move"
        );

        let entries = moved_dir_handle.safe_list_dir(&DEFAULT_TEST_CEDAR_AUTH)?;
        let has_test_file = entries.iter().any(|entry| entry.name() == "test_file.txt");
        let has_second_file = entries
            .iter()
            .any(|entry| entry.name() == "second_file.txt");
        assert!(
            has_test_file,
            "Expected moved directory to contain the test file"
        );
        assert!(
            has_second_file,
            "Expected moved directory to contain the second file"
        );

        Ok(())
    }

    /// Given: dest parent dir with nested directory configurations that cause errors
    /// When: safe_move is attempted
    /// Then: safe_move fails with appropriate error
    #[rstest]
    #[case::nested_dir_nonempty(false, "Directory not empty")]
    #[case::nested_dir_permission_denied(true, "Error moving dir")]
    fn test_safe_move_dir_nested_errors(
        #[case] restrict_permissions: bool,
        #[case] expected_error: &str,
    ) -> Result<()> {
        let src_dirname = "source_dir";
        let file_contents = vec![("test_file.txt", "test content for directory move operation")];

        let setup = setup_move_test(src_dirname, file_contents, false)?;
        let src_parent_handle = setup.src_parent_handle;
        let src_dir_handle = setup.src_dir_handle;
        let dst_parent_dir = setup.dst_parent_dir;
        let dst_parent_dir_handle = setup.dst_parent_handle;

        let dest_dirname = "dest_dir";
        let dest_dir = dst_parent_dir.child(dest_dirname);
        dest_dir.create_dir_all()?;

        let nested_dir = dest_dir.child("source_dir");
        nested_dir.create_dir_all()?;
        let second_file = nested_dir.child("second_file.txt");
        second_file.write_str("doesn't matter")?;

        if restrict_permissions {
            set_permissions(dest_dir.path(), Permissions::from_mode(0o000))?;
        }

        let result = src_parent_handle.safe_move(
            &DEFAULT_TEST_CEDAR_AUTH,
            src_dir_handle,
            dst_parent_dir_handle,
            dest_dirname,
            MoveOptionsBuilder::default().build().unwrap(),
        );

        assert_error_contains(result, expected_error);
        Ok(())
    }

    /// Given: Various error scenarios during directory move
    /// When: safe_move is attempted
    /// Then: Appropriate error is returned
    #[rstest]
    #[case::path_traversal("../moved_dir", false, "Path traversal detected")]
    #[case::dest_dir_closed("moved_dir", true, "Error moving dir")]
    fn test_safe_move_dir_error_scenarios(
        #[case] dest_dirname: &str,
        #[case] close_dest_dir: bool,
        #[case] expected_error: &str,
    ) -> Result<()> {
        let src_dirname = "source_dir";
        let setup = setup_move_test(src_dirname, vec![], false)?;
        let src_parent_handle = setup.src_parent_handle;
        let src_dir_handle = setup.src_dir_handle;
        let src_parent_dir = setup.src_parent_dir;
        let temp_dest_dir = setup.dst_parent_dir;
        let dest_parent_handle = setup.dst_parent_handle;

        if close_dest_dir {
            temp_dest_dir.close()?;
        }

        let result = src_parent_handle.safe_move(
            &DEFAULT_TEST_CEDAR_AUTH,
            src_dir_handle,
            dest_parent_handle,
            dest_dirname,
            MoveOptionsBuilder::default().build().unwrap(),
        );

        assert_error_contains(result, expected_error);

        if !close_dest_dir {
            assert!(
                src_parent_dir.child(src_dirname).exists(),
                "Expected source directory to still exist after failed move"
            );
        }

        Ok(())
    }
}

mod cross_filesystem_tests {
    use super::*;

    /// Given: A source directory and a destination parent directory in different file systems
    /// When: The directory is moved using safe_move
    /// Then: The directory is successfully moved to the destination with its contents intact
    #[rstest]
    #[case::non_verbose(false, false)]
    #[case::verbose(true, false)]
    #[case::with_socket(false, true)]
    fn test_move_dir_cross_fs_success(
        #[case] verbose: bool,
        #[case] include_socket: bool,
    ) -> Result<()> {
        let src_dirname = "source_dir";
        let dest_dirname = src_dirname;

        let mut file_contents = vec![
            ("test_file.txt", "test content for directory move operation"),
            (
                "second_file.txt",
                "second file content for directory move operation",
            ),
        ];

        if include_socket {
            file_contents.push(("nested/nested_file.txt", "nested content"));
        }

        let setup = setup_move_test(src_dirname, file_contents, true)?;
        let src_parent_handle = setup.src_parent_handle;
        let src_dir_handle = setup.src_dir_handle;
        let src_parent_dir = setup.src_parent_dir;
        let src_dir = setup.src_dir;
        let dst_parent_dir = setup.dst_parent_dir;
        let dst_parent_dir_handle = setup.dst_parent_handle;

        if include_socket {
            let socket_path = src_dir.path().join("nested/test_socket");
            UnixListener::bind(socket_path)?;
        }

        let moved_dir_handle = src_parent_handle.safe_move(
            &DEFAULT_TEST_CEDAR_AUTH,
            src_dir_handle,
            dst_parent_dir_handle,
            dest_dirname,
            MoveOptionsBuilder::default()
                .verbose(verbose)
                .build()
                .unwrap(),
        )?;

        assert!(
            !src_parent_dir.child(src_dirname).exists(),
            "Expected source directory to no longer exist after move"
        );

        let dest_dir_path = dst_parent_dir.path().join(dest_dirname);
        assert!(
            dest_dir_path.exists() && dest_dir_path.is_dir(),
            "Expected destination directory to exist after move"
        );

        let entries = moved_dir_handle.safe_list_dir(&DEFAULT_TEST_CEDAR_AUTH)?;
        let has_test_file = entries.iter().any(|entry| entry.name() == "test_file.txt");
        let has_second_file = entries
            .iter()
            .any(|entry| entry.name() == "second_file.txt");
        assert!(
            has_test_file,
            "Expected moved directory to contain the test file"
        );
        assert!(
            has_second_file,
            "Expected moved directory to contain the second file"
        );

        if include_socket {
            let has_nested_dir = entries
                .iter()
                .any(|entry| entry.name() == "nested" && entry.is_dir());
            assert!(
                has_nested_dir,
                "Expected moved directory to contain the nested directory"
            );

            let nested_file_path = dest_dir_path.join("nested/nested_file.txt");
            assert!(
                nested_file_path.exists(),
                "Expected nested file to exist after move"
            );
        }

        Ok(())
    }

    /// Given: A source directory and a destination parent directory in different filesystems with an existing non-empty directory at the destination path
    /// When: The directory is moved using safe_move
    /// Then: Directory is successfully moved
    #[test]
    fn test_safe_move_dir_cross_fs_empty_dest_dir() -> Result<()> {
        let src_dirname = "source_dir";
        let dest_dirname = "dest_dir";

        let file_contents = vec![("src_file.txt", "test content for directory move operation")];

        let setup = setup_move_test(src_dirname, file_contents, true)?;
        let src_parent_handle = setup.src_parent_handle;
        let src_dir_handle = setup.src_dir_handle;
        let src_parent_dir = setup.src_parent_dir;
        let dest_parent_dir = setup.dst_parent_dir;
        let dest_parent_handle = setup.dst_parent_handle;

        let dest_dir = dest_parent_dir.child(dest_dirname);
        dest_dir.create_dir_all()?;

        src_parent_handle.safe_move(
            &DEFAULT_TEST_CEDAR_AUTH,
            src_dir_handle,
            dest_parent_handle,
            dest_dirname,
            MoveOptionsBuilder::default().build().unwrap(),
        )?;

        let dest_dir_path = dest_parent_dir.path().join(dest_dirname);

        assert!(
            dest_dir_path.exists() && dest_dir_path.is_dir(),
            "Expected destination directory to exist after move"
        );

        assert!(
            !src_parent_dir.child(src_dirname).exists(),
            "Expected source directory to no longer exist after move"
        );

        let moved_file_path = dest_dir_path.join("src_file.txt");
        assert!(
            moved_file_path.exists(),
            "Expected file inside moved directory to exist"
        );

        Ok(())
    }

    /// Given: Two identical source directories in /dev/shm (tmpfs) and destination directories on a different filesystem
    /// When: One is moved using safe_move and one using std::process::Command("mv") across filesystems
    /// Then: Both operations should have the same result
    #[test]
    fn test_cross_fs_safe_move_dir_matches_process_command() -> Result<()> {
        let src_dirname = "safe_move_source_dir";
        let dest_dirname = "safe_move_dest_dir";
        let file_content = "test content for cross-filesystem directory move comparison";

        let file_contents = vec![("test_file.txt", file_content)];

        let setup = setup_move_test(src_dirname, file_contents, true)?;
        let src_parent_handle = setup.src_parent_handle;
        let src_dir_handle = setup.src_dir_handle;
        let src_parent_dir = setup.src_parent_dir;
        let dest_parent_dir = setup.dst_parent_dir;
        let dest_parent_handle = setup.dst_parent_handle;

        let moved_dir_handle = src_parent_handle.safe_move(
            &DEFAULT_TEST_CEDAR_AUTH,
            src_dir_handle,
            dest_parent_handle,
            dest_dirname,
            MoveOptionsBuilder::default().build().unwrap(),
        )?;

        assert!(
            !src_parent_dir.child(src_dirname).exists(),
            "Expected source directory to no longer exist after safe_move"
        );

        let dest_dir_path = dest_parent_dir.path().join(dest_dirname);
        assert!(
            dest_dir_path.exists() && dest_dir_path.is_dir(),
            "Expected destination directory to exist after safe_move"
        );

        let entries = moved_dir_handle.safe_list_dir(&DEFAULT_TEST_CEDAR_AUTH)?;
        let has_test_file = entries.iter().any(|entry| entry.name() == "test_file.txt");
        assert!(
            has_test_file,
            "Expected moved directory to contain the test file after safe_move"
        );

        let moved_file_path = dest_dir_path.join("test_file.txt");
        let moved_file_content = std::fs::read_to_string(moved_file_path)?;
        assert_eq!(
            moved_file_content, file_content,
            "Expected moved file content to match original content after safe_move"
        );

        let std_src_dirname = "process_move_source_dir";
        let std_dest_dirname = "process_move_dest_dir";

        let std_src_parent_dir = TempDir::new_in("/dev/shm/")?;
        let std_src_dir = std_src_parent_dir.child(std_src_dirname);
        std_src_dir.create_dir_all()?;

        let std_test_file = std_src_dir.child("test_file.txt");
        std_test_file.write_str(file_content)?;

        let (std_dest_parent_dir, _) = create_temp_dir_and_path()?;

        let src_path = std_src_dir.path().to_string_lossy().to_string();
        let dest_path = std_dest_parent_dir
            .path()
            .join(std_dest_dirname)
            .to_string_lossy()
            .to_string();

        let status = std::process::Command::new("mv")
            .arg(&src_path)
            .arg(&dest_path)
            .status()?;

        assert!(status.success(), "mv command failed");

        assert!(
            !std_src_parent_dir.child(std_src_dirname).exists(),
            "Expected source directory to no longer exist after process mv"
        );

        let std_dest_dir_path = std_dest_parent_dir.path().join(std_dest_dirname);
        assert!(
            std_dest_dir_path.exists() && std_dest_dir_path.is_dir(),
            "Expected destination directory to exist after process mv"
        );

        let std_moved_file_path = std_dest_dir_path.join("test_file.txt");
        assert!(
            std_moved_file_path.exists(),
            "Expected file inside moved directory to exist after process mv"
        );

        let std_moved_file_content = std::fs::read_to_string(std_moved_file_path)?;
        assert_eq!(
            std_moved_file_content, file_content,
            "Expected moved file content to match original content after process mv"
        );

        Ok(())
    }

    /// Given: A cedar policy that forbids specific actions during cross-filesystem move
    /// When: a cross filesystem safe_move is attempted
    /// Then: safe_move fails with a PermissionDenied error
    #[rstest]
    #[case::read_dest_denied(FilesystemAction::Read, true)]
    #[case::delete_src_denied(FilesystemAction::Delete, false)]
    fn test_safe_move_dir_cross_fs_unauthorized(
        #[case] forbidden_action: FilesystemAction,
        #[case] target_dest: bool,
    ) -> Result<()> {
        let principal = get_test_rex_principal();
        let src_dirname = "source_dir";
        let dest_dirname = if target_dest { "dest_dir" } else { src_dirname };

        let setup = setup_move_test(src_dirname, vec![], true)?;
        let src_parent_handle = setup.src_parent_handle;
        let src_dir_handle = setup.src_dir_handle;
        let src_dir = setup.src_dir;
        let dest_parent_dir = setup.dst_parent_dir;
        let dest_parent_handle = setup.dst_parent_handle;

        let dest_dir = dest_parent_dir.child(dest_dirname);
        dest_dir.create_dir_all()?;

        let target_path = if target_dest {
            dest_parent_dir
                .path()
                .join(dest_dirname)
                .display()
                .to_string()
        } else {
            src_dir.path().to_string_lossy().to_string()
        };

        let resource_type = if target_dest { "Dir" } else { "Dir" };
        let test_policy = format!(
            r#"permit(
                principal,
                action,
                resource
            );
            forbid(
                principal == User::"{principal}",
                action == {},
                resource == file_system::{resource_type}::"{target_path}"
            );"#,
            forbidden_action
        );

        let test_cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy)
            .build()
            .unwrap()
            .create();

        let result = src_parent_handle.safe_move(
            &test_cedar_auth,
            src_dir_handle,
            dest_parent_handle,
            dest_dirname,
            MoveOptionsBuilder::default().build().unwrap(),
        );

        let expected_error = format!(
            "Permission denied: {principal} unauthorized to perform {}",
            forbidden_action
        );
        assert_error_contains(result, &expected_error);

        Ok(())
    }

    /// Given: dest parent dir that has a file called dest_dir
    /// When: a cross filesystem safe_move is attempted
    /// Then: safe_move fails with a InvalidPath error as we cannot attempt to move source_dir inside dest_dir since dest_dir is a file not a dir
    #[test]
    fn test_safe_move_dir_cross_fs_invalid_path() -> Result<()> {
        let src_dirname = "source_dir";
        let dest_dirname = "dest_dir";

        let setup = setup_move_test(src_dirname, vec![], true)?;
        let src_parent_handle = setup.src_parent_handle;
        let src_dir_handle = setup.src_dir_handle;
        let dest_parent_dir = setup.dst_parent_dir;
        let dest_parent_handle = setup.dst_parent_handle;

        let file = dest_parent_dir.child(dest_dirname);
        let file_content = "doesn't matter";
        file.write_str(file_content)?;

        let result = src_parent_handle.safe_move(
            &DEFAULT_TEST_CEDAR_AUTH,
            src_dir_handle,
            dest_parent_handle,
            dest_dirname,
            MoveOptionsBuilder::default().build().unwrap(),
        );

        let expected_error = format!("Cannot create directory '{dest_dirname}': file exists",);

        assert_error_contains(result, &expected_error);

        Ok(())
    }

    /// Given: dest parent dir with various destination directory configurations
    /// When: a cross filesystem safe_move is attempted
    /// Then: safe_move successfully moves src_dir appropriately
    #[rstest]
    #[case::dest_dir_exists_empty("source_dir", "source_dir", false, false)]
    #[case::inside_dest_dir_with_content("source_dir", "dest_dir", true, false)]
    #[case::empty_nested_dir("source_dir", "dest_dir", false, true)]
    fn test_safe_move_dir_cross_fs_dest_scenarios(
        #[case] src_dirname: &str,
        #[case] dest_dirname: &str,
        #[case] create_extra_content: bool,
        #[case] create_empty_nested: bool,
    ) -> Result<()> {
        let file_contents = vec![
            ("test_file.txt", "test content for directory move operation"),
            (
                "second_file.txt",
                "second file content for directory move operation",
            ),
        ];

        let setup = setup_move_test(src_dirname, file_contents, true)?;
        let src_parent_handle = setup.src_parent_handle;
        let src_dir_handle = setup.src_dir_handle;
        let src_parent_dir = setup.src_parent_dir;
        let dst_parent_dir = setup.dst_parent_dir;
        let dst_parent_dir_handle = setup.dst_parent_handle;

        let dest_dir = dst_parent_dir.child(dest_dirname);
        dest_dir.create_dir_all()?;

        if create_extra_content {
            let nested_dir = dest_dir.child("asdf");
            nested_dir.create_dir_all()?;
        }

        if create_empty_nested {
            let nested_dir = dest_dir.child(src_dirname);
            nested_dir.create_dir_all()?;
        }

        let moved_dir_handle = src_parent_handle.safe_move(
            &DEFAULT_TEST_CEDAR_AUTH,
            src_dir_handle,
            dst_parent_dir_handle,
            dest_dirname,
            MoveOptionsBuilder::default().build().unwrap(),
        )?;

        assert!(
            !src_parent_dir.child(src_dirname).exists(),
            "Expected source directory to no longer exist after move"
        );

        let expected_dest_path = if create_extra_content || create_empty_nested {
            dest_dir.path().join(src_dirname)
        } else {
            dst_parent_dir.path().join(dest_dirname)
        };

        assert!(
            expected_dest_path.exists() && expected_dest_path.is_dir(),
            "Expected destination directory to exist after move"
        );

        let entries = moved_dir_handle.safe_list_dir(&DEFAULT_TEST_CEDAR_AUTH)?;
        let has_test_file = entries.iter().any(|entry| entry.name() == "test_file.txt");
        let has_second_file = entries
            .iter()
            .any(|entry| entry.name() == "second_file.txt");
        assert!(
            has_test_file,
            "Expected moved directory to contain the test file"
        );
        assert!(
            has_second_file,
            "Expected moved directory to contain the second file"
        );

        Ok(())
    }

    /// Given: dest parent dir with various problematic nested configurations
    /// When: a cross filesystem safe_move is attempted
    /// Then: safe_move fails with appropriate error
    #[rstest]
    #[case::nested_dir_nonempty(true, "Directory not empty")]
    #[case::nested_file_conflict(false, "Cannot create directory 'source_dir': file exists")]
    fn test_safe_move_dir_cross_fs_nested_conflicts(
        #[case] create_dir: bool,
        #[case] expected_error: &str,
    ) -> Result<()> {
        let src_dirname = "source_dir";
        let dest_dirname = "dest_dir";
        let file_contents = vec![("test_file.txt", "test content for directory move operation")];

        let setup = setup_move_test(src_dirname, file_contents, true)?;
        let src_parent_handle = setup.src_parent_handle;
        let src_dir_handle = setup.src_dir_handle;
        let dst_parent_dir = setup.dst_parent_dir;
        let dst_parent_dir_handle = setup.dst_parent_handle;

        let dest_dir = dst_parent_dir.child(dest_dirname);
        dest_dir.create_dir_all()?;

        if create_dir {
            let nested_dir = dest_dir.child(src_dirname);
            nested_dir.create_dir_all()?;
            let second_file = nested_dir.child("second_file.txt");
            second_file.write_str("doesn't matter")?;
        } else {
            let file = dest_dir.child(src_dirname);
            file.write_str("doesn't matter")?;
        }

        let result = src_parent_handle.safe_move(
            &DEFAULT_TEST_CEDAR_AUTH,
            src_dir_handle,
            dst_parent_dir_handle,
            dest_dirname,
            MoveOptionsBuilder::default().build().unwrap(),
        );

        assert_error_contains(result, expected_error);
        Ok(())
    }

    /// Given: A cedar policy that forbids Read in dest dir
    /// When: a cross filesystem safe_move is attempted
    /// Then: safe_move fails with a PermissionDenied error
    #[test]
    fn test_safe_move_dir_cross_fs_read_nested_dir_unauthorized() -> Result<()> {
        let principal = get_test_rex_principal();

        let src_dirname = "source_dir";
        let setup = setup_move_test(src_dirname, vec![], true)?;
        let src_parent_handle = setup.src_parent_handle;
        let src_dir_handle = setup.src_dir_handle;
        let _src_parent_dir = setup.src_parent_dir;
        let _src_dir = setup.src_dir;
        let dest_parent_dir = setup.dst_parent_dir;
        let dest_parent_handle = setup.dst_parent_handle;

        let dest_dirname = "dest_dir";
        let dest_dir = dest_parent_dir.child(dest_dirname);
        dest_dir.create_dir_all()?;

        let nested_dir = dest_dir.child(src_dirname);
        nested_dir.create_dir_all()?;
        let nested_dir_path = nested_dir.path().to_string_lossy().to_string();

        let test_policy = format!(
            r#"permit(
                principal,
                action,
                resource
            );
            forbid(
                principal == User::"{principal}",
                action == {},
                resource == file_system::Dir::"{nested_dir_path}"
            );"#,
            FilesystemAction::Read
        );

        let test_cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy)
            .build()
            .unwrap()
            .create();

        let result = src_parent_handle.safe_move(
            &test_cedar_auth,
            src_dir_handle,
            dest_parent_handle,
            dest_dirname,
            MoveOptionsBuilder::default().build().unwrap(),
        );

        let expected_error = format!(
            "Permission denied: {principal} unauthorized to perform {}",
            FilesystemAction::Read,
        );

        assert_error_contains(result, &expected_error);

        Ok(())
    }

    /// Given: A cedar policy that forbids Open for a file in src_dir
    /// When: a cross filesystem safe_move is attempted
    /// Then: safe_move fails with a PermissionDenied error
    #[test]
    fn test_safe_move_dir_cross_fs_open_file_unauthorized() -> Result<()> {
        let principal = get_test_rex_principal();
        let src_dirname = "source_dir";
        let file_contents = vec![("test_file.txt", "test content for directory move operation")];
        let setup = setup_move_test(src_dirname, file_contents, true)?;
        let src_parent_handle = setup.src_parent_handle;
        let src_dir_handle = setup.src_dir_handle;
        let _src_parent_dir = setup.src_parent_dir;
        let src_dir = setup.src_dir;
        let _dest_parent_dir = setup.dst_parent_dir;
        let dest_parent_handle = setup.dst_parent_handle;
        let dest_dirname = "dest_dir";
        let test_file_path = src_dir
            .path()
            .join("test_file.txt")
            .to_string_lossy()
            .to_string();

        let test_policy = format!(
            r#"permit(
                principal,
                action,
                resource
            );
            forbid(
                principal == User::"{principal}",
                action == {},
                resource == file_system::File::"{test_file_path}"
            );"#,
            FilesystemAction::Open
        );

        let test_cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy)
            .build()
            .unwrap()
            .create();

        let result = src_parent_handle.safe_move(
            &test_cedar_auth,
            src_dir_handle,
            dest_parent_handle,
            dest_dirname,
            MoveOptionsBuilder::default().build().unwrap(),
        );

        let expected_error = format!(
            "Permission denied: {principal} unauthorized to perform {}",
            FilesystemAction::Open,
        );

        assert_error_contains(result, &expected_error);

        Ok(())
    }

    /// Given: A cedar policy that forbids Write for a file in a nested directory inside src_dir
    /// When: a cross filesystem safe_move is attempted
    /// Then: safe_move fails with a PermissionDenied error
    #[test]
    fn test_safe_move_dir_cross_fs_write_nested_file_unauthorized() -> Result<()> {
        let principal = get_test_rex_principal();
        let src_dirname = "source_dir";
        let nested_dirname = "nested_dir";
        let file_path = format!("{}/test_file.txt", nested_dirname);
        let file_contents = vec![(
            file_path.as_str(),
            "test content for nested directory move operation",
        )];

        let setup = setup_move_test(src_dirname, file_contents, true)?;
        let src_parent_handle = setup.src_parent_handle;
        let src_dir_handle = setup.src_dir_handle;
        let _src_parent_dir = setup.src_parent_dir;
        let src_dir = setup.src_dir;
        let _dest_parent_dir = setup.dst_parent_dir;
        let dest_parent_handle = setup.dst_parent_handle;
        let dest_dirname = "dest_dir";

        let test_file_path = src_dir
            .path()
            .join(nested_dirname)
            .join("test_file.txt")
            .to_string_lossy()
            .to_string();

        let test_policy = format!(
            r#"permit(
                principal,
                action,
                resource
            );
            forbid(
                principal == User::"{principal}",
                action == {},
                resource == file_system::File::"{test_file_path}"
            );"#,
            FilesystemAction::Read
        );

        let test_cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy)
            .build()
            .unwrap()
            .create();

        let result = src_parent_handle.safe_move(
            &test_cedar_auth,
            src_dir_handle,
            dest_parent_handle,
            dest_dirname,
            MoveOptionsBuilder::default().build().unwrap(),
        );

        let expected_error = format!(
            "Permission denied: {principal} unauthorized to perform {}",
            FilesystemAction::Read,
        );

        assert_error_contains(result, &expected_error);

        Ok(())
    }

    /// Given: A source directory containing a symlink
    /// When: The directory is moved across filesystems using safe_move
    /// Then: The symlink is successfully recreated in the destination directory with preserved timestamps and ownership
    #[test]
    fn test_safe_move_dir_cross_fs_with_symlink() -> Result<()> {
        let src_dirname = "source_dir";
        let dest_dirname = "dest_dir";

        let setup = setup_move_test(src_dirname, vec![], true)?;
        let src_parent_handle = setup.src_parent_handle;
        let src_dir_handle = setup.src_dir_handle;
        let src_parent_dir = setup.src_parent_dir;
        let src_dir = setup.src_dir;
        let dest_parent_dir = setup.dst_parent_dir;
        let dest_parent_handle = setup.dst_parent_handle;

        let target_file = src_dir.child("target.txt");
        target_file.write_str("target content")?;

        let test_symlink = src_dir.child("test_symlink");
        test_symlink.symlink_to_file("target.txt")?;

        let src_symlink_path = src_dir.path().join("test_symlink");
        let src_metadata = symlink_metadata(&src_symlink_path)?;
        let src_uid = src_metadata.uid();
        let src_gid = src_metadata.gid();

        let moved_dir_handle = src_parent_handle.safe_move(
            &DEFAULT_TEST_CEDAR_AUTH,
            src_dir_handle,
            dest_parent_handle,
            dest_dirname,
            MoveOptionsBuilder::default().build().unwrap(),
        )?;

        assert!(
            !src_parent_dir.child(src_dirname).exists(),
            "Expected source directory to no longer exist after move"
        );

        let dest_dir_path = dest_parent_dir.path().join(dest_dirname);
        assert!(
            dest_dir_path.exists() && dest_dir_path.is_dir(),
            "Expected destination directory to exist after move"
        );

        let moved_symlink_path = dest_dir_path.join("test_symlink");
        assert!(
            moved_symlink_path.is_symlink(),
            "Expected symlink to exist in moved directory"
        );

        let symlink_target = read_link(&moved_symlink_path)?;
        assert_eq!(
            symlink_target,
            std::path::Path::new("target.txt"),
            "Expected symlink target to be preserved"
        );

        let dest_metadata = symlink_metadata(&moved_symlink_path)?;
        assert_eq!(
            dest_metadata.uid(),
            src_uid,
            "Expected symlink UID to be preserved after move"
        );
        assert_eq!(
            dest_metadata.gid(),
            src_gid,
            "Expected symlink GID to be preserved after move"
        );

        let entries = moved_dir_handle.safe_list_dir(&DEFAULT_TEST_CEDAR_AUTH)?;
        let has_symlink = entries
            .iter()
            .any(|entry| entry.name() == "test_symlink" && entry.is_symlink());
        let has_target = entries
            .iter()
            .any(|entry| entry.name() == "target.txt" && entry.is_file());

        assert!(
            has_symlink,
            "Expected moved directory to contain the symlink"
        );
        assert!(
            has_target,
            "Expected moved directory to contain the target file"
        );

        Ok(())
    }

    /// Given: A source directory containing a symlink and existing destination with Create permission denied
    /// When: The directory is moved across filesystems using safe_move
    /// Then: The move fails with a PermissionDenied error during symlink creation
    #[test]
    fn test_safe_move_dir_cross_fs_symlink_create_unauthorized() -> Result<()> {
        let principal = get_test_rex_principal();
        let src_dirname = "source_dir";
        let dest_dirname = src_dirname;

        let setup = setup_move_test(src_dirname, vec![], true)?;
        let src_parent_handle = setup.src_parent_handle;
        let src_dir_handle = setup.src_dir_handle;
        let src_dir = setup.src_dir;
        let dest_parent_dir = setup.dst_parent_dir;
        let dest_parent_handle = setup.dst_parent_handle;

        let target_file = src_dir.child("target.txt");
        target_file.write_str("target content")?;

        let test_symlink = src_dir.child("test_symlink");
        test_symlink.symlink_to_file("target.txt")?;

        let dest_dir = dest_parent_dir.child(dest_dirname);
        dest_dir.create_dir_all()?;
        let symlink_dest_path = dest_dir
            .path()
            .join("test_symlink")
            .to_string_lossy()
            .to_string();

        let test_policy = format!(
            r#"permit(
                principal,
                action,
                resource
            );
            forbid(
                principal == User::"{principal}",
                action == {},
                resource == file_system::File::"{symlink_dest_path}"
            );"#,
            FilesystemAction::Create
        );

        let test_cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy)
            .build()
            .unwrap()
            .create();

        let result = src_parent_handle.safe_move(
            &test_cedar_auth,
            src_dir_handle,
            dest_parent_handle,
            dest_dirname,
            MoveOptionsBuilder::default().build().unwrap(),
        );

        let expected_error = format!(
            "Permission denied: {principal} unauthorized to perform {}",
            FilesystemAction::Create
        );
        assert_error_contains(result, &expected_error);

        Ok(())
    }
}

/// Creates source and destination directories for move tests.
/// Returns a MoveTestSetup containing all necessary handles and paths.
/// file_contents can include nested paths like "nested/file.txt"
fn setup_move_test(
    src_dirname: &str,
    file_contents: Vec<(&str, &str)>,
    cross_filesystem: bool,
) -> Result<TestMoveSetup> {
    let (src_parent_handle, src_dir_handle, src_parent_dir, src_dir) = if cross_filesystem {
        let src_parent_dir = TempDir::new_in("/dev/shm/")?;
        let src_parent_path = src_parent_dir.path().to_string_lossy().to_string();
        let src_parent_handle = open_test_dir_handle(&src_parent_path);

        let src_dir = src_parent_dir.child(src_dirname);
        src_dir.create_dir_all()?;
        let src_dir_handle = open_test_dir_handle(&src_dir.path().to_string_lossy().to_string());

        (src_parent_handle, src_dir_handle, src_parent_dir, src_dir)
    } else {
        let (src_parent_dir, src_parent_path) = create_temp_dir_and_path()?;
        let src_parent_handle = open_test_dir_handle(&src_parent_path);
        let src_dir = src_parent_dir.child(src_dirname);
        src_dir.create_dir_all()?;
        let src_dir_handle = open_test_dir_handle(&src_dir.path().to_string_lossy().to_string());
        (src_parent_handle, src_dir_handle, src_parent_dir, src_dir)
    };

    for (filepath, content) in file_contents {
        let file = src_dir.child(filepath);
        if let Some(parent) = file.path().parent() {
            std::fs::create_dir_all(parent)?;
        }
        file.write_str(content)?;
    }

    let (dst_parent_dir, dst_parent_dir_path) = create_temp_dir_and_path()?;
    let dst_parent_handle = open_test_dir_handle(&dst_parent_dir_path);

    Ok(TestMoveSetup {
        src_parent_handle,
        src_dir_handle,
        src_parent_dir,
        src_dir,
        dst_parent_dir,
        dst_parent_handle,
    })
}
