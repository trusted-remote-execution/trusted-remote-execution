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
use std::path::PathBuf;

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

        // include a couple of levels of nested subdirectories and additional files
        let src_sub_dir = setup.src_dir.child("sub_dir");
        src_sub_dir.create_dir_all()?;
        let src_sub_sub_dir = src_sub_dir.child("sub_sub_dir");
        src_sub_sub_dir.create_dir_all()?;
        src_sub_dir
            .child("sub_dir_file.txt")
            .write_str("sub dir file content")?;
        src_sub_sub_dir
            .child("sub_sub_dir_file.txt")
            .write_str("sub sub dir file content")?;

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

        let dest_dir_path = dest_parent_dir.path().join(dest_dirname);
        let dest_dir_path_str = dest_dir_path.to_string_lossy().into_owned();

        assert_eq!(
            moved_dir_handle.full_path(),
            dest_dir_path_str,
            "Expected returned dir_handle to have the correct destination"
        );

        assert!(
            !src_parent_dir.child(src_dirname).exists(),
            "Expected source directory to no longer exist after move"
        );

        let expected_files: Vec<String> = vec![
            dest_dir_path_str.clone(),
            format!("{dest_dir_path_str}/test_file.txt"),
            format!("{dest_dir_path_str}/sub_dir"),
            format!("{dest_dir_path_str}/sub_dir/sub_dir_file.txt"),
            format!("{dest_dir_path_str}/sub_dir/sub_sub_dir"),
            format!("{dest_dir_path_str}/sub_dir/sub_sub_dir/sub_sub_dir_file.txt"),
        ];

        validate_dir_entries(&dest_dir_path, &expected_files)?;

        let files_to_validate = vec![
            (format!("{dest_dir_path_str}/test_file.txt"), file_content),
            (
                format!("{dest_dir_path_str}/sub_dir/sub_dir_file.txt"),
                "sub dir file content",
            ),
            (
                format!("{dest_dir_path_str}/sub_dir/sub_sub_dir/sub_sub_dir_file.txt"),
                "sub sub dir file content",
            ),
        ];
        for (file_path, expected_content) in files_to_validate.iter() {
            validate_file_contents(file_path, expected_content)?;
        }

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
        let dest_dir_path_str = dest_dir_path.to_string_lossy().into_owned();

        assert_eq!(
            moved_dir_handle.full_path(),
            dest_dir_path_str,
            "Expected returned dir_handle to have the correct destination"
        );

        let expected_files: Vec<String> = vec![
            dest_dir_path_str.clone(),
            format!("{dest_dir_path_str}/test_file.txt"),
        ];

        validate_dir_entries(&dest_dir_path, &expected_files)?;
        validate_file_contents(
            format!("{dest_dir_path_str}/test_file.txt").as_str(),
            file_content,
        )?;

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
        let std_dest_dir_path_str = std_dest_dir_path.to_string_lossy().into_owned();

        let expected_files: Vec<String> = vec![
            std_dest_dir_path_str.clone(),
            format!("{}/{}", std_dest_dir_path.display(), "test_file.txt"),
        ];

        validate_dir_entries(&std_dest_dir_path, &expected_files)?;
        validate_file_contents(
            format!("{std_dest_dir_path_str}/test_file.txt").as_str(),
            file_content,
        )?;

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
        let dest_dirname = "dest_dir";
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

        let dest_dir = dst_parent_dir.child(dest_dirname);
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
            dest_dirname,
            move_options_builder.build().unwrap(),
        )?;

        // The final location of the moved directory should be as a subdir of `dest_dir` because dest_dir wasn't empty
        let expected_dest_path = format!(
            "{}/{dest_dirname}/{src_dirname}",
            dst_parent_dir.to_string_lossy().into_owned()
        );
        assert_eq!(
            moved_dir_handle.full_path(),
            expected_dest_path,
            "Expected returned dir_handle to have the correct destination"
        );

        assert!(
            !src_parent_dir.child(src_dirname).exists(),
            "Expected source directory to no longer exist after move"
        );

        // Validate one level above the moved directory to make sure we didn't clobber existing contents
        let path_to_validate = dst_parent_dir.path().join(dest_dirname);
        let path_to_validate_str = path_to_validate.to_string_lossy().into_owned();

        let expected_files: Vec<String> = vec![
            path_to_validate_str.clone(),
            format!("{path_to_validate_str}/dest_file.txt"),
            format!("{path_to_validate_str}/{src_dirname}"),
            format!("{path_to_validate_str}/{src_dirname}/test_file.txt"),
            format!("{path_to_validate_str}/{src_dirname}/second_file.txt"),
        ];

        validate_dir_entries(&path_to_validate, &expected_files)?;

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
    #[case::non_verbose(false)]
    #[case::verbose(true)]
    fn test_move_dir_cross_fs_success(#[case] verbose: bool) -> Result<()> {
        let src_dirname = "source_dir";
        let dest_dirname = src_dirname;

        let mut file_contents = vec![
            ("test_file.txt", "test content for directory move operation"),
            (
                "second_file.txt",
                "second file content for directory move operation",
            ),
        ];

        file_contents.push(("nested/nested_file.txt", "nested content"));

        let setup = setup_move_test(src_dirname, file_contents, true)?;
        let src_parent_handle = setup.src_parent_handle;
        let src_dir_handle = setup.src_dir_handle;
        let src_parent_dir = setup.src_parent_dir;
        let src_dir = setup.src_dir;
        let dst_parent_dir = setup.dst_parent_dir;
        let dst_parent_dir_handle = setup.dst_parent_handle;

        // Add a socket to validate moving a socket across filesystems.
        let socket_path = src_dir.path().join("nested/test_socket");
        UnixListener::bind(socket_path)?;

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
        let dest_dir_path_str = dest_dir_path.to_string_lossy().into_owned();
        assert_eq!(
            moved_dir_handle.full_path(),
            dest_dir_path_str,
            "Expected returned dir_handle to have the correct destination"
        );

        let expected_files: Vec<String> = vec![
            dest_dir_path_str.clone(),
            format!("{dest_dir_path_str}/test_file.txt"),
            format!("{dest_dir_path_str}/second_file.txt"),
            format!("{dest_dir_path_str}/nested"),
            format!("{dest_dir_path_str}/nested/nested_file.txt"),
            format!("{dest_dir_path_str}/nested/test_socket"),
        ];

        validate_dir_entries(&dest_dir_path, &expected_files)?;
        validate_file_contents(
            format!("{dest_dir_path_str}/test_file.txt").as_str(),
            "test content for directory move operation",
        )?;
        validate_file_contents(
            format!("{dest_dir_path_str}/second_file.txt").as_str(),
            "second file content for directory move operation",
        )?;
        validate_file_contents(
            format!("{dest_dir_path_str}/nested/nested_file.txt").as_str(),
            "nested content",
        )?;

        // When a socket is moved across filesystems, we just create an empty file in its place.
        validate_file_contents(
            format!("{dest_dir_path_str}/nested/test_socket").as_str(),
            "",
        )?;

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
        let dest_dir_path_str = dest_dir_path.to_string_lossy().into_owned();

        assert_eq!(
            moved_dir_handle.full_path(),
            dest_dir_path_str,
            "Expected returned dir_handle to have the correct destination"
        );

        let expected_files: Vec<String> = vec![
            dest_dir_path_str.clone(),
            format!("{dest_dir_path_str}/src_file.txt"),
        ];

        validate_dir_entries(&dest_dir_path, &expected_files)?;

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
        let dest_dir_path_str = dest_dir_path.to_string_lossy().into_owned();

        assert_eq!(
            moved_dir_handle.full_path(),
            dest_dir_path_str,
            "Expected returned dir_handle to have the correct destination"
        );

        let expected_files: Vec<String> = vec![
            dest_dir_path_str.clone(),
            format!("{dest_dir_path_str}/test_file.txt"),
        ];

        validate_dir_entries(&dest_dir_path, &expected_files)?;
        validate_file_contents(
            format!("{dest_dir_path_str}/test_file.txt").as_str(),
            file_content,
        )?;

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
        let std_dest_dir_path_str = std_dest_dir_path.to_string_lossy().into_owned();
        let expected_files: Vec<String> = vec![
            std_dest_dir_path_str.clone(),
            format!("{std_dest_dir_path_str}/test_file.txt"),
        ];
        validate_dir_entries(&std_dest_dir_path, &expected_files)?;
        validate_file_contents(
            format!("{std_dest_dir_path_str}/test_file.txt").as_str(),
            file_content,
        )?;

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
    #[case::dest_dir_exists_empty("source_dir", "source_dir", false, false)] // `mv /src_parent/src /dest_parent` where /dest_parent/src exists and is empty
    #[case::inside_dest_dir_with_content("source_dir", "dest_dir", true, false)] // `mv /src_parent/src /dest_parent/dest` where /dest_parent/dest exists and is NOT empty
    #[case::empty_nested_dir("source_dir", "dest_dir", false, true)] // `mv /src_parent/src /dest_parent/dest` where /dest_parent/dest/src exists and is empty
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
            // $TMP/dest_dir/source_dir
            dest_dir.path().join(src_dirname)
        } else {
            // $TMP/source_dir
            dst_parent_dir.path().join(dest_dirname)
        };

        let expected_dest_path_str = expected_dest_path.to_string_lossy().into_owned();

        assert_eq!(
            moved_dir_handle.full_path(),
            expected_dest_path_str,
            "Expected returned dir_handle to have the correct destination"
        );

        let mut expected_files: Vec<String> = vec![
            expected_dest_path_str.clone(),
            format!("{expected_dest_path_str}/test_file.txt"),
            format!("{expected_dest_path_str}/second_file.txt"),
        ];

        if create_extra_content {
            expected_files.push(dest_dir.to_string_lossy().into_owned());
            expected_files.push(format!("{}/{}", dest_dir.display(), "asdf"));

            // Validate one level up at the `dest_dir` level to ensure we didn't overwrite the sibling directory.
            validate_dir_entries(&dest_dir.path().to_path_buf(), &expected_files)?;
        } else {
            validate_dir_entries(&expected_dest_path, &expected_files)?;
        }

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

/// Validates the contents of a directory against a list of expected entry names. The directory itself should be included in the expected entries.
fn validate_dir_entries(dir_path: &PathBuf, expected_entries: &Vec<String>) -> Result<()> {
    let find_results = String::from_utf8(
        std::process::Command::new("find")
            .arg(dir_path.as_os_str())
            .output()?
            .stdout,
    )?;

    let mut moved = find_results.lines().collect::<Vec<_>>();

    moved.sort();

    let mut expected_entries: Vec<&str> = expected_entries.iter().map(|s| s.as_str()).collect();
    expected_entries.sort();

    assert_eq!(
        *expected_entries, moved,
        "Expected entries did not equal actual entries"
    );

    Ok(())
}

fn validate_file_contents(file_path: &str, expected_content: &str) -> Result<()> {
    let actual_content = read_to_string(file_path)?;
    assert_eq!(
        actual_content, expected_content,
        "File content for path {file_path} does not match expected content"
    );
    Ok(())
}
