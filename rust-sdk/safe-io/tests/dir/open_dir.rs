use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::io::{create_file_with_content, create_temp_dir, create_temp_dir_and_path};
use rust_safe_io::DirConfigBuilder;
use rust_safe_io::error_constants::{
    FAILED_CREATE_DIR, FAILED_OPEN_DIR, FAILED_OPEN_PARENT, FILE_DNE_ERR, NOT_A_DIR,
    PATH_NOT_ABSOLUTE, PATH_TRAVERSAL, TOO_MANY_SYMLINKS,
};
use rust_safe_io::errors::RustSafeIoError;
use rust_safe_io::options::{DeleteDirOptionsBuilder, OpenDirOptionsBuilder};

use anyhow::Result;
use assert_fs::fixture::{SymlinkToDir, SymlinkToFile};
use assert_fs::prelude::{PathChild, PathCreateDir};
use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rstest::rstest;
use std::fs::{Permissions, metadata, set_permissions};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use crate::test_common::{
    PERMISSION_EXTRACT_BITMASK, open_dir_with_follow_symlinks, read_and_verify_file_content,
};

const NO_PERMS_BITMASK: u32 = 0o000;

mod open_existing_dir_tests {
    use super::*;

    /// Given: A directory path containing invalid characters (null byte)
    /// When: The dir is opened
    /// Then: The dir is not opened and an error is thrown
    #[test]
    fn test_open_dir_invalid_path() {
        let result = DirConfigBuilder::default()
            .path("/test\0dir".to_string())
            .build()
            .unwrap()
            .safe_open(
                &DEFAULT_TEST_CEDAR_AUTH,
                OpenDirOptionsBuilder::default().build().unwrap(),
            );

        // assert for auth failure since Cedar authorization check happens first before any file/dir operations
        assert_error_contains(result, "Path contains invalid characters");
    }

    /// Given: A directory path that should not be supported
    /// When: The dir is opened
    /// Then: The dir is not opened and an error is thrown
    #[rstest]
    #[case::path_does_not_exist("/invalid/path/to/directory", FILE_DNE_ERR)]
    #[case::empty_path("", PATH_NOT_ABSOLUTE)]
    #[case::dot_slash("./real_dir", PATH_NOT_ABSOLUTE)]
    #[case::traversal("../real_dir", PATH_NOT_ABSOLUTE)]
    fn test_open_dir_errors(#[case] dir_path: &str, #[case] expected_err: &str) -> Result<()> {
        let parent_dir = create_temp_dir()?;
        let child_dir = parent_dir.child("real_dir");
        let grandchild_dir = child_dir.child("grandchild");
        child_dir.create_dir_all()?;
        grandchild_dir.create_dir_all()?;

        let result = DirConfigBuilder::default()
            .path(dir_path.to_string())
            .build()?
            .safe_open(
                &DEFAULT_TEST_CEDAR_AUTH,
                OpenDirOptionsBuilder::default().build().unwrap(),
            );
        assert_error_contains(result, expected_err);

        Ok(())
    }

    /// Given: A directory path that should not be supported
    /// When: The dir is opened
    /// Then: The dir is not opened an error is thrown
    #[rstest]
    #[case::symlink("symlink")]
    #[case::symlink_slash("symlink/")]
    #[case::nested_symlink("symlink/grandchild")]
    fn test_open_dir_symlinks(#[case] dir_path: &str) -> Result<()> {
        let parent_dir = create_temp_dir()?;
        let child_dir = parent_dir.child("real_dir");
        let grandchild_dir = child_dir.child("grandchild");
        child_dir.create_dir_all()?;
        grandchild_dir.create_dir_all()?;

        // create a symlink from symlink -> real_dir
        parent_dir
            .child("symlink")
            .symlink_to_dir(child_dir.path())
            .unwrap();

        let path_str = format!(
            "{}/{dir_path}",
            parent_dir.path().to_str().unwrap().to_string()
        );

        // sanity check to ensure the path actually exists before testing
        // using safe IO
        assert!(
            Path::new(&path_str).exists(),
            "symlink path does not exist: {:?}",
            path_str
        );

        let result = DirConfigBuilder::default()
            .path(path_str)
            .build()?
            .safe_open(
                &DEFAULT_TEST_CEDAR_AUTH,
                OpenDirOptionsBuilder::default().build().unwrap(),
            );

        assert!(matches!(
            result,
            Err(RustSafeIoError::IoError(_)) | Err(RustSafeIoError::DirectoryOpenError { .. })
        ));

        assert_error_contains(result, NOT_A_DIR);
        Ok(())
    }

    /// Given: A directory path that leads to path traversal
    /// When: The dir is opened
    /// Then: The dir is not opened an error is thrown
    #[test]
    fn test_open_dir_path_traversal() -> Result<()> {
        let parent_dir = create_temp_dir()?;
        let child_dir = parent_dir.child("real_dir");
        child_dir.create_dir_all()?;

        let child_dir_path = child_dir.path().to_str().unwrap();
        let dir_path = format!("{child_dir_path}/../real_dir");
        let result = DirConfigBuilder::default()
            .path(dir_path)
            .build()?
            .safe_open(
                &DEFAULT_TEST_CEDAR_AUTH,
                OpenDirOptionsBuilder::default().build().unwrap(),
            );

        assert_error_contains(result, PATH_TRAVERSAL);

        Ok(())
    }

    /// Given: A non-existent directory path to open dir
    /// When: open dir is called with directory path
    /// Then: Error is thrown due to non-existent directory path
    #[test]
    fn test_safe_open_dir_nonexistent_dir_path() {
        let non_existent_dir_path = "/non/existent/directory/path";

        let result = DirConfigBuilder::default()
            .path(non_existent_dir_path.to_string())
            .build()
            .unwrap()
            .safe_open(
                &DEFAULT_TEST_CEDAR_AUTH,
                OpenDirOptionsBuilder::default().build().unwrap(),
            );
        assert!(matches!(result, Err(RustSafeIoError::IoError(_))));
        assert_error_contains(result, FILE_DNE_ERR);
    }

    /// Given: A directory and an unauthorized user
    /// When: The directory is attempted to be opened with create flag
    /// Then: Access is denied
    #[test]
    fn test_unauthorized_safe_open_dir() {
        let temp_dir = create_temp_dir().unwrap();
        let dir_path = temp_dir.path();
        let create_dir_path = dir_path.join("test");
        let create_dir_path_str = create_dir_path.to_string_lossy().to_string();
        let principal = get_test_rex_principal();
        let test_policy = format!(
            r#"forbid(
                principal == User::"{principal}",
                action == {},
                resource
            );"#,
            FilesystemAction::Open,
        );

        let test_cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy)
            .build()
            .unwrap()
            .create();

        assert!(
            !create_dir_path.exists(),
            "Expected directory path not to exist before attempted creation: {:?}",
            create_dir_path
        );

        let result = DirConfigBuilder::default()
            .path(create_dir_path_str)
            .build()
            .unwrap()
            .safe_open(
                &test_cedar_auth,
                OpenDirOptionsBuilder::default()
                    .create(true)
                    .build()
                    .unwrap(),
            );

        let expected_error = format!(
            "Permission denied: {principal} unauthorized to perform {}",
            FilesystemAction::Open
        );
        assert_error_contains(result, &expected_error);

        temp_dir.close().unwrap();
    }
}

mod open_create_dir_tests {
    use super::*;

    /// Given: A directory path that points to "/"
    /// When: Create directory is called with and without the recursive flag
    /// Then: Directory is created when recursive is passed, and fails when not
    #[rstest]
    #[case::recursive_create_root(true)]
    #[case::non_recursive_create_root(false)]
    fn test_safe_create_dir_root(#[case] recursive: bool) {
        let mut builder = DirConfigBuilder::default();
        builder.path("/".to_string());

        let result = builder.build().unwrap().safe_open(
            &DEFAULT_TEST_CEDAR_AUTH,
            OpenDirOptionsBuilder::default()
                .create(true)
                .recursive(recursive)
                .build()
                .unwrap(),
        );

        if recursive {
            assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
        } else {
            // slash exists on Linux, so this will fail unless recursive is passed
            assert!(result.is_err());
        }
    }

    /// Given: A directory path that points to a dir that exists
    /// When: The directory is attempted to open with create and doesn't have perms to create it
    /// Then: An error occurs
    #[rstest]
    #[cfg_attr(
        not(target_vendor = "apple"),
        case::no_permissions_existing_dir(NO_PERMS_BITMASK, "test3")
    )]
    #[case::read_only_nested_dir(0o444, "subdir1/subdir2")]
    fn test_directory_creation_failure(
        #[case] permission_mode: u32,
        #[case] subdir_path: &str,
    ) -> Result<()> {
        let temp_dir = create_temp_dir()?;
        let dir_path = temp_dir.path();
        let create_dir_path = dir_path.join("test");
        let create_dir_path_str = create_dir_path.to_string_lossy().to_string();

        assert!(
            !create_dir_path.exists(),
            "Expected directory path not to exist before creation: {:?}",
            create_dir_path
        );

        {
            let result = DirConfigBuilder::default()
                .path(create_dir_path_str.clone())
                .build()
                .unwrap()
                .safe_open(
                    &DEFAULT_TEST_CEDAR_AUTH,
                    OpenDirOptionsBuilder::default()
                        .create(true)
                        .build()
                        .unwrap(),
                );

            assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
            assert!(
                create_dir_path.exists(),
                "Expected directory to exist after creation: {:?}",
                create_dir_path
            );
        }

        // Set restrictive permissions on the parent directory
        let original_mode = metadata(&create_dir_path_str)?.mode() & PERMISSION_EXTRACT_BITMASK;
        set_permissions(
            &create_dir_path_str,
            Permissions::from_mode(permission_mode),
        )?;

        // Try to create a subdirectory which should fail due to permissions
        let target_path = format!("{}/{}", create_dir_path_str, subdir_path);

        let result = DirConfigBuilder::default()
            .path(target_path)
            .build()?
            .safe_open(
                &DEFAULT_TEST_CEDAR_AUTH,
                OpenDirOptionsBuilder::default()
                    .create(true)
                    .recursive(true)
                    .build()
                    .unwrap(),
            );

        // Restore original permissions to allow cleanup
        set_permissions(&create_dir_path_str, Permissions::from_mode(original_mode))?;

        assert!(matches!(
            result,
            Err(RustSafeIoError::DirectoryOpenError { .. })
        ));
        assert_error_contains(result, FAILED_OPEN_DIR);

        Ok(())
    }

    /// Given: A directory path to create the new directory and directory name
    /// When: Create directory is called with directory path and directory name
    /// Then: Directory is created at the expected path
    #[rstest]
    #[case::recursive_create(true)]
    #[case::non_recursive_create(false)]
    fn test_safe_create_dir(#[case] recursive: bool) {
        let temp_dir = create_temp_dir().unwrap();
        let dir_path = temp_dir.path();
        let create_dir_path = if recursive {
            dir_path.join("test").join("test2")
        } else {
            dir_path.join("test")
        };
        let create_dir_path_str = create_dir_path.to_string_lossy().to_string();

        assert!(
            !create_dir_path.exists(),
            "Expected directory path not to exist before creation: {:?}",
            create_dir_path
        );

        let mut args_builder = DirConfigBuilder::default();
        args_builder.path(create_dir_path_str);

        let result = args_builder.build().unwrap().safe_open(
            &DEFAULT_TEST_CEDAR_AUTH,
            OpenDirOptionsBuilder::default()
                .create(true)
                .recursive(recursive)
                .build()
                .unwrap(),
        );

        assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
        assert!(
            create_dir_path.exists(),
            "Expected directory to exist after creation: {:?}",
            create_dir_path
        );

        temp_dir.close().unwrap();
    }

    /// Given: A directory that has a symlink to another directory
    /// When: A directory is attempted to be created at path with a symlink
    /// Then: No directory is created and an error is thrown
    #[test]
    fn test_safe_create_directory_for_symlink_path() {
        let temp_dir = create_temp_dir().unwrap();
        let real_dir = temp_dir.child("real_dir");

        let link_dir = temp_dir.child("link_dir");
        link_dir.symlink_to_dir(real_dir.parent().unwrap()).unwrap();
        let link_dir_path = link_dir.path().to_string_lossy();
        let link_dir_full_path = link_dir_path.as_ref();

        let result = DirConfigBuilder::default()
            .path(format!("{link_dir_full_path}/test"))
            .build()
            .unwrap()
            .safe_open(
                &DEFAULT_TEST_CEDAR_AUTH,
                OpenDirOptionsBuilder::default()
                    .create(true)
                    .build()
                    .unwrap(),
            );

        assert!(matches!(
            result,
            Err(RustSafeIoError::DirectoryOpenError { .. })
        ));
        assert_error_contains(result, FAILED_OPEN_PARENT);
    }

    /// Given: A path in a restricted directory (/root) where we don't have write permissions
    /// When: A directory creation is attempted in this restricted location
    /// Then: A DirectoryCreateError is thrown and no directory is created
    #[test]
    #[cfg(target_os = "linux")]
    fn test_safe_create_directory_error() {
        let restricted_path = "/root/test_dir".to_string();

        let result = DirConfigBuilder::default()
            .path(restricted_path)
            .build()
            .unwrap()
            .safe_open(
                &DEFAULT_TEST_CEDAR_AUTH,
                OpenDirOptionsBuilder::default()
                    .create(true)
                    .build()
                    .unwrap(),
            );

        println!("{}", result.as_ref().unwrap_err());
        assert!(matches!(
            result,
            Err(RustSafeIoError::DirectoryOpenError { .. })
        ));
        assert_error_contains(result, FAILED_CREATE_DIR);
    }

    /// Given: A non-existent directory path to create the directory and directory name
    /// When: Create directory is called with directory path and directory name
    /// Then: Error is thrown due to non-existent directory path
    #[test]
    fn test_safe_create_dir_nonexistent_dir_path() {
        let non_existent_dir_path = "/non/existent/directory/path";

        let result = DirConfigBuilder::default()
            .path(non_existent_dir_path.to_string())
            .build()
            .unwrap()
            .safe_open(
                &DEFAULT_TEST_CEDAR_AUTH,
                OpenDirOptionsBuilder::default()
                    .create(true)
                    .build()
                    .unwrap(),
            );
        assert_error_contains(result, FAILED_OPEN_PARENT);
    }

    /// Given: A directory path and user with only open dir permissions
    /// When: The directory is attempted to be created
    /// Then: Access is denied
    #[test]
    fn test_unauthorized_safe_create_dir() {
        let principal = get_test_rex_principal();
        let test_policy = format!(
            r#"permit(
                principal == User::"{principal}",
                action == {},
                resource
            );
        "#,
            FilesystemAction::Open
        );

        let test_cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy.to_string())
            .build()
            .unwrap()
            .create();

        let temp_dir = create_temp_dir().unwrap();
        let dir_path = temp_dir.path();
        let create_dir_path = dir_path.join("test");
        let create_dir_path_str = create_dir_path.to_string_lossy().to_string();

        let result = DirConfigBuilder::default()
            .path(create_dir_path_str)
            .build()
            .unwrap()
            .safe_open(
                &test_cedar_auth,
                OpenDirOptionsBuilder::default()
                    .create(true)
                    .build()
                    .unwrap(),
            );

        let expected_error = format!(
            "Permission denied: {principal} unauthorized to perform {}",
            FilesystemAction::Create
        );
        assert_error_contains(result, &expected_error);
        temp_dir.close().unwrap();
    }
}

mod open_symlink_dir_tests {
    use super::*;

    /// Given: A real file that is opened with safe I/O and a symlink'd dir
    /// When: The file is read with safe I/O
    /// Then: The read gives an error because the directory is a symlink
    #[test]
    fn test_opening_symlink_dir_fails() {
        let temp = create_temp_dir().unwrap();
        let real_dir = temp.child("real_dir");
        real_dir.create_dir_all().unwrap();

        let link_dir = temp.child("link_dir");
        link_dir.symlink_to_dir(real_dir.path()).unwrap();
        let link_dir_full_path = link_dir.path().to_str().unwrap().to_string();

        let result = DirConfigBuilder::default()
            .path(link_dir_full_path)
            .build()
            .unwrap()
            .safe_open(
                &DEFAULT_TEST_CEDAR_AUTH,
                OpenDirOptionsBuilder::default().build().unwrap(),
            );

        assert!(matches!(
            result,
            Err(RustSafeIoError::DirectoryOpenError { .. })
        ));
        assert_error_contains(result, NOT_A_DIR);
    }

    /// Given: Absolute symlink as intermediate path component with different follow_symlinks values
    /// When: safe_open is called to access directory through symlink path
    /// Then: Success with follow_symlinks=true, sandbox violation with follow_symlinks=false
    #[rstest]
    #[case::follow_symlinks_true(true, false, "")]
    #[case::follow_symlinks_false(false, true, NOT_A_DIR)]
    #[cfg(target_os = "linux")]
    fn test_safe_open_absolute_symlink_path_component(
        #[case] follow_symlinks: bool,
        #[case] should_fail: bool,
        #[case] expected_error: &str,
    ) -> Result<()> {
        let (symlink_temp_dir, _) = create_temp_dir_and_path()?;
        let (target_temp_dir, _) = create_temp_dir_and_path()?;

        let target_root = target_temp_dir.child("target_root");
        target_root.create_dir_all()?;
        let target_subdir = target_root.child("subdir");
        target_subdir.create_dir_all()?;

        let test_content = "symlink path component content";
        create_file_with_content(&target_subdir.path(), "test_file.txt", test_content)?;

        let absolute_symlink = symlink_temp_dir.child("link_to_target");
        absolute_symlink.symlink_to_dir(target_root.path())?;

        let path_with_symlink = format!("{}/subdir", absolute_symlink.path().to_string_lossy());

        let result = open_dir_with_follow_symlinks(path_with_symlink, follow_symlinks);

        if should_fail {
            assert_error_contains(result, expected_error);
        } else {
            let dir_handle = result?;
            read_and_verify_file_content(&dir_handle, "test_file.txt", test_content)?;
        }

        Ok(())
    }

    /// Given: Aurora-style symlink chain across multiple temp directories
    /// When: safe_open is called with follow_symlinks=true
    /// Then: The final target is resolved correctly and Aurora file is accessible
    #[test]
    #[cfg(target_os = "linux")]
    fn test_safe_open_symlink_chain_success() -> Result<()> {
        let (appbin_temp, _appbin_path) = create_temp_dir_and_path()?;
        let (appbin1_temp, _appbin1_path) = create_temp_dir_and_path()?;
        let (versions_temp, _versions_path) = create_temp_dir_and_path()?;

        // Create the final target directory structure: versions_temp/aurora-16.7.16.7.0.33723.0/share/postgresql/extension/apgdbcc--1.0.sql
        let final_target = versions_temp.child("aurora-16.7.16.7.0.33723.0");
        final_target.create_dir_all()?;

        let share_dir = final_target
            .child("share")
            .child("postgresql")
            .child("extension");
        share_dir.create_dir_all()?;

        let test_content = "-- Aurora extension SQL";
        create_file_with_content(&share_dir.path(), "apgdbcc--1.0.sql", test_content)?;

        // Create symlink chain 1: appbin1_temp/aurora-16.7.16.7.0.33723.0 -> versions_temp/aurora-16.7.16.7.0.33723.0
        let intermediate_link = appbin1_temp.child("aurora-16.7.16.7.0.33723.0");
        intermediate_link.symlink_to_dir(final_target.path())?;

        // 2. appbin_temp/aurora -> appbin1_temp/aurora-16.7.16.7.0.33723.0
        let main_link = appbin_temp.child("aurora");
        main_link.symlink_to_dir(intermediate_link.path())?;

        // Final filesystem structure: appbin_temp/aurora -> appbin1_temp/aurora-16.7.16.7.0.33723.0 -> versions_temp/aurora-16.7.16.7.0.33723.0/
        // When accessing appbin_temp/aurora/share/postgresql/extension/, it resolves to:
        // versions_temp/aurora-16.7.16.7.0.33723.0/share/postgresql/extension/
        let aurora_extension_path = format!(
            "{}/share/postgresql/extension",
            main_link.path().to_string_lossy()
        );

        let dir_handle = open_dir_with_follow_symlinks(aurora_extension_path, true)?;
        read_and_verify_file_content(&dir_handle, "apgdbcc--1.0.sql", test_content)?;

        Ok(())
    }

    /// Given: Symlink with different Cedar authorization scenarios
    /// When: safe_open is called with follow_symlinks=true
    /// Then: Authorization is checked on both symlink and target paths
    #[test]
    #[cfg(target_os = "linux")]
    fn test_safe_open_symlink_unauthorized_target() -> Result<()> {
        let (source_temp_dir, _source_temp_path) = create_temp_dir_and_path()?;
        let (target_temp_dir, _target_temp_path) = create_temp_dir_and_path()?;

        let target_dir = target_temp_dir.child("restricted_target");
        target_dir.create_dir_all()?;
        let final_dir = target_dir.child("final_dir");
        final_dir.create_dir_all()?;
        let target_absolute_path = target_dir.path().to_string_lossy().to_string();

        let symlink_dir = source_temp_dir.child("public_symlink");
        symlink_dir.symlink_to_dir(&target_absolute_path)?;
        let symlink_path = symlink_dir.path().to_string_lossy().to_string();

        let path_through_symlink = format!("{}/final_dir", symlink_path);

        let principal = get_test_rex_principal();
        let test_policy = format!(
            r#"permit(
                principal == User::"{principal}",
                action == {},
                resource == file_system::Dir::"{symlink_path}"
            );
            forbid(
                principal == User::"{principal}",
                action == {},
                resource == file_system::Dir::"{target_absolute_path}"
            );"#,
            FilesystemAction::Open,
            FilesystemAction::Open
        );

        let test_cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy)
            .build()
            .unwrap()
            .create();

        let result = DirConfigBuilder::default()
            .path(path_through_symlink)
            .build()?
            .safe_open(
                &test_cedar_auth,
                OpenDirOptionsBuilder::default()
                    .follow_symlinks(true)
                    .build()
                    .unwrap(),
            );

        let expected_error = format!(
            "Permission denied: {principal} unauthorized to perform {}",
            FilesystemAction::Open
        );
        assert_error_contains(result, &expected_error);

        Ok(())
    }

    /// Given: Symlink where Cedar policy only allows delete on resolved path, not symlink path
    /// When: safe_open is called with follow_symlinks=true and then safe_delete
    /// Then: Delete succeeds, the resolved path is used as dir_handle path
    #[test]
    #[cfg(target_os = "linux")]
    fn test_safe_open_follow_symlinks_uses_resolved_path() -> Result<()> {
        let (symlink_temp_dir, _) = create_temp_dir_and_path()?;
        let (target_temp_dir, _) = create_temp_dir_and_path()?;

        let target_dir = target_temp_dir.child("target_dir");
        target_dir.create_dir_all()?;

        let test_content = "file to be deleted";
        create_file_with_content(&target_dir.path(), "delete_me.txt", test_content)?;

        let absolute_symlink = symlink_temp_dir.child("link_to_target");
        absolute_symlink.symlink_to_dir(target_dir.path())?;

        let symlink_path = absolute_symlink.path().to_string_lossy().to_string();
        let resolved_path = target_dir.path().to_string_lossy().to_string();

        let principal = get_test_rex_principal();
        let test_policy = format!(
            r#"forbid(
                principal == User::"{principal}",
                action == {},
                resource == file_system::Dir::"{symlink_path}"
            );
            permit(
                principal == User::"{principal}",
                action == {},
                resource == file_system::Dir::"{resolved_path}"
            );"#,
            FilesystemAction::Delete,
            FilesystemAction::Delete
        );

        let test_cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy)
            .build()
            .unwrap()
            .create();

        let dir_handle = DirConfigBuilder::default()
            .path(symlink_path)
            .build()?
            .safe_open(
                &DEFAULT_TEST_CEDAR_AUTH,
                OpenDirOptionsBuilder::default()
                    .follow_symlinks(true)
                    .build()
                    .unwrap(),
            )?;

        let result = dir_handle.safe_delete(
            &test_cedar_auth,
            DeleteDirOptionsBuilder::default()
                .force(true)
                .recursive(true)
                .build()
                .unwrap(),
        );

        assert!(result.is_ok());
        assert!(!target_dir.exists(), "Target directory should be deleted");

        Ok(())
    }

    /// Given: An absolute symlink pointing to a regular file (not directory)
    /// When: safe_open is called with follow_symlinks=true
    /// Then: A directory open error is returned because O_DIRECTORY flag fails on file
    #[test]
    #[cfg(target_os = "linux")]
    fn test_safe_open_symlink_to_file_error() -> Result<()> {
        let (symlink_temp_dir, _) = create_temp_dir_and_path()?;
        let (target_temp_dir, _) = create_temp_dir_and_path()?;

        let target_file_content = "file";
        create_file_with_content(
            &target_temp_dir.path(),
            "target_file.txt",
            target_file_content,
        )?;

        let target_file_path = target_temp_dir.path().join("target_file.txt");

        let symlink_to_file = symlink_temp_dir.child("link_to_file");
        symlink_to_file.symlink_to_file(target_file_path)?;

        let path_with_symlink = format!("{}/subdir", symlink_to_file.path().to_string_lossy());

        let result = DirConfigBuilder::default()
            .path(path_with_symlink)
            .build()?
            .safe_open(
                &DEFAULT_TEST_CEDAR_AUTH,
                OpenDirOptionsBuilder::default()
                    .follow_symlinks(true)
                    .build()
                    .unwrap(),
            );
        assert_error_contains(result, NOT_A_DIR);

        Ok(())
    }

    /// Given: A directory symlink with relative target path
    /// When: safe_open is called with follow_symlinks=true
    /// Then: The relative target is resolved correctly
    #[test]
    #[cfg(target_os = "linux")]
    fn test_safe_open_follow_symlinks_relative_target() -> Result<()> {
        let (temp_dir, _temp_dir_path) = create_temp_dir_and_path()?;

        let parent_dir = temp_dir.child("parent");
        parent_dir.create_dir_all()?;

        let target_dir = temp_dir.child("target");
        target_dir.create_dir_all()?;

        let test_content = "relative_test.txt";
        create_file_with_content(&target_dir.path(), "relative_test.txt", test_content)?;

        let symlink_dir = parent_dir.child("relative_link");
        symlink_dir.symlink_to_dir("../target")?;

        let symlink_path = symlink_dir.path().to_string_lossy().to_string();

        let dir_handle = open_dir_with_follow_symlinks(symlink_path, true)?;
        read_and_verify_file_content(&dir_handle, "relative_test.txt", test_content)?;

        Ok(())
    }

    /// Given: A circular symlink (symlink pointing to itself or creating a loop)
    /// When: safe_open is called with follow_symlinks=true
    /// Then: A DirectoryOpenError is returned due to too many levels of symbolic links
    #[test]
    #[cfg(target_os = "linux")]
    fn test_safe_open_follow_symlinks_circular_link() -> Result<()> {
        let (temp_dir, _temp_dir_path) = create_temp_dir_and_path()?;

        let link1 = temp_dir.child("link1");
        let link2 = temp_dir.child("link2");

        link1.symlink_to_dir(link2.path())?;
        link2.symlink_to_dir(link1.path())?;

        let link1_path = link1.path().to_string_lossy().to_string();

        let result = DirConfigBuilder::default()
            .path(link1_path)
            .build()?
            .safe_open(
                &DEFAULT_TEST_CEDAR_AUTH,
                OpenDirOptionsBuilder::default()
                    .follow_symlinks(true)
                    .build()
                    .unwrap(),
            );

        assert_error_contains(result, TOO_MANY_SYMLINKS);

        Ok(())
    }

    /// Given: A directory symlink with create=true and follow_symlinks=true
    /// When: safe_open is called on non-existent target link
    /// Then: The create flag is ignored as the target must already exist
    #[test]
    #[cfg(target_os = "linux")]
    fn test_safe_open_follow_symlinks_ignores_create_flag() -> Result<()> {
        let (temp_dir, _temp_dir_path) = create_temp_dir_and_path()?;

        let symlink_dir = temp_dir.child("link_to_nonexistent");
        symlink_dir.symlink_to_dir("nonexistent_target")?;

        let symlink_path = symlink_dir.path().to_string_lossy().to_string();

        let result = DirConfigBuilder::default()
            .path(symlink_path)
            .build()?
            .safe_open(
                &DEFAULT_TEST_CEDAR_AUTH,
                OpenDirOptionsBuilder::default()
                    .create(true)
                    .recursive(true)
                    .follow_symlinks(true)
                    .build()
                    .unwrap(),
            );

        assert_error_contains(result, FILE_DNE_ERR);

        Ok(())
    }
}

mod safe_open_subdir_tests {
    use super::*;
    use rust_safe_io::PATH_TRAVERSAL;

    /// Given: A parent directory with a direct child subdirectory
    /// When: safe_open_subdir is called with the child directory name
    /// Then: The subdirectory is successfully opened
    #[test]
    fn test_safe_open_subdir_direct_child() -> Result<()> {
        let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
        let child_dir = temp_dir.child("child");
        child_dir.create_dir_all()?;

        let parent_handle = DirConfigBuilder::default()
            .path(temp_dir_path.clone())
            .build()?
            .safe_open(
                &DEFAULT_TEST_CEDAR_AUTH,
                OpenDirOptionsBuilder::default().build().unwrap(),
            )?;

        let child_handle = parent_handle.safe_open_subdir(&DEFAULT_TEST_CEDAR_AUTH, "child")?;

        assert!(child_handle.to_string().ends_with("/child"));
        Ok(())
    }

    /// Given: A parent directory with nested subdirectories
    /// When: safe_open_subdir is called multiple times to navigate through nested directories
    /// Then: Each nested subdirectory is successfully opened
    #[test]
    fn test_safe_open_subdir_nested() -> Result<()> {
        let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
        let level1 = temp_dir.child("level1");
        let level2 = level1.child("level2");
        let level3 = level2.child("level3");
        level3.create_dir_all()?;

        let parent_handle = DirConfigBuilder::default()
            .path(temp_dir_path)
            .build()?
            .safe_open(
                &DEFAULT_TEST_CEDAR_AUTH,
                OpenDirOptionsBuilder::default().build().unwrap(),
            )?;

        let level1_handle = parent_handle.safe_open_subdir(&DEFAULT_TEST_CEDAR_AUTH, "level1")?;
        let level2_handle = level1_handle.safe_open_subdir(&DEFAULT_TEST_CEDAR_AUTH, "level2")?;
        let level3_handle = level2_handle.safe_open_subdir(&DEFAULT_TEST_CEDAR_AUTH, "level3")?;

        assert!(level3_handle.to_string().ends_with("/level3"));
        Ok(())
    }

    /// Given: A parent directory and various invalid path attempts
    /// When: safe_open_subdir is called with path traversal attempts
    /// Then: An error is returned preventing the operation
    #[rstest]
    #[case::parent_traversal("..", PATH_TRAVERSAL)]
    #[case::child_then_parent("child/..", PATH_TRAVERSAL)]
    fn test_safe_open_subdir_path_traversal(
        #[case] subdir_name: &str,
        #[case] expected_err: &str,
    ) -> Result<()> {
        let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
        let child_dir = temp_dir.child("child");
        child_dir.create_dir_all()?;

        let parent_handle = DirConfigBuilder::default()
            .path(temp_dir_path)
            .build()?
            .safe_open(
                &DEFAULT_TEST_CEDAR_AUTH,
                OpenDirOptionsBuilder::default().build().unwrap(),
            )?;

        let result = parent_handle.safe_open_subdir(&DEFAULT_TEST_CEDAR_AUTH, subdir_name);

        assert_error_contains(result, expected_err);
        Ok(())
    }

    /// Given: A parent directory with a symlink to a subdirectory
    /// When: safe_open_subdir is called with the symlink name
    /// Then: An error is returned as symlinks are not followed
    #[test]
    fn test_safe_open_subdir_symlink() -> Result<()> {
        let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
        let target_dir = temp_dir.child("target");
        target_dir.create_dir_all()?;

        let symlink_dir = temp_dir.child("link");
        symlink_dir.symlink_to_dir(target_dir.path())?;

        let parent_handle = DirConfigBuilder::default()
            .path(temp_dir_path)
            .build()?
            .safe_open(
                &DEFAULT_TEST_CEDAR_AUTH,
                OpenDirOptionsBuilder::default().build().unwrap(),
            )?;

        let result = parent_handle.safe_open_subdir(&DEFAULT_TEST_CEDAR_AUTH, "link");

        assert_error_contains(result, NOT_A_DIR);
        Ok(())
    }

    /// Given: A parent directory without a specific subdirectory
    /// When: safe_open_subdir is called with a non-existent subdirectory name
    /// Then: An error is returned
    #[test]
    fn test_safe_open_subdir_nonexistent() -> Result<()> {
        let (_temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

        let parent_handle = DirConfigBuilder::default()
            .path(temp_dir_path)
            .build()?
            .safe_open(
                &DEFAULT_TEST_CEDAR_AUTH,
                OpenDirOptionsBuilder::default().build().unwrap(),
            )?;

        let result = parent_handle.safe_open_subdir(&DEFAULT_TEST_CEDAR_AUTH, "nonexistent");

        assert_error_contains(result, FILE_DNE_ERR);
        Ok(())
    }

    /// Given: A Cedar policy allowing directories matching /proc/*/task pattern
    /// When: Opening /proc/<pid>/task directory (thread metadata)
    /// Then: Access is granted because the directory path matches the wildcard pattern
    #[test]
    #[cfg(target_os = "linux")]
    fn test_open_dir_with_wildcard_path_policy_proc_allow() -> Result<()> {
        let pid = std::process::id();

        let principal = get_test_rex_principal();
        let test_policy = format!(
            r#"permit(
                principal == User::"{principal}",
                action == {},
                resource is file_system::Dir
            ) when {{
                resource.path like "/proc/*/task"
            }};"#,
            FilesystemAction::Open
        );

        let test_cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy)
            .build()
            .unwrap()
            .create();

        let result = DirConfigBuilder::default()
            .path(format!("/proc/{}/task", pid))
            .build()?
            .safe_open(
                &test_cedar_auth,
                OpenDirOptionsBuilder::default().build().unwrap(),
            );
        assert!(result.is_ok(), "err: {:?}", result.unwrap_err());

        Ok(())
    }

    /// Given: A Cedar policy allowing only directories matching /proc/*/task pattern
    /// When: Opening /proc/<pid>/fd directory
    /// Then: Access is denied because the directory path does not match the wildcard pattern
    #[test]
    #[cfg(target_os = "linux")]
    fn test_open_dir_with_wildcard_path_policy_proc_deny() -> Result<()> {
        let pid = std::process::id();

        let principal = get_test_rex_principal();
        let test_policy = format!(
            r#"permit(
                principal == User::"{principal}",
                action == {},
                resource is file_system::Dir
            ) when {{
                resource.path like "/proc/*/task"
            }};"#,
            FilesystemAction::Open
        );

        let test_cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy)
            .build()
            .unwrap()
            .create();

        let result = DirConfigBuilder::default()
            .path(format!("/proc/{}/fd", pid))
            .build()?
            .safe_open(
                &test_cedar_auth,
                OpenDirOptionsBuilder::default().build().unwrap(),
            );

        let expected_error = format!(
            "Permission denied: {principal} unauthorized to perform {} for file_system::Dir::/proc/{}/fd",
            FilesystemAction::Open,
            pid
        );
        assert_error_contains(result, &expected_error);

        Ok(())
    }
}
