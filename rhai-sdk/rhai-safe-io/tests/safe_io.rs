use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::get_test_rex_principal;
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::io::{
    ArchiveEntry, create_and_write_to_test_file, create_file_with_content, create_new_file_path,
    create_temp_dir, create_temp_dir_and_path, create_test_archive,
};
use rex_test_utils::random::get_rand_string;
use rex_test_utils::rhai::common::{
    assert_with_registration_details, create_default_test_cedar_auth,
    create_test_cedar_auth_with_policy, create_test_engine_and_register,
    create_test_engine_with_auth, extract_error_message, get_current_user_and_group, to_eval_error,
};
use rex_test_utils::rhai::safe_io::{assert_error_kind, create_temp_test_env_with_cert_fixtures};
use rust_safe_io::dir_entry::EntryType;
use std::fs;

use assert_fs::prelude::{
    FileTouch, FileWriteBin, FileWriteStr, PathChild, PathCreateDir, SymlinkToDir, SymlinkToFile,
};
use rhai::{EvalAltResult, Scope};
use rhai_safe_io::errors::RhaiSafeIoErrorKind;
use rstest::rstest;
use rust_safe_io::DirConfigBuilder;
use rust_safe_io::error_constants::{
    DEST_FILE_NOT_EMPTY_ERR, DIR_NED_ERR, FAILED_OPEN_PARENT, FILE_DNE_ERR, FILE_NON_UTF_8,
    INVALID_PERMISSIONS_ERR, INVALID_REGEX_PATTERN_ERR, NOT_A_DIR, READ_FILE_FLAG_ERR,
    TOO_MANY_SYMLINKS, WRITE_FILE_FLAG_ERR,
};
use rust_safe_io::options::{OpenDirOptionsBuilder, OpenFileOptionsBuilder};
use std::fs::{
    Permissions, create_dir_all, metadata, read_link, read_to_string, set_permissions, write,
};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, UNIX_EPOCH};

/// Given: A file that is a real file and a real directory
/// When: The file contains non-utf-8
/// Then: There is an error from reading the file
#[test]
fn test_reading_non_utf8() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();
    let non_utf8 = &[0xFF];
    temp.child("foo.txt").write_binary(non_utf8).unwrap();

    // create variable to pass to Rhai script
    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    // start Rhai script with variable passed in via scope
    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig().path(temp_dir_path).build()
                .open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file("foo.txt", OpenFileOptions().read(true).build());
            file_handle.read();"#,
    );

    assert_error_contains(result, FILE_NON_UTF_8);

    Ok(())
}

/// Given: A Rhai engine with registered [`DirConfig`] functionality
/// When: Attempting to build [`DirConfig`] without required fields via Rhai script
/// Then: Should return a properly formatted error message
#[test]
fn test_arg_build_error_in_rhai() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();

    let result = engine.eval::<()>(r#"DirConfig().build()"#);

    assert_error_contains(result, "Field not initialized: path");
    Ok(())
}

/// Given: A file that is a real file and a real directory
/// When: The file is read with safe I/O plugin in Rhai
/// Then: The file is read correctly with no errors in a Rhai script
#[test]
fn test_reading_normal_file() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();
    let test_str = get_rand_string();
    temp.child("foo.txt").write_str(&test_str).unwrap();

    // create variable to pass to Rhai script
    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    // start Rhai script with variable passed in via scope
    let output: String = engine.eval_with_scope::<String>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file("foo.txt", OpenFileOptions().read(true).build());
            file_handle.read();"#,
    )?;

    assert_eq!(output, test_str);

    Ok(())
}

/// Given: A file that is a symlink to a real file
/// When: The file is read with safe I/O plugin in Rhai
/// Then: The file is not read and an error is thrown in the Rhai script
#[test]
fn test_reading_symlink_fails() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path = temp.path().to_string_lossy();

    let real_file = temp.child("real_file");
    real_file.touch().unwrap();

    let link_file_name = "link_file";
    temp.child(link_file_name)
        .symlink_to_file(real_file.path())
        .unwrap();

    let mut scope = Scope::new();
    scope.push_constant("path", temp_dir_path.to_string());
    scope.push_constant("file", link_file_name);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file(file, OpenFileOptions().read(true).build());
            file_handle.read()"#,
    );

    assert_error_contains(result, "symbolic link");

    Ok(())
}

/// Given: A real file that is opened with safe I/O and a symlink'd dir
/// When: The file is read with safe I/O plugin in Rhai
/// Then: The read gives an error because the directory is a symlink
#[test]
fn test_reading_symlink_dir_fails() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;

    let real_dir = temp.child("real_dir");
    real_dir.create_dir_all().unwrap();
    let test_str = get_rand_string();
    real_dir.child("foo.txt").write_str(&test_str).unwrap();

    let link_dir = temp.child("link_dir");
    link_dir.symlink_to_dir(real_dir.path()).unwrap();
    let link_dir_path = link_dir.path().to_str().unwrap();

    let mut scope = Scope::new();
    scope.push_constant("path", link_dir_path.to_string());
    scope.push_constant("file", "foo.txt");

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file(file, OpenFileOptions().build());
            file_handle.read();"#,
    );

    assert_error_contains(result, NOT_A_DIR);

    temp.close().unwrap();
    Ok(())
}

/// Given: A directory path containing invalid characters (null byte)
/// When: The file is read with safe I/O plugin in Rhai
/// Then: The file is not read and an error is thrown in the Rhai script
#[test]
fn test_read_file_contents_invalid_path() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let _temp_dir = create_temp_dir().map_err(to_eval_error)?;

    let mut scope = Scope::new();
    scope.push_constant("path", "/test\0dir");
    scope.push_constant("file", "test.txt");

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file(file, OpenFileOptions().build());
            file_handle.read();"#,
    );

    // assert for auth failure since Cedar authorization check happens firsts before any file/dir operations
    assert_error_contains(result, "Path contains invalid characters");

    Ok(())
}

/// Given: A dir that does not exist
/// When: The dir is read with safe I/O plugin in Rhai
/// Then: The Rhai script throws an error
#[test]
fn test_reading_dir_that_dne() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();

    // since we're expecting an error, use <()>
    let result = engine.eval::<()>(
        r#"
        DirConfig()
            .path("/path/dne")
            .build().open(OpenDirOptions().build());
        "#,
    );

    assert_error_contains(result, FILE_DNE_ERR);

    Ok(())
}

/// Given: A file that is in a directory that does not exist
/// When: The file is read with safe I/O plugin in Rhai
/// Then: The Rhai script throws an error
#[test]
fn test_reading_file_that_dne() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    // since we're expecting an error, use <()>
    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
        let dir_handle = DirConfig()
            .path({temp_dir_path})
            .build().open(OpenDirOptions().build());
        dir_handle.open_file("dne.txt", OpenFileOptions().read(true).build());
        "#,
    );

    assert_error_contains(result, FILE_DNE_ERR);

    temp.close().unwrap();

    Ok(())
}

/// Given: A file that is a real file and is in a real directory
/// When: [`rhai_safe_io::safe_io::delete_file`] is called to delete a file with both `force` = true/false case
/// Then: The file is deleted successfully with no errors
#[rstest]
#[case::no_force(false)]
#[case::force(true)]
fn test_safe_delete_file_success(#[case] force: bool) -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;
    let test_file = "test_file.txt";

    let _file_path = create_and_write_to_test_file(&temp_dir, test_file).map_err(to_eval_error)?;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("file", test_file);
    scope.push("force", force);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
        let dir_handle = DirConfig()
            .path(temp_dir_path)
            .build().open(OpenDirOptions().build());
        let file_handle = dir_handle.open_file(file, OpenFileOptions().read(true).build());

        file_handle.delete(DeleteFileOptions().build());
        "#,
    );

    assert!(result.is_ok());
    assert!(!temp_dir.child(test_file).exists());

    Ok(())
}

/// Given: A file that is in a non-existent directory
/// When: [`rhai_safe_io::safe_io::delete_file`] is called to delete a file with both `force` = true/false case
/// Then: The file is deleted successfully with no errors when `force` = true. An error is thrown when `force` = false
#[rstest]
#[case::no_force(false, FILE_DNE_ERR)]
#[case::force(true, "")]
fn test_safe_delete_file_for_nonexistent_dir(
    #[case] force: bool,
    #[case] expected_error: &str,
) -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;
    let test_file = "file.txt";

    let _file_path = create_and_write_to_test_file(&temp_dir, test_file).map_err(to_eval_error)?;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("file", test_file);
    scope.push("force", force);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_config = DirConfig()
                .path({temp_dir_path})
                .build();
            let dir_handle = dir_config.open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file(file, OpenFileOptions().read(true).build());

            let initial_delete = dir_handle.delete(DeleteDirOptions().force(true).recursive(true).build());
            file_handle.delete(DeleteFileOptions().force(force).build());
            "#,
    );

    assert!(!temp_dir.exists());
    assert!(!temp_dir.child(test_file).exists());

    if force {
        assert_with_registration_details(&result, || result.is_ok(), &engine, "delete");
    } else {
        assert_error_contains(result, expected_error);
    }

    Ok(())
}

/// Given: A file that is a non-existent file
/// When: [`rhai_safe_io::safe_io::delete_file`] is called to delete a file with both `force` = true/false case
/// Then: The file is deleted successfully with no errors when `force` = true. An error is thrown when `force` = false
#[rstest]
#[case::no_force(false, FILE_DNE_ERR)]
#[case::force(true, "")]
fn test_safe_delete_file_for_nonexistent_file(
    #[case] force: bool,
    #[case] expected_error: &str,
) -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;
    let test_file = "nonexistent_file.txt";

    let _file_path = create_and_write_to_test_file(&temp_dir, test_file).map_err(to_eval_error)?;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("file", test_file);
    scope.push("force", force);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
        let dir_handle = DirConfig()
            .path({temp_dir_path})
            .build().open(OpenDirOptions().build());
        let file_handle = dir_handle.open_file(file, OpenFileOptions().read(true).build());

        let initial_delete = file_handle.delete(DeleteFileOptions().build());
        file_handle.delete(DeleteFileOptions().force(force).build());
        "#,
    );

    assert!(temp_dir.exists());
    assert!(!temp_dir.child(test_file).exists());

    if force {
        assert!(result.is_ok());
    } else {
        assert_error_contains(result, expected_error);
    }

    Ok(())
}

/// Given: An empty directory
/// When: The directory is deleted with [`rust_safe_io::DirConfig::recursive`] and [`rust_safe_io::DirConfig::force`] combinations
/// Then: The directory is deleted successfully in all cases
#[rstest]
#[case::non_recursive_and_no_force(false, false)]
#[case::recursive_with_and_no_force(true, false)]
#[case::non_recursive_and_force(false, true)]
#[case::recursive_and_force(true, true)]
fn test_delete_dir_empty_directory(
    #[case] recursive: bool,
    #[case] force: bool,
) -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("recursive", recursive.clone());
    scope.push_constant("force", force.clone());

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
        let dir_config = DirConfig()
            .path(temp_dir_path)
            .build();

        let dir_handle = dir_config.open(OpenDirOptions().create(true).recursive(true).build());

        dir_handle.delete(DeleteDirOptions().force(force).recursive(recursive).build());
        "#,
    );

    assert!(result.is_ok());
    assert!(!temp_dir.exists());

    Ok(())
}

/// Given: A non-existent directory
/// When: The directory is deleted with [`rust_safe_io::DirConfig::recursive`] and [`rust_safe_io::DirConfig::force] combinations
/// Then: The directory is deleted successfully with no errors when [`rust_safe_io::DirConfig::force`] = true. An error is thrown when [`rust_safe_io::DirConfig::force`] = false
#[rstest]
#[case::non_recursive_and_no_force(false, false, FILE_DNE_ERR)]
#[case::recursive_and_no_force(true, false, FILE_DNE_ERR)]
#[case::non_recursive_and_force(false, true, "")]
#[case::recursive_and_force(true, true, "")]
fn test_delete_dir_nonexistent_directory(
    #[case] recursive: bool,
    #[case] force: bool,
    #[case] expected_error: &str,
) -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let (_temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("recursive", recursive.clone());
    scope.push_constant("force", force.clone());

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
        let dir_config = DirConfig()
            .path(temp_dir_path)
            .build();

        let dir_handle = dir_config.open(OpenDirOptions().build());

        let initial_delete = dir_handle.delete(DeleteDirOptions().force(true).recursive(true).build());

        dir_handle.delete(DeleteDirOptions().force(force).recursive(recursive).build());
        "#,
    );

    if force {
        assert_with_registration_details(&result, || result.is_ok(), &engine, "delete");
    } else {
        assert_error_contains(result, expected_error);
    }

    Ok(())
}

/// Given: A directory containing a subdirectory and files
/// When: The directory is deleted with [`rust_safe_io::DirConfig::recursive`] and [`rust_safe_io::DirConfig::force`] combinations
/// Then: The directory and its contents are deleted successfully when [`rust_safe_io::DirConfig::recursive`] = true, an error is thrown when [`rust_safe_io::DirConfig::recursive`] = false
#[rstest]
#[case::non_recursive_and_no_force(false, false, DIR_NED_ERR)]
#[case::recursive_and_no_force(true, false, "")]
#[case::non_recursive_and_force(false, true, DIR_NED_ERR)]
#[case::recursive_and_force(true, true, "")]
fn test_delete_dir_with_files(
    #[case] recursive: bool,
    #[case] force: bool,
    #[case] expected_error: &str,
) -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let subdir = temp_dir.child("subdir");
    subdir.create_dir_all().unwrap();

    let test_file = "test_file.txt";
    let file = temp_dir.child(test_file);
    create_and_write_to_test_file(&temp_dir, test_file).map_err(to_eval_error)?;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("recursive", recursive.clone());
    scope.push_constant("force", force.clone());

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
        let dir_config = DirConfig()
            .path(temp_dir_path)
            .build();

        let dir_handle = dir_config.open(OpenDirOptions().build());

        dir_handle.delete(DeleteDirOptions().force(force).recursive(recursive).build());
        "#,
    );

    if recursive {
        assert!(result.is_ok());
        assert!(!temp_dir.exists());
        assert!(!subdir.exists());
        assert!(!file.exists());
    } else {
        assert_error_contains(result, expected_error);
        assert!(temp_dir.exists());
        assert!(subdir.exists());
        assert!(file.exists());
    }

    Ok(())
}

/// Given: A directory that is a read-only directory
/// When: The directory is deleted with [`rust_safe_io::DirConfig::recursive`] and [`rust_safe_io::DirConfig::force`] combinations
/// Then: The directory is not deleted an error is thrown.
#[rstest]
#[case::non_recursive_and_no_force(false, false)]
#[case::recursive_and_no_force(true, false)]
#[case::non_recursive_and_force(false, true)]
#[case::recursive_and_force(true, true)]
fn test_delete_dir_permission_denied(
    #[case] recursive: bool,
    #[case] force: bool,
) -> Result<(), anyhow::Error> {
    let engine = create_test_engine_and_register();
    let (_temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let cedar_auth = create_default_test_cedar_auth();
    let dir_config = DirConfigBuilder::default()
        .path(temp_dir_path.to_string())
        .build()
        .unwrap();
    let dir_handle = dir_config
        .safe_open(
            &cedar_auth,
            OpenDirOptionsBuilder::default().build().unwrap(),
        )
        .unwrap();

    let readonly_mode = 0o644;
    set_permissions(&temp_dir_path, Permissions::from_mode(readonly_mode))?;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("recursive", recursive.clone());
    scope.push_constant("force", force.clone());
    scope.push_constant("dir_handle", dir_handle);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
        let dir_handle = DirConfig()
            .path(temp_dir_path)
            .build().open(OpenDirOptions().build());

        dir_handle.delete(DeleteDirOptions().force(force).recursive(recursive).build());
        "#,
    );

    assert_error_contains(result, "Error removing directory:");

    Ok(())
}

/// Given: A directory to create a file in
/// When: A file is created with safe_create_file
/// Then: The file is created and the file handle is returned which can be used for writing
#[test]
fn test_creating_file() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();

    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;
    let (temp_file_path, temp_file_name) = create_new_file_path(&temp_dir);
    let content = get_rand_string();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path.clone());
    scope.push_constant("temp_file_name", temp_file_name.clone());
    scope.push_constant("content", content.clone()); // clone() to avoid "borrow of moved value" error

    engine.eval_with_scope::<()>(
        &mut scope,
        r#"
        let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
        let file_handle = dir_handle.open_file(temp_file_name, OpenFileOptions().create(true).build());

        file_handle = file_handle.write(content);
        "#,
    )?;

    assert!(Path::new(&temp_file_path).exists());

    let actual_content = read_file_contents(&temp_dir_path, &temp_file_name)?;

    assert_eq!(actual_content, content);

    temp_dir.close().unwrap();

    Ok(())
}

/// Given: A user without Open permission
/// When: A file is opened with open_file
/// Then: Access is denied for the Open action (first check fails)
#[test]
fn test_unauthorized_open_file() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let policy = format!(
        r#"forbid(
            principal == User::"{principal}",
            action == {},
            resource
        );"#,
        FilesystemAction::Open
    );

    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file("test_file.txt", OpenFileOptions().create(true).build());
        "#,
    );

    let error_message = extract_error_message(&result.unwrap_err());
    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Open
    );

    assert!(
        error_message.contains(&expected_error),
        "Expected error to contain '{}', but got: '{}'",
        expected_error,
        error_message
    );

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A user without Create permission but with Open permission
/// When: A file is opened with open_file and create=true
/// Then: Access is denied for the Create action
#[test]
fn test_unauthorized_create_file() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let policy = format!(
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

    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file("test_file.txt", OpenFileOptions().create(true).build());
        "#,
    );

    let error_message = extract_error_message(&result.unwrap_err());
    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Create
    );
    assert!(
        error_message.contains(&expected_error),
        "Expected error to contain '{}', but got: '{}'",
        expected_error,
        error_message
    );

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A file that already exists
/// When: A safe_open_file is called with the create option
/// Then: The original file is opened and its contents are unaltered
#[test]
fn test_creating_file_that_already_exists() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();

    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;
    let (_temp_file_path, temp_file_name) = create_new_file_path(&temp_dir);
    let test_str = get_rand_string();
    temp_dir
        .child(&temp_file_name)
        .write_str(&test_str)
        .unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_file_name", temp_file_name);
    scope.push_constant("temp_dir_path", temp_dir_path);

    let output: String = engine.eval_with_scope::<String>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file(temp_file_name, OpenFileOptions().create(true).read(true).build());
            file_handle.read();"#,
    )?;

    // Validate that the file is the same as the original one by comparing its contents to the original contents.
    // If a new file was created, the actual contents would be empty.
    assert_eq!(output, test_str);

    Ok(())
}

/// Given: A directory that does not exist whose parent exists
/// When: A directory is created with create set to true and errors if set to false
/// Then: The directory is created when set to true and will fail when set to false
#[rstest]
#[case::create(true)]
#[case::missing_create(false)]
fn test_creating_directory(#[case] should_create: bool) -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();

    let (temp_dir, _temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;
    let (new_dir_path, _new_dir_name) = create_new_file_path(&temp_dir);

    // ensure dir does not exist
    assert!(!Path::new(&new_dir_path).exists());

    let mut scope = Scope::new();
    let new_dir_path_str = new_dir_path.display().to_string();
    scope.push_constant("temp_dir_name", new_dir_path_str);

    if should_create {
        let result = engine.eval_with_scope::<()>(
            &mut scope,
            r#"
            let dir_handle = DirConfig()
                .path(temp_dir_name)
                .build().open(OpenDirOptions().create(true).recursive(true).build());
            "#,
        );
        assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
        assert!(Path::new(&new_dir_path).exists());
    } else {
        let result = engine.eval_with_scope::<()>(
            &mut scope,
            r#"
            let dir_handle = DirConfig()
                .path(temp_dir_name)
                .build().open(OpenDirOptions().build());
            "#,
        );
        assert_error_contains(result, FILE_DNE_ERR);
    }

    Ok(())
}

/// Given: A directory whose parent does not exist
/// When: A directory is created with create flag set to true
/// Then: An error is thrown due to non-existing directory
#[test]
fn test_creating_directory_for_non_existing_dir() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();

    let temp_dir_parent = get_rand_string();
    let temp_dir_path = get_rand_string();

    let mut scope = Scope::new();
    scope.push_constant(
        "temp_dir_path",
        format!("/{}/{}", temp_dir_parent, temp_dir_path),
    );

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().create(true).build());
            "#,
    );

    assert_error_contains(result, FAILED_OPEN_PARENT);

    Ok(())
}

/// Given: A file with content
/// When: The get_last_modified_time function is called on the file
/// Then: A valid unix timestamp is returned
#[test]
#[cfg(unix)]
fn test_last_modified_time() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    temp.child("test.txt").write_str("test content").unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let modified_time = engine.eval_with_scope::<i64>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file("test.txt", OpenFileOptions().read(true).build());
            file_handle.get_last_modified_time();"#,
    )?;

    let binding = temp.child("test.txt");
    let file_path = binding.path();
    let expected_time = std::fs::metadata(file_path)
        .unwrap()
        .modified()
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as i64;

    assert_eq!(modified_time, expected_time);

    Ok(())
}

fn read_file_contents(dir_path: &str, file_name: &str) -> Result<String, Box<EvalAltResult>> {
    let cedar_auth = create_default_test_cedar_auth();
    let args = DirConfigBuilder::default()
        .path(dir_path.to_string())
        .build()
        .unwrap();
    let dir = args
        .safe_open(
            &cedar_auth,
            OpenDirOptionsBuilder::default().build().unwrap(),
        )
        .unwrap();
    let file = dir
        .safe_open_file(
            &cedar_auth,
            file_name,
            OpenFileOptionsBuilder::default()
                .read(true)
                .build()
                .unwrap(),
        )
        .map_err(to_eval_error)?;
    file.safe_read(&cedar_auth).map_err(to_eval_error)
}

/// Given: A valid directory path and file name
/// When: Text file is written with WriteOptions
/// Then: Text file is written correctly with no errors in a Rhai script
#[test]
fn test_safe_write_file_with_options_happy_case() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();

    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;
    let test_file = "test.txt";
    let content = get_rand_string();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("test_file", test_file);
    scope.push_constant("content", content.clone());

    let script = r#"
        let dir_handle = DirConfig()
            .path(temp_dir_path)
            .build().open(OpenDirOptions().build());
        let file_handle = dir_handle.open_file(test_file, OpenFileOptions().create(true).build());
        let write_opts = WriteOptions().preserve_ownership(false).build();
        file_handle = file_handle.write(content, write_opts);
    "#;

    let result = engine.eval_with_scope::<()>(&mut scope, script);
    assert_with_registration_details(&result, || result.is_ok(), &engine, "write");

    let actual_content = read_file_contents(&temp_dir.path().to_string_lossy(), test_file)?;
    assert_eq!(actual_content, content);

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A file opened without write option
/// When: Text file is written with WriteOptions
/// Then: An error is returned with write flag error message
#[test]
fn test_safe_write_file_with_options_err() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();

    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;
    let test_file = "test.txt";

    create_and_write_to_test_file(&temp_dir, test_file).map_err(to_eval_error)?;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("test_file", test_file);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file(test_file, OpenFileOptions().read(true).build());
            let write_opts = WriteOptions().preserve_ownership(false).build();
            file_handle = file_handle.write("content", write_opts);
        "#,
    );
    assert!(result.is_err());
    let error_message = extract_error_message(&result.unwrap_err());
    assert!(
        error_message.contains(WRITE_FILE_FLAG_ERR),
        "Expected error to contain '{}', but got: '{}'",
        WRITE_FILE_FLAG_ERR,
        error_message
    );

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A valid directory path and file name
/// When: Text file is written in the directory
/// Then: Text file is written correctly with no errors in a Rhai script
#[rstest]
#[case::atomic_write(String::from("write"))]
#[case::non_atomic_write(String::from("write_in_place"))]
fn test_safe_write_file_happy_case(
    #[case] write_function: String,
) -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();

    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;
    let test_file = "test.txt";
    let content = get_rand_string();

    // create variable to pass to Rhai script
    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("test_file", test_file);
    scope.push_constant("content", content.clone());

    let script = format!(
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            try {{
                // this block fails if file does not exist yet
                let file_handle = dir_handle.open_file(test_file, OpenFileOptions().create(true).build());
                file_handle = file_handle.{write_function}(content);
            }} catch {{
                let file_handle = dir_handle.open_file(test_file, OpenFileOptions().create(true).build());
                file_handle = file_handle.{write_function}(content);
            }}
            "#
    );

    // start Rhai script with variable passed in via scope
    engine.eval_with_scope::<()>(&mut scope, script.as_str())?;

    assert!(temp_dir.child(test_file).exists());

    let actual_content = read_file_contents(&temp_dir.path().to_string_lossy(), test_file)?;
    assert_eq!(actual_content, content);

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A valid directory path and a text file in the directory
/// When: Text file is overwritten with a new content
/// Then: Text file is overwritten correctly
#[rstest]
#[case::atomic_write(String::from("write"))]
#[case::non_atomic_write(String::from("write_in_place"))]
fn test_safe_write_file_overwrite_file(
    #[case] write_function: String,
) -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();

    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;
    let test_file = "test.txt";
    let updated_content = get_rand_string();

    create_and_write_to_test_file(&temp_dir, test_file).map_err(to_eval_error)?;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("test_file", test_file);
    scope.push_constant("updated_content", updated_content.clone()); // clone() to avoid "borrow of moved value" error

    let script = format!(
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file(test_file, OpenFileOptions().write(true).build());

            file_handle = file_handle.{write_function}(updated_content);
        "#
    );

    let result = engine.eval_with_scope::<()>(&mut scope, script.as_str());
    assert!(result.is_ok());

    let actual_updated_content = read_file_contents(&temp_dir.path().to_string_lossy(), test_file)?;

    assert_eq!(actual_updated_content, updated_content);

    temp_dir.close().unwrap();

    Ok(())
}

/// Given: A file to write that's been closed
/// When: The file is accessed for writing
/// Then: The write fails and an error is returned
#[rstest]
#[case::atomic_write(String::from("write"))]
#[case::non_atomic_write(String::from("write_in_place"))]
fn test_safe_write_file_force_err(
    #[case] write_function: String,
) -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();

    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;
    let test_file = "test.txt";
    let data = get_rand_string();

    create_and_write_to_test_file(&temp_dir, test_file).map_err(to_eval_error)?;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("test_file", test_file);
    scope.push_constant("contents", data);

    // open dir/file in engine first
    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file(test_file, OpenFileOptions().read(true).build());
            "#,
    );
    assert!(result.is_ok());

    // close fd to force an error when writing
    temp_dir.close().unwrap();

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        format!(
            r#"
            file_handle = file_handle.{write_function}(contents);
            "#
        )
        .as_str(),
    );
    assert!(result.is_err());

    Ok(())
}

/// NB: More thorough tests for this function will be implemented as REX integration tests.
/// Given: A valid directory
/// When: The get_ownership function is called
/// Then: The owner and group of the directory are returned successfully
#[test]
#[cfg(unix)]
fn test_get_ownership_success() -> Result<(), Box<EvalAltResult>> {
    use rex_test_utils::rhai::common::get_current_user_and_group;

    let principal = get_test_rex_principal();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    let no_get_ownership_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [
                file_system::Action::"read",
                file_system::Action::"open",
                file_system::Action::"stat"
            ],
            resource in file_system::Dir::"{temp_dir_path}"
        );"#
    );

    let auth = create_test_cedar_auth_with_policy(&no_get_ownership_policy);
    let engine = create_test_engine_with_auth(auth);

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<rhai::Map>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let ownership = dir_handle.get_ownership();
            #{
                "user": ownership.user,
                "group": ownership.group
            }
        "#,
    );

    assert_with_registration_details(&result, || result.is_ok(), &engine, "ownership");
    let ownership = result.unwrap();

    let owner = ownership["user"].clone().into_string().unwrap();
    let group = ownership["group"].clone().into_string().unwrap();

    let (actual_owner, actual_group) = get_current_user_and_group();

    assert_eq!(actual_owner, owner);
    assert_eq!(actual_group, group);

    temp.close().unwrap();
    Ok(())
}

/// Given: A directory and a user unauthorized for getting ownership
/// When: The get_ownership function is called
/// Then: An error is thrown from the safe_get_ownership function
#[test]
#[cfg(unix)]
fn test_get_ownership_error() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();

    // Create the temp dir outside of rhai so we can close it even if the rhai script fails
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let no_get_ownership_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [
                file_system::Action::"read",
                file_system::Action::"open"
            ],
            resource in file_system::Dir::"{temp_dir_path}"
        );
        
        forbid(
            principal == User::"{principal}",
            action in [
                file_system::Action::"stat"
            ],
            resource in file_system::Dir::"{temp_dir_path}"
        );
        "#
    );

    let auth = create_test_cedar_auth_with_policy(&no_get_ownership_policy);
    let engine = create_test_engine_with_auth(auth);

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path.clone());

    let result = engine.eval_with_scope::<rhai::Dynamic>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let ownership = dir_handle.get_ownership();
        "#,
    );

    let error_message = extract_error_message(&result.unwrap_err());
    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Stat
    );
    assert!(
        error_message.contains(&expected_error),
        "Expected error to contain '{}', but got: '{}'",
        expected_error,
        error_message
    );

    temp_dir.close().unwrap();
    Ok(())
}

/// NB: More thorough tests for this function will be implemented as REX integration tests.
/// Given: A valid file
/// When: The get_ownership function is called on the file
/// Then: The owner and group of the file are returned successfully
#[test]
#[cfg(unix)]
fn test_get_file_ownership_success() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let no_get_ownership_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [
                file_system::Action::"read",
                file_system::Action::"open"
            ],
            resource in file_system::Dir::"{temp_dir_path}"
        );
        permit(
            principal == User::"{principal}",
            action in [
                file_system::Action::"open",
                file_system::Action::"stat"
            ],
            resource is file_system::File in file_system::Dir::"{temp_dir_path}"
        );"#
    );

    let auth = create_test_cedar_auth_with_policy(&no_get_ownership_policy);
    let engine = create_test_engine_with_auth(auth);

    let test_file = "test_file.txt";
    temp.child(test_file).write_str("test content").unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("test_file", test_file);

    let ownership = engine.eval_with_scope::<rhai::Map>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file(test_file, OpenFileOptions().read(true).build());
            let ownership = file_handle.get_ownership();
            #{
                "user": ownership.user,
                "group": ownership.group
            }
        "#,
    )?;

    let owner = ownership["user"].clone().into_string().unwrap();
    let group = ownership["group"].clone().into_string().unwrap();

    assert!(!owner.is_empty(), "Owner should not be empty");
    assert!(!group.is_empty(), "Group should not be empty");

    temp.close().unwrap();
    Ok(())
}

/// Given: A file and a user unauthorized for getting ownership
/// When: The get_ownership function is called on the file
/// Then: An error is thrown from the safe_get_ownership function
#[test]
#[cfg(unix)]
fn test_get_file_ownership_error() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let no_get_ownership_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [
                file_system::Action::"read",
                file_system::Action::"open"
            ],
            resource in file_system::Dir::"{temp_dir_path}"
        );
        permit(
            principal == User::"{principal}",
            action in [
                file_system::Action::"open"
            ],
            resource is file_system::File in file_system::Dir::"{temp_dir_path}"
        );
        
        forbid(
            principal == User::"{principal}",
            action in [
                file_system::Action::"stat"
            ],
            resource is file_system::File in file_system::Dir::"{temp_dir_path}"
        );"#
    );

    let auth = create_test_cedar_auth_with_policy(&no_get_ownership_policy);
    let engine = create_test_engine_with_auth(auth);

    let test_file = "test_file.txt";

    temp_dir.child(test_file).write_str("test content").unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("test_file", test_file);

    let result = engine.eval_with_scope::<rhai::Dynamic>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file(test_file, OpenFileOptions().read(true).build());
            let ownership = file_handle.get_ownership();
        "#,
    );

    let error_message = extract_error_message(&result.unwrap_err());
    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Stat
    );

    assert!(
        error_message.contains(&expected_error),
        "Expected error to contain '{}', but got: '{}'",
        expected_error,
        error_message
    );

    temp_dir.close().unwrap();
    Ok(())
}

/// NB: we can't create new users and groups in Rust integration tests because we don't have control over the test environment
/// More thorough testing will be performed in REX integration tests
/// Given: A valid directory
/// When: The set_ownership function is called with the current owning user and group
/// Then: The directory's ownership is set successfully
#[test]
#[cfg(unix)]
#[cfg(not(target_vendor = "apple"))]
fn test_set_dir_ownership_success() -> Result<(), Box<EvalAltResult>> {
    let (username, groupname) = get_current_user_and_group();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let policy = format!(
        r#"permit(
            principal == User::"{username}",
            action in [
                file_system::Action::"read",
                file_system::Action::"open",
                file_system::Action::"chown"
            ],
            resource is file_system::Dir in file_system::Dir::"{temp_dir_path}"
        );"#
    );

    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("username", username);
    scope.push_constant("groupname", groupname);

    let result = engine.eval_with_scope::<rhai::Dynamic>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            dir_handle.set_ownership(SetOwnershipOptions().user(username).group(groupname).build());
        "#,
    );

    assert_with_registration_details(&result, || result.is_ok(), &engine, "set_ownership");

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: an unauthorized user
/// When: set_ownership is called on a directory
/// Then: an error is returned
#[test]
#[cfg(not(target_vendor = "apple"))]
fn test_set_dir_ownership_error() -> Result<(), Box<EvalAltResult>> {
    let (username, groupname) = get_current_user_and_group();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let policy = format!(
        r#"permit(
            principal == User::"{username}",
            action in [
                file_system::Action::"read",
                file_system::Action::"open"
            ],
            resource is file_system::Dir in file_system::Dir::"{temp_dir_path}"
        );
        forbid(
            principal == User::"{username}",
            action in [
                file_system::Action::"chown"
            ],
            resource is file_system::Dir in file_system::Dir::"{temp_dir_path}"
        );"#
    );

    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("username", username.clone());
    scope.push_constant("groupname", groupname);

    let result = engine.eval_with_scope::<rhai::Dynamic>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            dir_handle.set_ownership(SetOwnershipOptions().user(username).group(groupname).build());
        "#,
    );

    let error_message = extract_error_message(&result.unwrap_err());
    let expected_error = format!(
        "Permission denied: {username} unauthorized to perform {}",
        FilesystemAction::Chown
    );
    assert!(
        error_message.contains(&expected_error),
        "Expected error to contain '{}', but got: '{}'",
        expected_error,
        error_message
    );

    temp_dir.close().unwrap();
    Ok(())
}

/// NB: More thorough tests for this function will be implemented as REX integration tests.
/// Given: A valid file
/// When: The set_ownership function is called with the current owning user and group
/// Then: The file's ownership is set successfully
#[test]
#[cfg(unix)]
#[cfg(not(target_vendor = "apple"))]
fn test_set_file_ownership_success() -> Result<(), Box<EvalAltResult>> {
    let (username, groupname) = get_current_user_and_group();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let policy = format!(
        r#"permit(
            principal == User::"{username}",
            action in [
                file_system::Action::"read",
                file_system::Action::"open",
                file_system::Action::"chown"
            ],
            resource in file_system::Dir::"{temp_dir_path}"
        );"#
    );

    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let test_file = "test_file.txt";

    temp_dir.child(test_file).write_str("test content").unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("test_file", test_file);
    scope.push_constant("username", username);
    scope.push_constant("groupname", groupname);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file(test_file, OpenFileOptions().read(true).build());
            file_handle.set_ownership(SetOwnershipOptions().user(username).group(groupname).build());
        "#,
    );

    assert!(result.is_ok(), "err: {:?}", result.unwrap_err());

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A file and an unauthorized user
/// When: set_ownership is called on a file
/// Then: an error is returned
#[test]
#[cfg(not(target_vendor = "apple"))]
fn test_set_file_ownership_error() -> Result<(), Box<EvalAltResult>> {
    let (username, groupname) = get_current_user_and_group();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let policy = format!(
        r#"permit(
            principal == User::"{username}",
            action in [
                file_system::Action::"read",
                file_system::Action::"open"
            ],
            resource in file_system::Dir::"{temp_dir_path}"
        );
        forbid(
            principal == User::"{username}",
            action in [
                file_system::Action::"chown"
            ],
            resource is file_system::File in file_system::Dir::"{temp_dir_path}"
        );"#
    );

    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let test_file = "test_file.txt";

    temp_dir.child(test_file).write_str("test content").unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("test_file", test_file);
    scope.push_constant("username", username.clone());
    scope.push_constant("groupname", groupname);

    let result = engine.eval_with_scope::<rhai::Dynamic>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file(test_file, OpenFileOptions().read(true).build());
            file_handle.set_ownership(SetOwnershipOptions().user(username).group(groupname).build());
        "#,
    );

    let error_message = extract_error_message(&result.unwrap_err());
    let expected_error = format!(
        "Permission denied: {username} unauthorized to perform {}",
        FilesystemAction::Chown
    );

    assert!(
        error_message.contains(&expected_error),
        "Expected error to contain '{}', but got: '{}'",
        expected_error,
        error_message
    );

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A Rhai script that creates a file with or without custom permissions
/// When: The script is executed
/// Then: The file should be created with the expected permissions
#[rstest]
#[case::with_custom_permissions(Some(0o600), 0o600)]
#[case::with_default_permissions(None, 0o644)]
#[case::ignore_setuid_bits(Some(0o4755), 0o755)]
#[cfg(unix)]
fn test_create_file_permissions_from_rhai(
    #[case] permissions_option: Option<i64>,
    #[case] expected_permissions: u32,
) -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();

    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;
    let test_file = "permissions_test.txt";

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path.clone());
    scope.push_constant("test_file", test_file);

    let script = if let Some(perms) = permissions_option {
        scope.push_constant("permissions", perms);
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
                
            let file_handle = dir_handle.open_file(
                test_file, 
                OpenFileOptions()
                    .create(true)
                    .permissions(permissions)
                    .build()
            );
        "#
    } else {
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
                
            let file_handle = dir_handle.open_file(
                test_file, 
                OpenFileOptions()
                    .create(true)
                    .build()
            );
        "#
    };

    engine.eval_with_scope::<()>(&mut scope, script)?;

    let file_path = Path::new(&temp_dir_path).join(test_file);
    assert!(file_path.exists());

    let actual_mode = metadata(&file_path).map_err(to_eval_error)?.mode() & 0o777;

    // Default permissions can vary based on the system umask. Get the umask from the shell
    // and compute the expected default file permissions (0o666 & !umask).
    let effective_expected = if permissions_option.is_none() {
        let output = Command::new("sh")
            .args(["-c", "umask"])
            .output()
            .expect("Failed to run umask command");
        let umask_str = String::from_utf8(output.stdout).unwrap();
        let umask = u32::from_str_radix(umask_str.trim().trim_start_matches('0'), 8).unwrap();
        0o666 & !umask
    } else {
        expected_permissions
    };

    assert_eq!(actual_mode, effective_expected);

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A file that is a real file and an authorized user who is the owner
/// When: The file permissions are changed with chmod from Rhai
/// Then: The permissions are changed successfully
#[test]
#[cfg(unix)]
fn test_safe_chmod_file_permissions() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();
    let test_file = "permissions_test.txt";

    temp.child(test_file).touch().unwrap();
    let file_path = temp.path().join(test_file);

    let original_perms = metadata(&file_path).map_err(to_eval_error)?.mode() & 0o777;
    let new_perms: i64 = 0o600;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("test_file", test_file);
    scope.push_constant("new_perms", new_perms);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file(test_file, OpenFileOptions().read(true).build());
            file_handle.chmod(new_perms);
        "#,
    );

    assert_with_registration_details(&result, || result.is_ok(), &engine, "chmod");

    let actual_mode = metadata(&file_path).map_err(to_eval_error)?.mode() & 0o777;
    assert_ne!(original_perms, actual_mode);
    assert_eq!(actual_mode, new_perms as u32);

    Ok(())
}

/// Given: A file that exists and an attempt to set invalid permissions
/// When: The chmod function is called with permissions > 0o777
/// Then: An error is returned from the chmod function
#[test]
#[cfg(unix)]
fn test_safe_chmod_file_error() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;
    let test_file = "test_file.txt";

    let _file_path = create_and_write_to_test_file(&temp_dir, test_file).map_err(to_eval_error)?;

    let invalid_perms: i64 = 0o1000;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("test_file", test_file);
    scope.push_constant("invalid_perms", invalid_perms);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file(test_file, OpenFileOptions().read(true).build());
            file_handle.chmod(invalid_perms);
        "#,
    );

    assert!(result.is_err());
    assert_error_contains(result, INVALID_PERMISSIONS_ERR);

    Ok(())
}

/// Given: A directory that is a real directory and an authorized user who is the owner
/// When: The directory permissions are changed with chmod from Rhai
/// Then: The permissions are changed successfully
#[test]
#[cfg(unix)]
fn test_safe_chmod_dir_permissions() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    let original_perms = metadata(temp.path()).map_err(to_eval_error)?.mode() & 0o777;
    let new_perms: i64 = 0o600;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("new_perms", new_perms);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build()
                .open(OpenDirOptions().build());
            dir_handle.chmod(ChmodDirOptions().permissions(new_perms).build());
        "#,
    );

    assert_with_registration_details(&result, || result.is_ok(), &engine, "ChmodDir");

    let actual_mode = metadata(temp.path()).map_err(to_eval_error)?.mode() & 0o777;
    assert_ne!(original_perms, actual_mode);
    assert_eq!(actual_mode, new_perms as u32);

    Ok(())
}

/// Given: A directory that exists and an attempt to set invalid permissions
/// When: The chmod function is called with permissions > 0o777
/// Then: An error is returned from the chmod function
#[test]
#[cfg(unix)]
fn test_safe_chmod_dir_error() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let (_temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let invalid_perms: i64 = 0o1000;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("invalid_perms", invalid_perms);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build()
                .open(OpenDirOptions().build());
            dir_handle.chmod(ChmodDirOptions().permissions(invalid_perms).build());
        "#,
    );

    assert!(result.is_err());
    assert_error_contains(result, INVALID_PERMISSIONS_ERR);

    Ok(())
}

/// Given: A directory with subdirectories and files
/// When: The directory permissions are changed with recursive chmod from Rhai  
/// Then: The permissions are changed successfully on all items
#[test]
#[cfg(unix)]
fn test_safe_chmod_dir_recursive_permissions() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [
                file_system::Action::"open",
                file_system::Action::"chmod",
                file_system::Action::"read"
            ],
            resource in file_system::Dir::"{temp_dir_path}"
        );
        "#
    );
    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let subdir = temp_dir.child("subdir");
    subdir.create_dir_all().unwrap();

    let test_file = "test_file.txt";
    create_and_write_to_test_file(&temp_dir, test_file).map_err(to_eval_error)?;

    let file_path = temp_dir.child(test_file);
    let root_path = temp_dir.path();
    let subdir_path = subdir.path();

    let root_original_perms = metadata(root_path).map_err(to_eval_error)?.mode() & 0o777;
    let subdir_original_perms = metadata(subdir_path).map_err(to_eval_error)?.mode() & 0o777;
    let file_original_perms = metadata(file_path.path()).map_err(to_eval_error)?.mode() & 0o777;

    let new_perms: i64 = 0o700;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("new_perms", new_perms);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            dir_handle.chmod(ChmodDirOptions().permissions(new_perms).recursive(true).build());
        "#,
    );

    assert!(result.is_ok(), "err: {:?}", result.unwrap_err());

    let root_mode = metadata(root_path).map_err(to_eval_error)?.mode() & 0o777;
    let subdir_mode = metadata(subdir_path).map_err(to_eval_error)?.mode() & 0o777;
    let file_mode = metadata(file_path.path()).map_err(to_eval_error)?.mode() & 0o777;

    assert_ne!(root_mode, root_original_perms);
    assert_ne!(subdir_mode, subdir_original_perms);
    assert_ne!(file_mode, file_original_perms);

    assert_eq!(root_mode, new_perms as u32);
    assert_eq!(subdir_mode, new_perms as u32);
    assert_eq!(file_mode, new_perms as u32);

    Ok(())
}

/// Given: A file with multiple lines
/// When: read_lines is called with the count option
/// Then: The first N lines are returned as array
#[test]
fn test_rhai_read_lines_count_success() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    let test_content = (1..=15)
        .map(|i| format!("Line {}", i))
        .collect::<Vec<_>>()
        .join("\n");
    temp.child("test.txt").write_str(&test_content).unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result: rhai::Array = engine.eval_with_scope(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file("test.txt", OpenFileOptions().read(true).build());
            file_handle.read_lines(ReadLinesOptions().count(10).build());"#,
    )?;

    assert_eq!(result.len(), 10);
    assert_eq!(result[0].clone().cast::<String>(), "Line 1");
    assert_eq!(result[9].clone().cast::<String>(), "Line 10");

    Ok(())
}

/// Given: A file with multiple lines
/// When: read_lines is called via Rhai
/// Then: The last N lines are returned as array
#[test]
fn test_rhai_read_lines_last_lines_success() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    let test_content = (1..=15)
        .map(|i| format!("Line {}", i))
        .collect::<Vec<_>>()
        .join("\n");
    temp.child("test.txt").write_str(&test_content).unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result: rhai::Array = engine.eval_with_scope(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file("test.txt", OpenFileOptions().read(true).build());
            file_handle.read_lines(ReadLinesOptions().count(-2).build());"#,
    )?;

    assert_eq!(result.len(), 2);
    assert_eq!(result[0].clone().cast::<String>(), "Line 14");
    assert_eq!(result[1].clone().cast::<String>(), "Line 15");

    Ok(())
}

/// Given: A file with multiple lines
/// When: read_lines is called via Rhai
/// Then: All lines starting at line N is returned as an array
#[test]
fn test_rhai_read_lines_start_success() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    let test_content = (1..=15)
        .map(|i| format!("Line {}", i))
        .collect::<Vec<_>>()
        .join("\n");
    temp.child("test.txt").write_str(&test_content).unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result: rhai::Array = engine.eval_with_scope(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file("test.txt", OpenFileOptions().read(true).build());
            file_handle.read_lines(ReadLinesOptions().start(5).build());"#,
    )?;

    assert_eq!(result.len(), 11);
    assert_eq!(result[0].clone().cast::<String>(), "Line 5");
    assert_eq!(result[10].clone().cast::<String>(), "Line 15");

    Ok(())
}
/// Given: A negative line to start reading from
/// When: read_lines is called via Rhai
/// Then: A conversion error is returned (since start takes usize, negative values fail conversion)
#[test]
fn test_rhai_read_lines_negative_start_line() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    temp.child("test.txt")
        .write_str("Line 1\nLine 2\nLine 3")
        .unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<rhai::Array>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file("test.txt", OpenFileOptions().read(true).build());
            file_handle.read_lines(ReadLinesOptions().start(-1).build());"#,
    );

    assert!(result.is_err());
    // Negative values can't convert to usize, so conversion fails at the Rhai boundary
    assert_error_contains(result, "out of range integral type conversion attempted");

    Ok(())
}

/// Given: A file not opened with read permissions
/// When: read_lines is called via Rhai
/// Then: An error is returned with specific message
#[test]
fn test_rhai_read_lines_no_read_permission() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    temp.child("test.txt")
        .write_str("Line 1\nLine 2\nLine 3")
        .unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<rhai::Array>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file("test.txt", OpenFileOptions().write(true).build());
            file_handle.read_lines(ReadLinesOptions().count(5).build());"#,
    );

    assert!(result.is_err());
    assert_error_contains(result, READ_FILE_FLAG_ERR);

    Ok(())
}

/// Given: A file with multiple lines
/// When: read_page is called multiple times via Rhai
/// Then: each page returns the appropriate lines and EOF is handled appropriately.
#[test]
fn test_rhai_read_page_success() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    let test_content = (1..=12)
        .map(|i| format!("Line {}", i))
        .collect::<Vec<_>>()
        .join("\n");
    temp.child("test.txt").write_str(&test_content).unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result: rhai::Array = engine.eval_with_scope(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file("test.txt", OpenFileOptions().read(true).build());
            let lines = [];
            loop {
                let page = file_handle.read_page(ReadPageOptions().num_lines(5).build());
                if page.len() == 0 {
                    break;
                } else {
                    lines += page;
                }
            }
            lines"#
    )?;

    assert_eq!(result.len(), 12);
    assert_eq!(
        &result
            .into_iter()
            .map(|d| d.to_string())
            .collect::<Vec<String>>()
            .join("\n"),
        &test_content
    );

    Ok(())
}

/// Given: A file not opened with read permissions
/// When: read_page is called via Rhai
/// Then: An error is returned with specific message
#[test]
fn test_rhai_read_page_no_read_permission() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    temp.child("test.txt")
        .write_str("Line 1\nLine 2\nLine 3")
        .unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<rhai::Array>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file("test.txt", OpenFileOptions().write(true).build());
            file_handle.read_page(ReadPageOptions().num_lines(5).build());"#,
    );

    assert!(result.is_err());
    assert_error_contains(result, READ_FILE_FLAG_ERR);

    Ok(())
}

/// Given: A file with content containing specific patterns
/// When: The search method is called
/// Then: Returns the correct number of matches
#[test]
fn test_search_array_len() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;

    let config_content = "ssl = on\nport = 5432\nssl_cert = test\nmax_connections = 100";
    let file_name = "test.conf";
    let temp_dir_path =
        create_file_with_content(&temp, file_name, config_content).map_err(to_eval_error)?;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let len = engine.eval_with_scope::<i64>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file("test.conf", OpenFileOptions().read(true).build());
            
            let matches = file_handle.search("ssl");
            matches.len()
        "#
    )?;

    assert_eq!(len, 2, "Should find 2 matches for 'ssl'");

    Ok(())
}

/// Given: A file with content containing specific patterns
/// When: The search function is called with a regex pattern
/// Then: Returns correct matches with accurate line numbers and content
#[test]
fn test_search_basic_success() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;

    let postgres_config = r#"# PostgreSQL Configuration
listen_addresses = '*'
ssl = on
port = 5432
ssl_cert_file = 'server.crt'
ssl_key_file = 'server.key'
max_connections = 100
ssl_ciphers = 'HIGH:MEDIUM'"#;

    let file_name = "postgresql.conf";
    let temp_dir_path =
        create_file_with_content(&temp, file_name, postgres_config).map_err(to_eval_error)?;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let _matches = engine.eval_with_scope::<rhai::Array>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file("postgresql.conf", OpenFileOptions().read(true).build());
            
            let matches = file_handle.search("ssl");
            matches
        "#
    )?;

    let line1 =
        engine.eval_with_scope::<i64>(&mut scope, format!("matches[0].line_number",).as_str())?;
    let content1 = engine
        .eval_with_scope::<String>(&mut scope, format!("matches[0].line_content").as_str())?;

    assert_eq!(line1, 3, "First match should be on line 3");
    assert_eq!(content1, "ssl = on", "First match content mismatch");

    let line2 =
        engine.eval_with_scope::<i64>(&mut scope, format!("matches[1].line_number").as_str())?;
    let content2 = engine
        .eval_with_scope::<String>(&mut scope, format!("matches[1].line_content").as_str())?;

    assert_eq!(line2, 5, "Second match should be on line 5");
    assert_eq!(
        content2, "ssl_cert_file = 'server.crt'",
        "Second match content mismatch"
    );

    let line3 =
        engine.eval_with_scope::<i64>(&mut scope, format!("matches[2].line_number").as_str())?;
    let content3 = engine
        .eval_with_scope::<String>(&mut scope, format!("matches[2].line_content").as_str())?;

    assert_eq!(line3, 6, "Third match should be on line 6");
    assert_eq!(
        content3, "ssl_key_file = 'server.key'",
        "Third match content mismatch"
    );

    let line4 =
        engine.eval_with_scope::<i64>(&mut scope, format!("matches[3].line_number").as_str())?;
    let content4 = engine
        .eval_with_scope::<String>(&mut scope, format!("matches[3].line_content").as_str())?;

    assert_eq!(line4, 8, "Fourth match should be on line 8");
    assert_eq!(
        content4, "ssl_ciphers = 'HIGH:MEDIUM'",
        "Fourth match content mismatch"
    );

    Ok(())
}

/// Given: A file with content
/// When: The search function is called with an invalid regex pattern
/// Then: An error is returned
#[test]
fn test_search_invalid_regex_pattern() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;

    let config_content = "ssl = on\nport = 5432";
    let file_name = "regex_error.conf";
    let temp_dir_path =
        create_file_with_content(&temp, file_name, config_content).map_err(to_eval_error)?;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file("regex_error.conf", OpenFileOptions().read(true).build());
            
            let matches = file_handle.search("[invalid");
        "#
    );

    assert!(result.is_err());
    assert_error_contains(result, INVALID_REGEX_PATTERN_ERR);

    Ok(())
}

/// Given: A file that is a symlink to a real file
/// When: The read_link_target function is called
/// Then: The symlink is resolved and returns the target path
#[test]
fn test_read_link_target() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path = temp.path().to_string_lossy();

    let test_content = "This is the target file content";
    let real_file = temp.child("real_file.txt");
    real_file.write_str(test_content).unwrap();

    let link_file_name = "link_file";
    temp.child(link_file_name)
        .symlink_to_file(real_file.path())
        .unwrap();

    let mut scope = Scope::new();
    scope.push_constant("path", temp_dir_path.to_string());
    scope.push_constant("link_name", link_file_name);

    let result = engine.eval_with_scope::<String>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(path)
                .build().open(OpenDirOptions().build());

            // Resolve the symlink
            dir_handle.read_link_target(link_name)
        "#,
    );
    assert_with_registration_details(&result, || result.is_ok(), &engine, "read_link_target");
    let full_target_path = format!("{temp_dir_path}/real_file.txt");
    assert_eq!(result.unwrap(), full_target_path);

    Ok(())
}

/// Given: A file that is not a symlink
/// When: The read_link_target function is called
/// Then: An error is returned indicating the file is not a symlink
#[test]
fn test_read_link_target_not_a_symlink() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path = temp.path().to_string_lossy();

    let test_content = "This is the target file content";
    let real_file = temp.child("real_file.txt");
    real_file.write_str(test_content).unwrap();

    let mut scope = Scope::new();
    scope.push_constant("path", temp_dir_path.to_string());

    let result = engine.eval_with_scope::<String>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(path)
                .build().open(OpenDirOptions().build());

            // Resolve the symlink
            dir_handle.read_link_target("real_file.txt")
        "#,
    );

    assert_error_contains(result, "Invalid argument");
    Ok(())
}

/// Given: A source file with content and a destination file
/// When: The copy method is called with various options
/// Then: The content is copied correctly to the destination file
#[test]
fn test_copy_file_success() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [
                file_system::Action::"read",
                file_system::Action::"open",
                file_system::Action::"create",
                file_system::Action::"write"
            ],
            resource in file_system::Dir::"{temp_dir_path}"
        );
        "#
    );
    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let src_file = "src_file.txt";
    let content = get_rand_string();
    temp_dir.child(src_file).write_str(&content).unwrap();

    let dest_file = "dest_file.txt";

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("src_file", src_file);
    scope.push_constant("dest_file", dest_file);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());

            let src_file = dir_handle.open_file(src_file, OpenFileOptions().read(true).build());
            
            let dest_file = dir_handle.open_file(dest_file, OpenFileOptions().write(true).create(true).build());
            
            // Copy source to destination
            let copy_options = CopyFileOptions()
                .force(true)
                .preserve(true)
                .build();
                
            let copied_file = src_file.copy(dest_file, copy_options);
        "#,
    );

    assert_with_registration_details(&result, || result.is_ok(), &engine, "copy");

    let dest_content = read_file_contents(&temp_dir.path().to_string_lossy(), dest_file)?;
    assert_eq!(dest_content, content);

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A source file with content and a destination file that already exists with content
/// When: The copy method is called with force=false
/// Then: An error is returned
#[test]
fn test_copy_file_error_destination_not_empty() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [
                file_system::Action::"read",
                file_system::Action::"open",
                file_system::Action::"write"
            ],
            resource in file_system::Dir::"{temp_dir_path}"
        );"#
    );
    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let src_file = "src_file.txt";
    let content = get_rand_string();
    temp_dir.child(src_file).write_str(&content).unwrap();

    let dest_file = "dest.txt";
    let dest_content = get_rand_string();
    temp_dir.child(dest_file).write_str(&dest_content).unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("src_file", src_file);
    scope.push_constant("dest_file", dest_file);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
                
            let src_file = dir_handle.open_file(src_file, OpenFileOptions().read(true).build());
            
            let dest_file = dir_handle.open_file(dest_file, OpenFileOptions().write(true).build());
            
            let copy_options = CopyFileOptions()
                .force(false)
                .build();
                
            let copied_file = src_file.copy(dest_file, copy_options);
        "#,
    );

    assert!(result.is_err());
    assert_error_contains(result, DEST_FILE_NOT_EMPTY_ERR);

    let actual_dest_content = read_file_contents(&temp_dir.path().to_string_lossy(), dest_file)?;
    assert_eq!(actual_dest_content, dest_content);

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A source file opened without open file read option
/// When: The copy method is called
/// Then: An error is returned indicating read option are required
#[test]
fn test_copy_file_error_no_read_option() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [
                file_system::Action::"read",
                file_system::Action::"open",
                file_system::Action::"create",
                file_system::Action::"write"
            ],
            resource in file_system::Dir::"{temp_dir_path}"
        );"#
    );
    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let src_file = "src_file.txt";
    let content = get_rand_string();
    temp_dir.child(src_file).write_str(&content).unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("src_file", src_file);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
                
            let src_file = dir_handle.open_file(src_file, OpenFileOptions().write(true).build());
            
            let dest_file = dir_handle.open_file("dest.txt", OpenFileOptions().write(true).create(true).build());
            
            let copy_options = CopyFileOptions()
                .force(true)
                .build();
                
            let copied_file = src_file.copy(dest_file, copy_options);
        "#,
    );

    assert!(result.is_err());
    assert_error_contains(result, READ_FILE_FLAG_ERR);

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A gzipped file with content
/// When: read_gzip_lines is called via Rhai
/// Then: Lines are returned successfully
#[test]
fn test_rhai_read_gzip_lines_success() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [{}, {}, {}, {}],
            resource in file_system::Dir::"{temp_dir_path}"
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Read,
        FilesystemAction::Create,
        FilesystemAction::Write
    );
    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let content = "line1\nline2\nline3\n";
    temp_dir.child("source.txt").write_str(content).unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<i64>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());

            let source = dir_handle.open_file("source.txt", OpenFileOptions().read(true).build());
            let dest = dir_handle.open_file("source.txt.gz", OpenFileOptions().read(true).write(true).create(true).build());

            source.compress_gzip(dest, CompressGzipOptions().build());

            let lines = dest.read_gzip_lines(ReadLinesOptions().count(2).build());
            lines.len()
        "#,
    );

    assert_with_registration_details(&result, || result.is_ok(), &engine, "read_gzip_lines");
    assert_eq!(result.unwrap(), 2);

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A gzipped file opened without read permission
/// When: read_gzip_lines is called via Rhai
/// Then: An error is returned
#[test]
fn test_rhai_read_gzip_lines_no_read_permission() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [{}, {}, {}, {}],
            resource in file_system::Dir::"{temp_dir_path}"
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Read,
        FilesystemAction::Create,
        FilesystemAction::Write
    );
    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let content = "line1\nline2\n";
    temp_dir.child("source.txt").write_str(content).unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<i64>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());

            let source = dir_handle.open_file("source.txt", OpenFileOptions().read(true).build());
            let dest = dir_handle.open_file("source.txt.gz", OpenFileOptions().write(true).create(true).build());

            source.compress_gzip(dest, CompressGzipOptions().build());

            // Now open without read to trigger error
            let dest_no_read = dir_handle.open_file("source.txt.gz", OpenFileOptions().write(true).build());
            let lines = dest_no_read.read_gzip_lines(ReadLinesOptions().count(2).build());
            lines.len()
        "#,
    );

    assert!(result.is_err());
    assert_error_contains(result, READ_FILE_FLAG_ERR);

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A gzipped file
/// When: gzip_info is called via Rhai
/// Then: GzipInfo is returned with sizes
#[test]
fn test_rhai_gzip_info_success() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [{}, {}, {}, {}],
            resource in file_system::Dir::"{temp_dir_path}"
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Read,
        FilesystemAction::Create,
        FilesystemAction::Write
    );
    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let content = "Hello, gzip info test content!\n".repeat(10);
    temp_dir.child("source.txt").write_str(&content).unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<i64>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());

            let source = dir_handle.open_file("source.txt", OpenFileOptions().read(true).build());
            let dest = dir_handle.open_file("source.txt.gz", OpenFileOptions().read(true).write(true).create(true).build());

            source.compress_gzip(dest, CompressGzipOptions().build());

            let info = dest.gzip_info();
            info.uncompressed_size_bytes
        "#,
    );

    assert_with_registration_details(&result, || result.is_ok(), &engine, "gzip_info");
    assert_eq!(result.unwrap(), content.len() as i64);

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A gzipped file opened without read permission
/// When: gzip_info is called via Rhai
/// Then: An error is returned
#[test]
fn test_rhai_gzip_info_no_read_permission() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [{}, {}, {}, {}],
            resource in file_system::Dir::"{temp_dir_path}"
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Read,
        FilesystemAction::Create,
        FilesystemAction::Write
    );
    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    temp_dir.child("source.txt").write_str("content").unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<u64>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());

            let source = dir_handle.open_file("source.txt", OpenFileOptions().read(true).build());
            let dest = dir_handle.open_file("source.txt.gz", OpenFileOptions().write(true).create(true).build());

            source.compress_gzip(dest, CompressGzipOptions().build());

            // Open without read
            let dest_no_read = dir_handle.open_file("source.txt.gz", OpenFileOptions().write(true).build());
            let info = dest_no_read.gzip_info();
            info.compressed_size_bytes()
        "#,
    );

    assert!(result.is_err());
    assert_error_contains(result, READ_FILE_FLAG_ERR);

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A gzipped file with searchable content
/// When: search_gzip is called via Rhai
/// Then: Matching lines are returned
#[test]
fn test_rhai_search_gzip_success() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [{}, {}, {}, {}],
            resource in file_system::Dir::"{temp_dir_path}"
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Read,
        FilesystemAction::Create,
        FilesystemAction::Write
    );
    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let content = "line1 ERROR here\nline2 info\nline3 ERROR again\n";
    temp_dir.child("source.txt").write_str(content).unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<i64>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());

            let source = dir_handle.open_file("source.txt", OpenFileOptions().read(true).build());
            let dest = dir_handle.open_file("source.txt.gz", OpenFileOptions().read(true).write(true).create(true).build());

            source.compress_gzip(dest, CompressGzipOptions().build());

            let matches = dest.search_gzip("ERROR", SearchGzipOptions().build());
            matches.len()
        "#,
    );

    assert_with_registration_details(&result, || result.is_ok(), &engine, "search_gzip");
    assert_eq!(result.unwrap(), 2);

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A gzipped file
/// When: search_gzip is called with invalid regex
/// Then: An error is returned
#[test]
fn test_rhai_search_gzip_invalid_pattern() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [{}, {}, {}, {}],
            resource in file_system::Dir::"{temp_dir_path}"
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Read,
        FilesystemAction::Create,
        FilesystemAction::Write
    );
    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    temp_dir.child("source.txt").write_str("content").unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<i64>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());

            let source = dir_handle.open_file("source.txt", OpenFileOptions().read(true).build());
            let dest = dir_handle.open_file("source.txt.gz", OpenFileOptions().read(true).write(true).create(true).build());

            source.compress_gzip(dest, CompressGzipOptions().build());

            let matches = dest.search_gzip("[invalid(", SearchGzipOptions().build());
            matches.len()
        "#,
    );

    assert!(result.is_err());
    assert_error_contains(result, INVALID_REGEX_PATTERN_ERR);

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A gzipped file with searchable content
/// When: search_gzip_exists is called with matching pattern
/// Then: true is returned
#[test]
fn test_rhai_search_gzip_exists_found() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [{}, {}, {}, {}],
            resource in file_system::Dir::"{temp_dir_path}"
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Read,
        FilesystemAction::Create,
        FilesystemAction::Write
    );
    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let content = "info line\nERROR critical\nwarning line\n";
    temp_dir.child("source.txt").write_str(content).unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<bool>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());

            let source = dir_handle.open_file("source.txt", OpenFileOptions().read(true).build());
            let dest = dir_handle.open_file("source.txt.gz", OpenFileOptions().read(true).write(true).create(true).build());

            source.compress_gzip(dest, CompressGzipOptions().build());

            dest.search_gzip_exists("ERROR", SearchGzipOptions().build())
        "#,
    );

    assert_with_registration_details(&result, || result.is_ok(), &engine, "search_gzip_exists");
    assert!(result.unwrap());

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A gzipped file with content
/// When: search_gzip_exists is called with non-matching pattern
/// Then: false is returned
#[test]
fn test_rhai_search_gzip_exists_not_found() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [{}, {}, {}, {}],
            resource in file_system::Dir::"{temp_dir_path}"
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Read,
        FilesystemAction::Create,
        FilesystemAction::Write
    );
    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let content = "info line\nwarning line\n";
    temp_dir.child("source.txt").write_str(content).unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<bool>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());

            let source = dir_handle.open_file("source.txt", OpenFileOptions().read(true).build());
            let dest = dir_handle.open_file("source.txt.gz", OpenFileOptions().read(true).write(true).create(true).build());

            source.compress_gzip(dest, CompressGzipOptions().build());

            dest.search_gzip_exists("CRITICAL", SearchGzipOptions().build())
        "#,
    );

    assert_with_registration_details(&result, || result.is_ok(), &engine, "search_gzip_exists");
    assert!(!result.unwrap());

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A destination file opened without open file write option
/// When: The copy method is called
/// Then: An error is returned indicating write option are required
#[test]
fn test_copy_file_error_no_write_option() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [
                file_system::Action::"read",
                file_system::Action::"open",
                file_system::Action::"write"
            ],
            resource in file_system::Dir::"{temp_dir_path}"
        );"#
    );
    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let src_file = "src_file.txt";
    let content = get_rand_string();
    temp_dir.child(src_file).write_str(&content).unwrap();

    let dest_file = "dest.txt";
    temp_dir.child(dest_file).touch().unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("src_file", src_file);
    scope.push_constant("dest_file", dest_file);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
                
            let src_file = dir_handle.open_file(src_file, OpenFileOptions().read(true).build());
            
            let dest_file = dir_handle.open_file(dest_file, OpenFileOptions().read(true).build());
            
            let copy_options = CopyFileOptions()
                .force(true)
                .build();
                
            let copied_file = src_file.copy(dest_file, copy_options);
        "#,
    );

    assert!(result.is_err());
    assert_error_contains(result, WRITE_FILE_FLAG_ERR);

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A source file and Cedar policy that forbids read action
/// When: The copy method is called
/// Then: An authorization error is returned before file operations
#[test]
fn test_copy_file_error_cedar_forbid_read() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [
                file_system::Action::"open",
                file_system::Action::"write",
                file_system::Action::"create"
            ],
            resource in file_system::Dir::"{temp_dir_path}"
        );
        
        forbid(
            principal == User::"{principal}",
            action == file_system::Action::"read",
            resource in file_system::Dir::"{temp_dir_path}"
        );"#
    );
    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let src_file = "src_file.txt";
    let content = get_rand_string();
    temp_dir.child(src_file).write_str(&content).unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("src_file", src_file);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
                
            let src_file = dir_handle.open_file(src_file, OpenFileOptions().read(true).build());
            
            let dest_file = dir_handle.open_file("dest.txt", OpenFileOptions().write(true).create(true).build());
            
            let copy_options = CopyFileOptions()
                .force(true)
                .build();
                
            let copied_file = src_file.copy(dest_file, copy_options);
        "#,
    );

    assert!(result.is_err());
    let error_message = extract_error_message(&result.unwrap_err());
    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Read
    );
    assert!(
        error_message.contains(&expected_error),
        "Expected error to contain '{}', but got: '{}'",
        expected_error,
        error_message
    );

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A destination file and Cedar policy that forbids write action
/// When: The copy method is called
/// Then: An authorization error is returned before file operations
#[test]
fn test_copy_file_error_cedar_forbid_write() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [
                file_system::Action::"read",
                file_system::Action::"open"
            ],
            resource in file_system::Dir::"{temp_dir_path}"
        );
        
        forbid(
            principal == User::"{principal}",
            action == file_system::Action::"write",
            resource in file_system::Dir::"{temp_dir_path}"
        );"#
    );
    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let src_file = "src_file.txt";
    let content = get_rand_string();
    temp_dir.child(src_file).write_str(&content).unwrap();

    let dest_file = "dest.txt";
    temp_dir.child(dest_file).touch().unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("src_file", src_file);
    scope.push_constant("dest_file", dest_file);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
                
            let src_file = dir_handle.open_file(src_file, OpenFileOptions().read(true).build());
            
            let dest_file = dir_handle.open_file(dest_file, OpenFileOptions().write(true).build());
            
            let copy_options = CopyFileOptions()
                .force(true)
                .build();
                
            let copied_file = src_file.copy(dest_file, copy_options);
        "#,
    );

    assert!(result.is_err());
    let error_message = extract_error_message(&result.unwrap_err());
    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Write
    );

    assert!(
        error_message.contains(&expected_error),
        "Expected error to contain '{}', but got: '{}'",
        expected_error,
        error_message
    );

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A valid string
/// When: The replace_text() function is called with a regex pattern and replace_all=false
/// Then: Only the first match of the pattern is replaced in the string
#[test]
fn test_replace_text_success() -> Result<(), Box<EvalAltResult>> {
    let initial_content = "# Application Configuration 1.2.3\napp.name=MyApp\napp.version=v1.2.3\napi.version=v1.2.3\ndatabase.version=v1.2.3\nlogging.level=INFO";
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();
    scope.push_constant("initial_content", initial_content);

    engine.eval_with_scope::<()>(
	         &mut scope,
	         r#" 
	             // Replace only the first occurrence of version pattern "v\d+\.\d+\.\d+" with "v2.0.0"
	             let replacement_options = ReplacementOptions().is_regex(true).replace_all(false).build();
	             let modified_string = replace_text(initial_content, "v\\d+\\.\\d+\\.\\d+", "v2.0.0", replacement_options);
	         "#
	     )?;

    let content = engine.eval_with_scope::<String>(&mut scope, "modified_string")?;

    assert!(content.contains("# Application Configuration 1.2.3"));
    assert!(content.contains("app.version=v2.0.0"));
    assert!(content.contains("api.version=v1.2.3"));
    assert!(content.contains("database.version=v1.2.3"));

    Ok(())
}

/// Given: A valid string
/// When: The replace_text() function is called with an invalid regex pattern and replace_all=true
/// Then: The replacement fails and an error is thrown
#[test]
fn test_replace_text_invalid_regex_pattern() -> Result<(), Box<EvalAltResult>> {
    let initial_content = "# Application Configuration 1.2.3\napp.name=MyApp\napp.version=v1.2.3\napi.version=v1.2.3\ndatabase.version=v1.2.3\nlogging.level=INFO";
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();
    scope.push_constant("initial_content", initial_content);

    let result = engine.eval_with_scope::<()>(
	         &mut scope,
	         r#" 
	             // Replace only the first occurrence of version pattern "v\d+\.\d+\.\d+" with "v2.0.0"
	             let replacement_options = ReplacementOptions().is_regex(true).replace_all(true).build();
	             let modified_string = replace_text(initial_content, "[", "v2.0.0", replacement_options);
	         "#
	     );

    assert!(result.is_err());
    assert_error_contains(result, INVALID_REGEX_PATTERN_ERR);

    Ok(())
}

/// Given: A file that is a symlink to a real file within the same directory
/// When: The file is opened with follow_symlinks set to true
/// Then: The file is successfully read with the content of the target file
#[test]
#[cfg(target_os = "linux")]
fn test_reading_symlink_with_follow_symlinks() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path = temp.path().to_string_lossy();

    let test_content = "This is the target file content";
    let real_file = temp.child("real_file.txt");
    real_file.write_str(test_content).unwrap();

    let link_file_name = "link_file";
    temp.child(link_file_name)
        .symlink_to_file("real_file.txt")
        .unwrap();

    let mut scope = Scope::new();
    scope.push_constant("path", temp_dir_path.to_string());
    scope.push_constant("file", link_file_name);

    let output: String = engine.eval_with_scope(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(path)
                .build().open(OpenDirOptions().build());
                let file_handle = dir_handle.open_file(file, OpenFileOptions().read(true).follow_symlinks(true).build());
            file_handle.read();"#,
    )?;

    assert_eq!(output, test_content);

    temp.close().unwrap();
    Ok(())
}

/// Given: An absolute symlink pointing to a file in a different directory
/// When: The symlink is opened with follow_symlinks=true via Rhai
/// Then: The target file content is read successfully
#[test]
#[cfg(target_os = "linux")]
fn test_safe_open_file_follow_absolute_symlink_success() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;
    let (target_dir, _) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let target_content = "absolute symlink target content";
    let target_file = target_dir.child("abs_target.txt");
    target_file
        .write_str(target_content)
        .map_err(to_eval_error)?;
    let target_absolute_path = target_file.path().to_string_lossy().to_string();

    let symlink_file = temp_dir.child("abs_link");
    symlink_file
        .symlink_to_file(&target_absolute_path)
        .map_err(to_eval_error)?;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("target_content", target_content);

    let result = engine.eval_with_scope::<String>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file("abs_link", 
                OpenFileOptions().read(true).follow_symlinks(true).build());
            file_handle.read()
        "#,
    )?;

    assert_eq!(result, target_content);
    Ok(())
}

/// Given: A symlink chain (symlink -> symlink -> file) via Rhai
/// When: The first symlink is opened with follow_symlinks=true
/// Then: The final target file is accessed successfully
#[test]
#[cfg(target_os = "linux")]
fn test_safe_open_file_follow_symlink_chain() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let final_content = "end of symlink chain";
    let final_target = temp_dir.child("final_target.txt");
    final_target
        .write_str(final_content)
        .map_err(to_eval_error)?;

    let link2 = temp_dir.child("link2");
    link2
        .symlink_to_file("final_target.txt")
        .map_err(to_eval_error)?;

    let link1 = temp_dir.child("link1");
    link1.symlink_to_file("link2").map_err(to_eval_error)?;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("final_content", final_content);

    let result = engine.eval_with_scope::<String>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file("link1", 
                OpenFileOptions().read(true).follow_symlinks(true).build());
            file_handle.read()
        "#,
    )?;

    assert_eq!(result, final_content);
    Ok(())
}

/// Given: A symlink with unauthorized target file via Rhai
/// When: The symlink is opened with follow_symlinks=true
/// Then: Access is denied for the target file
#[test]
#[cfg(target_os = "linux")]
fn test_safe_open_file_follow_symlink_unauthorized_target() -> Result<(), Box<EvalAltResult>> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;
    let (target_dir, target_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let target_file = target_dir.child("restricted.txt");
    target_file
        .write_str("restricted content")
        .map_err(to_eval_error)?;
    let target_absolute_path = target_file.path().to_string_lossy().to_string();

    let symlink_file = temp_dir.child("link_to_restricted");
    symlink_file
        .symlink_to_file(&target_absolute_path)
        .map_err(to_eval_error)?;

    let principal = get_test_rex_principal();
    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [{}, {}],
            resource in file_system::Dir::"{temp_dir_path}"
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource in file_system::Dir::"{target_dir_path}" 
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Open,
        FilesystemAction::Open
    );

    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file("link_to_restricted", 
                OpenFileOptions().read(true).follow_symlinks(true).build());
        "#,
    );

    let error_message = extract_error_message(&result.unwrap_err());
    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {} for file_system::File::{target_absolute_path}",
        FilesystemAction::Open
    );
    assert!(
        error_message.contains(&expected_error),
        "Expected error to contain '{}', but got: '{}'",
        expected_error,
        error_message
    );

    Ok(())
}

/// Given: A symlink opened with follow_symlinks=true via Rhai
/// When: delete is called on the file handle
/// Then: The symlink itself is deleted, not the target (Unix rm behavior)
#[test]
#[cfg(target_os = "linux")]
fn test_safe_delete_symlink_deletes_symlink_not_target() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let target_content = "target to preserve";
    let target_file = temp_dir.child("preserve_target.txt");
    target_file
        .write_str(target_content)
        .map_err(to_eval_error)?;
    let target_absolute_path = target_file.path().to_string_lossy().to_string();

    let symlink_file = temp_dir.child("delete_link");
    symlink_file
        .symlink_to_file("preserve_target.txt")
        .map_err(to_eval_error)?;
    let symlink_absolute_path = symlink_file.path().to_string_lossy().to_string();

    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action == {},
            resource == file_system::Dir::"{temp_dir_path}"
        );
        permit(
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
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{target_absolute_path}"
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Open,
        FilesystemAction::Open,
        FilesystemAction::Delete,
        FilesystemAction::Delete
    );

    let auth = create_test_cedar_auth_with_policy(&test_policy);
    let engine = create_test_engine_with_auth(auth);

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file("delete_link", 
                OpenFileOptions().read(true).follow_symlinks(true).build());
            file_handle.delete(DeleteFileOptions().build());
        "#,
    );

    assert!(
        result.is_ok(),
        "Delete operation failed: {:?}",
        result.unwrap_err()
    );

    assert!(!symlink_file.exists(), "Expected symlink to be deleted");
    assert!(target_file.exists(), "Expected target file to be preserved");

    let preserved_content = read_to_string(target_file.path()).map_err(to_eval_error)?;
    assert_eq!(preserved_content, target_content);

    Ok(())
}

/// Given: A symlink opened with follow_symlinks=true via Rhai
/// When: chmod is called on the file handle
/// Then: The target file permissions are changed, not the symlink (Unix chmod behavior)
#[test]
#[cfg(target_os = "linux")]
fn test_safe_chmod_symlink_changes_target_permissions() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;
    let (target_dir, _) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let target_file = target_dir.child("chmod_target.txt");
    target_file
        .write_str("chmod test content")
        .map_err(to_eval_error)?;
    let target_absolute_path = target_file.path().to_string_lossy().to_string();

    let initial_perms = 0o644;
    set_permissions(&target_absolute_path, Permissions::from_mode(initial_perms))
        .map_err(to_eval_error)?;

    let symlink_file = temp_dir.child("chmod_link");
    symlink_file
        .symlink_to_file(&target_absolute_path)
        .map_err(to_eval_error)?;
    let symlink_path = symlink_file.path().to_string_lossy().to_string();

    let initial_symlink_metadata = fs::symlink_metadata(&symlink_path).map_err(to_eval_error)?;
    let initial_symlink_perms = initial_symlink_metadata.mode() & 0o777;

    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action == {},
            resource == file_system::Dir::"{temp_dir_path}"
        );
        permit(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{symlink_path}"
        );
        permit(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{target_absolute_path}"
        );
        permit(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{target_absolute_path}"
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{symlink_path}"
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Open,
        FilesystemAction::Open,
        FilesystemAction::Chmod,
        FilesystemAction::Chmod
    );

    let auth = create_test_cedar_auth_with_policy(&test_policy);
    let engine = create_test_engine_with_auth(auth);

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file("chmod_link", 
                OpenFileOptions().read(true).follow_symlinks(true).build());
            file_handle.chmod(0o600);
        "#,
    );

    assert!(
        result.is_ok(),
        "Chmod operation failed: {:?}",
        result.unwrap_err()
    );

    let target_metadata = metadata(&target_absolute_path).map_err(to_eval_error)?;
    let target_final_perms = target_metadata.mode() & 0o777;
    assert_eq!(target_final_perms, 0o600);

    let symlink_metadata = fs::symlink_metadata(&symlink_path).map_err(to_eval_error)?;
    let symlink_final_perms = symlink_metadata.mode() & 0o777;
    assert_eq!(symlink_final_perms, initial_symlink_perms);

    Ok(())
}

/// Given: A symlink pointing to a non-existent file via Rhai
/// When: The symlink is opened with follow_symlinks=true
/// Then: A file not found error is returned
#[test]
#[cfg(target_os = "linux")]
fn test_safe_open_file_follow_broken_symlink() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let broken_link = temp_dir.child("broken_link");
    broken_link
        .symlink_to_file("nonexistent.txt")
        .map_err(to_eval_error)?;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file("broken_link", 
                OpenFileOptions().read(true).follow_symlinks(true).build());
        "#,
    );

    assert_error_contains(result, FILE_DNE_ERR);
    Ok(())
}

/// Given: A circular symlink (link1 -> link2 -> link1) via Rhai
/// When: The symlink is opened with follow_symlinks=true
/// Then: A "too many symlinks" error is returned
#[test]
#[cfg(target_os = "linux")]
fn test_safe_open_file_follow_circular_symlink() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let link1 = temp_dir.child("circular1");
    let link2 = temp_dir.child("circular2");

    link1.symlink_to_file("circular2").map_err(to_eval_error)?;
    link2.symlink_to_file("circular1").map_err(to_eval_error)?;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file("circular1", 
                OpenFileOptions().read(true).follow_symlinks(true).build());
        "#,
    );

    assert_error_contains(result, TOO_MANY_SYMLINKS);
    Ok(())
}

/// Given: A symlink pointing to a directory via Rhai
/// When: The symlink is opened with follow_symlinks=true using open_file
/// Then: An error is returned because the target is not a file
#[test]
#[cfg(target_os = "linux")]
fn test_safe_open_file_symlink_to_directory() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let target_dir = temp_dir.child("target_directory");
    target_dir.create_dir_all().map_err(to_eval_error)?;

    let symlink_file = temp_dir.child("link_to_dir");
    symlink_file
        .symlink_to_dir(target_dir.path())
        .map_err(to_eval_error)?;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file("link_to_dir", 
                OpenFileOptions().read(true).follow_symlinks(true).build());
        "#,
    );

    assert_error_contains(result, "argument is not a file");
    Ok(())
}

/// Given: an open dir handle with 2 files and a subdirectory in it, and a user authorized to read the directory
/// When: list_entries is called on the directory
/// Then: the list of entries is returned and name, file type and inode are correct
#[test]
fn test_list_entries_success() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [{}, {}],
            resource in file_system::Dir::"{temp_dir_path}"
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Read
    );
    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let file1_name = "file1.txt";
    let file2_name = "file2.txt";
    temp_dir
        .child(file1_name)
        .write_str("file1 content")
        .unwrap();
    temp_dir
        .child(file2_name)
        .write_str("file2 content")
        .unwrap();

    let subdir_name = "subdir";
    let subdir = temp_dir.child(subdir_name);
    subdir.create_dir_all().unwrap();

    let file1_path = temp_dir.path().join(file1_name);
    let file2_path = temp_dir.path().join(file2_name);
    let subdir_path = temp_dir.path().join(subdir_name);

    #[cfg(unix)]
    let file1_inode = std::fs::metadata(&file1_path).unwrap().ino();
    #[cfg(unix)]
    let file2_inode = std::fs::metadata(&file2_path).unwrap().ino();
    #[cfg(unix)]
    let subdir_inode = std::fs::metadata(&subdir_path).unwrap().ino();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let entries = dir_handle.list_entries();
        "#,
    )?;

    // Check that all entries are present with corrent names
    let entries_len = engine.eval_with_scope::<i64>(&mut scope, "entries.len()")?;
    assert_eq!(entries_len, 3, "Expected 3 entries");

    let has_file1 = engine.eval_with_scope::<bool>(
        &mut scope,
        format!(r#"entries.contains("{}")"#, file1_name).as_str(),
    )?;
    let has_file2 = engine.eval_with_scope::<bool>(
        &mut scope,
        format!(r#"entries.contains("{}")"#, file2_name).as_str(),
    )?;
    let has_subdir = engine.eval_with_scope::<bool>(
        &mut scope,
        format!(r#"entries.contains("{}")"#, subdir_name).as_str(),
    )?;

    assert!(has_file1, "Missing file1 entry");
    assert!(has_file2, "Missing file2 entry");
    assert!(has_subdir, "Missing subdir entry");

    // Check file types
    let file1_type = engine.eval_with_scope::<EntryType>(
        &mut scope,
        format!(r#"entries["{}"].type()"#, file1_name).as_str(),
    )?;
    let file2_type = engine.eval_with_scope::<EntryType>(
        &mut scope,
        format!(r#"entries["{}"].type()"#, file2_name).as_str(),
    )?;
    let subdir_type = engine.eval_with_scope::<EntryType>(
        &mut scope,
        format!(r#"entries["{}"].type()"#, subdir_name).as_str(),
    )?;

    assert_eq!(file1_type, EntryType::File, "file1 should be a File");
    assert_eq!(file2_type, EntryType::File, "file2 should be a File");
    assert_eq!(subdir_type, EntryType::Dir, "subdir should be a Dir");

    // Check inodes on Unix systems
    #[cfg(unix)]
    {
        let file1_entry_inode = engine.eval_with_scope::<u64>(
            &mut scope,
            format!(r#"entries["{}"].inode"#, file1_name).as_str(),
        )?;
        let file2_entry_inode = engine.eval_with_scope::<u64>(
            &mut scope,
            format!(r#"entries["{}"].inode"#, file2_name).as_str(),
        )?;
        let subdir_entry_inode = engine.eval_with_scope::<u64>(
            &mut scope,
            format!(r#"entries["{}"].inode"#, subdir_name).as_str(),
        )?;

        assert_eq!(file1_entry_inode, file1_inode, "file1 inode mismatch");
        assert_eq!(file2_entry_inode, file2_inode, "file2 inode mismatch");
        assert_eq!(subdir_entry_inode, subdir_inode, "subdir inode mismatch");
    }

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: an open dir handle, and a user unauthorized to read the directory
/// When: list_entries is called on the directory
/// Then: an authorization error is returned
#[test]
fn test_list_entries_unauthorized() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [
                file_system::Action::"open"
            ],
            resource in file_system::Dir::"{temp_dir_path}"
        );
        
        forbid(
            principal == User::"{principal}",
            action == file_system::Action::"read",
            resource in file_system::Dir::"{temp_dir_path}"
        );"#
    );

    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let entries = dir_handle.list_entries();
        "#,
    );

    let error_message = extract_error_message(&result.unwrap_err());
    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Read
    );

    assert!(
        error_message.contains(&expected_error),
        "Expected error to contain '{}', but got: '{}'",
        expected_error,
        error_message
    );

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: An opened file handle and a user authorized to get metadata
/// When: metadata is called on the file handle
/// Then: the metadata is returned
#[test]
fn test_file_metadata_success() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [{}, {}, {}],
            resource in file_system::Dir::"{temp_dir_path}"
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Read,
        FilesystemAction::Stat
    );
    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let test_file = "metadata_test.txt";
    let test_content = "test content for metadata";
    temp.child(test_file).write_str(test_content).unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("test_file", test_file);

    let result = engine.eval_with_scope::<i64>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file(test_file, OpenFileOptions().read(true).build());
            let metadata = file_handle.metadata();
            metadata.file_size()
        "#,
    );

    assert!(result.is_ok(), "Failed to get metadata: {:?}", result.err());

    let file_size = result.unwrap();
    assert_eq!(file_size, test_content.len() as i64);

    temp.close().unwrap();
    Ok(())
}

/// Given: An opened file handle and a user unauthorized to get metadata
/// When: metadata is called on the file handle
/// Then: an authorization error is returned
#[test]
fn test_file_metadata_unauthorized() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [
                file_system::Action::"read",
                file_system::Action::"open"
            ],
            resource in file_system::Dir::"{temp_dir_path}"
        );
        
        forbid(
            principal == User::"{principal}",
            action == file_system::Action::"stat",
            resource is file_system::File in file_system::Dir::"{temp_dir_path}"
        );"#
    );

    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let test_file = "metadata_test.txt";
    temp.child(test_file).write_str("test content").unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("test_file", test_file);

    let result = engine.eval_with_scope::<rhai::Map>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file(test_file, OpenFileOptions().read(true).build());
            let metadata = file_handle.metadata();
            #{}
        "#,
    );

    assert!(result.is_err());
    let error_message = extract_error_message(&result.unwrap_err());
    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Stat
    );

    assert!(
        error_message.contains(&expected_error),
        "Expected error to contain '{}', but got: '{}'",
        expected_error,
        error_message
    );

    temp.close().unwrap();
    Ok(())
}

/// Given: An opened dir handle and a user authorized to get metadata
/// When: metadata is called on the dir handle
/// Then: the metadata is returned
#[test]
fn test_dir_metadata_success() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [{}, {}, {}],
            resource in file_system::Dir::"{temp_dir_path}"
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Read,
        FilesystemAction::Stat
    );
    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<bool>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let metadata = dir_handle.metadata();
            (metadata.permissions() & 0o40000) != 0  // Check if it's a directory using the mode bits
        "#,
    );

    assert_with_registration_details(&result, || result.is_ok(), &engine, "permissions");

    let is_dir = result.unwrap();
    assert!(
        is_dir,
        "Expected directory metadata to indicate it's a directory"
    );

    temp.close().unwrap();
    Ok(())
}

/// Given: An opened dir handle and a user unauthorized to get metadata
/// When: metadata is called on the dir handle
/// Then: an authorization error is returned
#[test]
fn test_dir_metadata_unauthorized() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [
                file_system::Action::"read",
                file_system::Action::"open"
            ],
            resource in file_system::Dir::"{temp_dir_path}"
        );
        
        forbid(
            principal == User::"{principal}",
            action == file_system::Action::"stat",
            resource is file_system::Dir in file_system::Dir::"{temp_dir_path}"
        );"#
    );

    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<rhai::Map>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let metadata = dir_handle.metadata();
            #{}
        "#,
    );

    assert!(result.is_err());
    let error_message = extract_error_message(&result.unwrap_err());
    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Stat
    );

    assert!(
        error_message.contains(&expected_error),
        "Expected error to contain '{}', but got: '{}'",
        expected_error,
        error_message
    );

    temp.close().unwrap();
    Ok(())
}

/// Given: A valid tar.gz archive with files and directories
/// When: extract_archive is called via Rhai with basic options
/// Then: The archive is extracted successfully and files are accessible
#[test]
#[cfg(unix)]
#[cfg(not(target_vendor = "apple"))]
fn test_extract_archive_success() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [{}, {}, {}, {}, {}, {}],
            resource in file_system::Dir::"/tmp"
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Read,
        FilesystemAction::Create,
        FilesystemAction::Write,
        FilesystemAction::Chmod,
        FilesystemAction::Chown
    );
    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let archive_name = "test_archive.tar.gz";

    create_test_archive(
        &temp_dir,
        archive_name,
        vec![
            ArchiveEntry::file("file1.txt", "Content of file 1"),
            ArchiveEntry::file("file2.txt", "Content of file 2"),
            ArchiveEntry::directory("subdir/"),
            ArchiveEntry::file("subdir/nested_file.txt", "Nested file content"),
        ],
    )
    .map_err(to_eval_error)?;

    let extract_dir_name = "extracted";
    let extract_dir_path = temp_dir.path().join(extract_dir_name);

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("archive_name", archive_name);
    scope.push_constant(
        "extract_dir_path",
        extract_dir_path.to_string_lossy().to_string(),
    );

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            
            let archive_file = dir_handle.open_file(archive_name, OpenFileOptions().read(true).build());
            
            let extract_dir = DirConfig()
                .path(extract_dir_path)
                .build().open(OpenDirOptions().create(true).recursive(true).build());
            
            let extract_options = ExtractArchiveOptions()
                .preserve_permissions(true)
                .preserve_timestamps(true)
                .build();
            
            archive_file.extract_archive(extract_dir, extract_options);
        "#,
    );

    assert_with_registration_details(&result, || result.is_ok(), &engine, "extract_archive");

    assert!(extract_dir_path.join("file1.txt").exists());
    assert!(extract_dir_path.join("file2.txt").exists());
    assert!(extract_dir_path.join("subdir").exists());
    assert!(extract_dir_path.join("subdir/nested_file.txt").exists());

    let file1_content = read_to_string(extract_dir_path.join("file1.txt")).unwrap();
    assert_eq!(file1_content, "Content of file 1");

    temp_dir.close().unwrap();
    Ok(())
}

// Given: A tar.gz archive and a user without read permission on the archive
/// When: extract_archive is called via Rhai
/// Then: An authorization error is returned
#[test]
#[cfg(unix)]
#[cfg(not(target_vendor = "apple"))]
fn test_extract_archive_unauthorized_read() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [{}, {}],
            resource in file_system::Dir::"/tmp"
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource is file_system::File in file_system::Dir::"/tmp"
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Create,
        FilesystemAction::Read
    );

    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let archive_name = "test_archive.tar.gz";
    create_test_archive(
        &temp_dir,
        archive_name,
        vec![ArchiveEntry::file("file1.txt", "Content of file 1")],
    )
    .map_err(to_eval_error)?;

    let extract_dir_path = temp_dir.path().join("extracted");

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("archive_name", archive_name);
    scope.push_constant(
        "extract_dir_path",
        extract_dir_path.to_string_lossy().to_string(),
    );

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            
            let archive_file = dir_handle.open_file(archive_name, OpenFileOptions().read(true).build());
            
            let extract_dir = DirConfig()
                .path(extract_dir_path)
                .build().open(OpenDirOptions().create(true).recursive(true).build());
            
            let extract_options = ExtractArchiveOptions().build();
            
            archive_file.extract_archive(extract_dir, extract_options);
        "#,
    );

    assert!(result.is_err());
    let error_message = extract_error_message(&result.unwrap_err());
    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Read
    );
    assert!(
        error_message.contains(&expected_error),
        "Expected error to contain '{}', but got: '{}'",
        expected_error,
        error_message
    );

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: An archive file opened without read open file option
/// When: extract_archive is called via Rhai
/// Then: An error is returned indicating read open file options is required
#[test]
#[cfg(unix)]
#[cfg(not(target_vendor = "apple"))]
fn test_extract_archive_no_read_option() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [{}, {}, {}],
            resource in file_system::Dir::"/tmp"
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Read,
        FilesystemAction::Create
    );
    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let archive_name = "test_archive.tar.gz";
    create_test_archive(
        &temp_dir,
        archive_name,
        vec![ArchiveEntry::file("file1.txt", "Content of file 1")],
    )
    .map_err(to_eval_error)?;

    let extract_dir_path = temp_dir.path().join("extracted");

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("archive_name", archive_name);
    scope.push_constant(
        "extract_dir_path",
        extract_dir_path.to_string_lossy().to_string(),
    );

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            
            // Open archive without read permission
            let archive_file = dir_handle.open_file(archive_name, OpenFileOptions().write(true).build());
            
            let extract_dir = DirConfig()
                .path(extract_dir_path)
                .build().open(OpenDirOptions().create(true).recursive(true).build());
            
            let extract_options = ExtractArchiveOptions().build();
            
            archive_file.extract_archive(extract_dir, extract_options);
        "#,
    );

    assert!(result.is_err());
    let error_message = extract_error_message(&result.unwrap_err());
    assert!(
        error_message.contains(READ_FILE_FLAG_ERR),
        "Expected error to contain '{}', but got: '{}'",
        READ_FILE_FLAG_ERR,
        error_message
    );

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A tar.gz archive with special file types (symlinks, devices, etc.)
/// When: extract_archive is called via Rhai
/// Then: Special file types are skipped and regular files are extracted
#[test]
#[cfg(unix)]
#[cfg(not(target_vendor = "apple"))]
fn test_extract_archive_skip_special_files() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [{}, {}, {}, {}],
            resource in file_system::Dir::"/tmp"
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Read,
        FilesystemAction::Write,
        FilesystemAction::Create
    );
    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let archive_name = "special.tar.gz";
    let content = "regular file content";

    create_test_archive(
        &temp_dir,
        archive_name,
        vec![
            ArchiveEntry::file("regular.txt", content),
            ArchiveEntry::special_file("symlink", tar::EntryType::Symlink),
            ArchiveEntry::special_file("chardev", tar::EntryType::Char),
        ],
    )
    .map_err(to_eval_error)?;

    let extract_dir_path = temp_dir.path().join("extracted");

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("archive_name", archive_name);
    scope.push_constant(
        "extract_dir_path",
        extract_dir_path.to_string_lossy().to_string(),
    );

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            
            let archive_file = dir_handle.open_file(archive_name, OpenFileOptions().read(true).build());
            
            let extract_dir = DirConfig()
                .path(extract_dir_path)
                .build().open(OpenDirOptions().create(true).recursive(true).build());
            
            let extract_options = ExtractArchiveOptions().build();
            
            archive_file.extract_archive(extract_dir, extract_options);
        "#,
    );

    assert!(
        result.is_ok(),
        "Archive extraction failed: {:?}",
        result.unwrap_err()
    );

    let regular_file = extract_dir_path.join("regular.txt");
    assert!(regular_file.exists());
    assert_eq!(read_to_string(regular_file).unwrap(), content);

    assert!(!extract_dir_path.join("symlink").exists());
    assert!(!extract_dir_path.join("chardev").exists());

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A tar.gz archive with files that already exist in destination
/// When: extract_archive is called via Rhai
/// Then: Files are overwritten with new content
#[test]
#[cfg(unix)]
#[cfg(not(target_vendor = "apple"))]
fn test_extract_archive_overwrite_files() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [{}, {}, {}, {}],
            resource in file_system::Dir::"/tmp"
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Read,
        FilesystemAction::Create,
        FilesystemAction::Write
    );
    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let archive_name = "overwrite_test.tar.gz";
    let new_content = "new content from archive";

    create_test_archive(
        &temp_dir,
        archive_name,
        vec![ArchiveEntry::file("existing_file.txt", new_content)],
    )
    .map_err(to_eval_error)?;

    let extract_dir_path = temp_dir.path().join("extracted");
    create_dir_all(&extract_dir_path).unwrap();

    let existing_file = extract_dir_path.join("existing_file.txt");
    write(&existing_file, "original content").unwrap();
    assert_eq!(read_to_string(&existing_file).unwrap(), "original content");

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("archive_name", archive_name);
    scope.push_constant(
        "extract_dir_path",
        extract_dir_path.to_string_lossy().to_string(),
    );

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            
            let archive_file = dir_handle.open_file(archive_name, OpenFileOptions().read(true).build());
            
            let extract_dir = DirConfig()
                .path(extract_dir_path)
                .build().open(OpenDirOptions().build());
            
            let extract_options = ExtractArchiveOptions().build();
            
            archive_file.extract_archive(extract_dir, extract_options);
        "#,
    );

    assert_with_registration_details(&result, || result.is_ok(), &engine, "extract_archive");

    let final_content = read_to_string(&existing_file).unwrap();
    assert_eq!(final_content, new_content);

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A tar.gz archive and unauthorized user for file operations during extraction
/// When: extract_archive is called via Rhai
/// Then: Extraction behavior varies based on the denied file operation
#[rstest]
#[case::create_denied(FilesystemAction::Create, false)]
#[case::write_denied(FilesystemAction::Write, false)]
#[case::chmod_denied(FilesystemAction::Chmod, true)]
#[case::chown_denied(FilesystemAction::Chown, true)]
#[cfg(unix)]
#[cfg(not(target_vendor = "apple"))]
fn test_extract_archive_unauthorized_file_operations(
    #[case] denied_action: FilesystemAction,
    #[case] file_should_exist: bool,
) -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;
    let (dest_dir, dest_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let archive_name = "test.tar.gz";
    create_test_archive(
        &temp_dir,
        archive_name,
        vec![ArchiveEntry::file("file1.txt", "content")],
    )
    .map_err(to_eval_error)?;

    let dest_file_path = format!("{}/file1.txt", dest_dir_path);
    let policy = format!(
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

    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("archive_name", archive_name);
    scope.push_constant("dest_dir_path", dest_dir_path);

    let rhai_script = if denied_action == FilesystemAction::Chmod
        || denied_action == FilesystemAction::Chown
    {
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            
            let archive_file = dir_handle.open_file(archive_name, OpenFileOptions().read(true).build());
            
            let extract_dir = DirConfig()
                .path(dest_dir_path)
                .build().open(OpenDirOptions().build());
            
            let extract_options = ExtractArchiveOptions()
                .preserve_permissions(true)
                .preserve_ownership(true)
                .build();
            
            archive_file.extract_archive(extract_dir, extract_options);
        "#
    } else {
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            
            let archive_file = dir_handle.open_file(archive_name, OpenFileOptions().read(true).build());
            
            let extract_dir = DirConfig()
                .path(dest_dir_path)
                .build().open(OpenDirOptions().build());
            
            let extract_options = ExtractArchiveOptions().build();
            
            archive_file.extract_archive(extract_dir, extract_options);
        "#
    };

    let result = engine.eval_with_scope::<()>(&mut scope, rhai_script);
    assert!(result.is_ok());

    let file_path = dest_dir.path().join("file1.txt");
    if file_should_exist {
        assert!(file_path.exists());
        assert_eq!(read_to_string(&file_path).unwrap(), "content");
    } else {
        assert!(!file_path.exists());
    }

    temp_dir.close().unwrap();
    dest_dir.close().unwrap();
    Ok(())
}

/// Given: A tar.gz archive and unauthorized user for directory operations during extraction
/// When: extract_archive is called via Rhai
/// Then: Extraction behavior varies based on the denied directory operation
#[rstest]
#[case::create_denied(FilesystemAction::Create, false)]
#[case::chmod_denied(FilesystemAction::Chmod, true)]
#[case::chown_denied(FilesystemAction::Chown, true)]
#[cfg(unix)]
#[cfg(not(target_vendor = "apple"))]
fn test_extract_archive_unauthorized_directory_operations(
    #[case] denied_action: FilesystemAction,
    #[case] dir_should_exist: bool,
) -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;
    let (dest_dir, dest_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let archive_name = "test.tar.gz";
    create_test_archive(
        &temp_dir,
        archive_name,
        vec![
            ArchiveEntry::directory("test_directory/"),
            ArchiveEntry::file("test_directory/file.txt", "content"),
        ],
    )
    .map_err(to_eval_error)?;

    let dest_directory_path = format!("{}/test_directory", dest_dir_path);
    let policy = format!(
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

    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("archive_name", archive_name);
    scope.push_constant("dest_dir_path", dest_dir_path);

    let rhai_script = if denied_action == FilesystemAction::Chmod
        || denied_action == FilesystemAction::Chown
    {
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            
            let archive_file = dir_handle.open_file(archive_name, OpenFileOptions().read(true).build());
            
            let extract_dir = DirConfig()
                .path(dest_dir_path)
                .build().open(OpenDirOptions().build());
            
            let extract_options = ExtractArchiveOptions()
                .preserve_permissions(true)
                .preserve_ownership(true)
                .build();
            
            archive_file.extract_archive(extract_dir, extract_options);
        "#
    } else {
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            
            let archive_file = dir_handle.open_file(archive_name, OpenFileOptions().read(true).build());
            
            let extract_dir = DirConfig()
                .path(dest_dir_path)
                .build().open(OpenDirOptions().build());
            
            let extract_options = ExtractArchiveOptions().build();
            
            archive_file.extract_archive(extract_dir, extract_options);
        "#
    };

    let result = engine.eval_with_scope::<()>(&mut scope, rhai_script);
    assert_with_registration_details(&result, || result.is_ok(), &engine, "extract_archive");

    let directory_path = dest_dir.path().join("test_directory");
    let file_path = directory_path.join("file.txt");

    if dir_should_exist {
        assert!(directory_path.exists() && directory_path.is_dir());
        assert!(file_path.exists());
        assert_eq!(read_to_string(&file_path).unwrap(), "content");
    } else {
        assert!(!directory_path.exists());
        assert!(!file_path.exists());
    }

    temp_dir.close().unwrap();
    dest_dir.close().unwrap();
    Ok(())
}

/// Given: A tar.gz archive with nested directories and authorization denied for intermediate directory
/// When: extract_archive is called via Rhai
/// Then: Warning is logged for directory creation failure but extraction continues
#[test]
#[cfg(unix)]
#[cfg(not(target_vendor = "apple"))]
fn test_extract_archive_nested_directory_creation_failure() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;
    let (dest_dir, dest_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let archive_name = "nested_dirs.tar.gz";
    create_test_archive(
        &temp_dir,
        archive_name,
        vec![ArchiveEntry::directory("parent/child/grandchild/")],
    )
    .map_err(to_eval_error)?;

    let intermediate_dir_path = format!("{}/parent/child", dest_dir_path);
    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [{}, {}],
            resource
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::Dir::"{intermediate_dir_path}"
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Read,
        FilesystemAction::Create
    );

    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("archive_name", archive_name);
    scope.push_constant("dest_dir_path", dest_dir_path);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            
            let archive_file = dir_handle.open_file(archive_name, OpenFileOptions().read(true).build());
            
            let extract_dir = DirConfig()
                .path(dest_dir_path)
                .build().open(OpenDirOptions().build());
            
            let extract_options = ExtractArchiveOptions().build();
            
            archive_file.extract_archive(extract_dir, extract_options);
        "#,
    );

    assert!(result.is_ok());

    let nested_dir = dest_dir.path().join("parent/child/grandchild");
    assert!(!nested_dir.exists());

    let parent_dir = dest_dir.path().join("parent");
    assert!(!parent_dir.exists());

    temp_dir.close().unwrap();
    dest_dir.close().unwrap();
    Ok(())
}

/// Given: A tar.gz archive with files and directories having specific permissions
/// When: extract_archive is called with preserve_permissions option via Rhai
/// Then: File and directory permissions are preserved or set to default based on the option
#[rstest]
#[case::preserve_true(true)]
#[case::preserve_false(false)]
#[cfg(unix)]
#[cfg(not(target_vendor = "apple"))]
fn test_extract_archive_preserve_permissions(
    #[case] preserve_permissions: bool,
) -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [{}, {}, {}, {}, {}],
            resource in file_system::Dir::"/tmp"
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Read,
        FilesystemAction::Create,
        FilesystemAction::Write,
        FilesystemAction::Chmod
    );
    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let archive_name = "permissions_test.tar.gz";
    let file_mode = 0o755;
    let dir_mode = 0o700;

    create_test_archive(
        &temp_dir,
        archive_name,
        vec![
            ArchiveEntry::file("executable.sh", "#!/bin/bash\necho hello").with_mode(file_mode),
            ArchiveEntry::directory("test_directory/").with_mode(dir_mode),
            ArchiveEntry::file("test_directory/nested_file.txt", "nested content")
                .with_mode(file_mode),
        ],
    )
    .map_err(to_eval_error)?;

    let extract_dir_path = temp_dir.path().join("extracted");

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("archive_name", archive_name);
    scope.push_constant(
        "extract_dir_path",
        extract_dir_path.to_string_lossy().to_string(),
    );
    scope.push_constant("preserve_permissions", preserve_permissions);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            
            let archive_file = dir_handle.open_file(archive_name, OpenFileOptions().read(true).build());
            
            let extract_dir = DirConfig()
                .path(extract_dir_path)
                .build().open(OpenDirOptions().create(true).recursive(true).build());
            
            let extract_options = ExtractArchiveOptions()
                .preserve_permissions(preserve_permissions)
                .build();
            
            archive_file.extract_archive(extract_dir, extract_options);
        "#,
    );

    assert!(
        result.is_ok(),
        "Archive extraction failed: {:?}",
        result.unwrap_err()
    );

    let extracted_file = extract_dir_path.join("executable.sh");
    let nested_file = extract_dir_path.join("test_directory/nested_file.txt");
    let extracted_dir = extract_dir_path.join("test_directory");

    assert!(extracted_file.exists());
    assert!(nested_file.exists());
    assert!(extracted_dir.exists() && extracted_dir.is_dir());

    let actual_file_mode = metadata(&extracted_file).unwrap().permissions().mode() & 0o777;
    let actual_nested_file_mode = metadata(&nested_file).unwrap().permissions().mode() & 0o777;
    let actual_dir_mode = metadata(&extracted_dir).unwrap().permissions().mode() & 0o777;

    if preserve_permissions {
        assert_eq!(
            actual_file_mode, file_mode,
            "File permissions should be preserved"
        );
        assert_eq!(
            actual_nested_file_mode, file_mode,
            "Nested file permissions should be preserved"
        );
        assert_eq!(
            actual_dir_mode, dir_mode,
            "Directory permissions should be preserved"
        );
    } else {
        assert_ne!(
            actual_file_mode, file_mode,
            "File permissions should be default"
        );
        assert_ne!(
            actual_nested_file_mode, file_mode,
            "Nested file permissions should be default"
        );
        assert_ne!(
            actual_dir_mode, dir_mode,
            "Directory permissions should be default"
        );
    }

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A tar.gz archive with files and directories having very old timestamps
/// When: extract_archive is called with preserve_timestamps option via Rhai
/// Then: Timestamps are preserved or set to current time based on the option
#[rstest]
#[case::preserve_true(true)]
#[case::preserve_false(false)]
#[cfg(unix)]
#[cfg(not(target_vendor = "apple"))]
fn test_extract_archive_preserve_timestamps(
    #[case] preserve_timestamps: bool,
) -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [{}, {}, {}, {}],
            resource in file_system::Dir::"/tmp"
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Read,
        FilesystemAction::Write,
        FilesystemAction::Create,
    );

    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let archive_name = "timestamps_test.tar.gz";
    let very_old_timestamp = 946684800;

    create_test_archive(
        &temp_dir,
        archive_name,
        vec![
            ArchiveEntry::file("timestamped_file.txt", "file content")
                .with_mtime(very_old_timestamp),
            ArchiveEntry::directory("timestamped_directory/").with_mtime(very_old_timestamp),
        ],
    )
    .map_err(to_eval_error)?;

    let extract_dir_path = temp_dir.path().join("extracted");

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("archive_name", archive_name);
    scope.push_constant(
        "extract_dir_path",
        extract_dir_path.to_string_lossy().to_string(),
    );
    scope.push_constant("preserve_timestamps", preserve_timestamps);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            
            let archive_file = dir_handle.open_file(archive_name, OpenFileOptions().read(true).build());
            
            let extract_dir = DirConfig()
                .path(extract_dir_path)
                .build().open(OpenDirOptions().create(true).recursive(true).build());
            
            let extract_options = ExtractArchiveOptions()
                .preserve_timestamps(preserve_timestamps)
                .build();
            
            archive_file.extract_archive(extract_dir, extract_options);
        "#,
    );

    assert!(result.is_ok());

    let extracted_file = extract_dir_path.join("timestamped_file.txt");
    let extracted_dir = extract_dir_path.join("timestamped_directory");

    assert!(extracted_file.exists());
    assert!(extracted_dir.exists() && extracted_dir.is_dir());

    let file_metadata = metadata(&extracted_file).unwrap();
    let dir_metadata = metadata(&extracted_dir).unwrap();

    let file_mtime = file_metadata.modified().unwrap();
    let dir_mtime = dir_metadata.modified().unwrap();

    let very_old_time = UNIX_EPOCH + Duration::from_secs(very_old_timestamp);
    let year_2010 = UNIX_EPOCH + Duration::from_secs(1262304000);

    if preserve_timestamps {
        assert_eq!(file_mtime, very_old_time);
        assert_eq!(dir_mtime, very_old_time);
    } else {
        assert_ne!(file_mtime, very_old_time);
        assert_ne!(dir_mtime, very_old_time);
        assert!(file_mtime > year_2010);
        assert!(dir_mtime > year_2010);
    }

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A file with known content
/// When: The count method is called
/// Then: Returns correct line, word, and byte counts
#[test]
fn test_counts_success() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;

    let test_content = "line one\n line two \nline three\nline four";
    let temp_dir_path =
        create_file_with_content(&temp, "test.txt", test_content).map_err(to_eval_error)?;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file("test.txt", OpenFileOptions().read(true).build());
            let counts = file_handle.counts();
        "#,
    )?;

    let lines = engine.eval_with_scope::<i64>(&mut scope, "counts.line_count")?;
    let words = engine.eval_with_scope::<i64>(&mut scope, "counts.word_count")?;
    let bytes = engine.eval_with_scope::<i64>(&mut scope, "counts.byte_count")?;

    assert_eq!(lines, 3);
    assert_eq!(words, 8);
    assert_eq!(bytes, test_content.len() as i64);

    temp.close().unwrap();
    Ok(())
}

/// Given: A file not opened with read permissions
/// When: The count method is called
/// Then: An error is returned
#[test]
fn test_counts_no_read_permission() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;

    let test_content = "test content";
    let temp_dir_path =
        create_file_with_content(&temp, "test.txt", test_content).map_err(to_eval_error)?;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file("test.txt", OpenFileOptions().write(true).build());
            let counts = file_handle.counts();
        "#,
    );

    assert_error_contains(result, READ_FILE_FLAG_ERR);
    temp.close().unwrap();
    Ok(())
}

/// Given: A file with binary content containing printable strings
/// When: The extract_strings method is called
/// Then: Returns an array of printable strings that are at least 4 characters long
#[test]
fn test_extract_strings_success() -> Result<(), Box<EvalAltResult>> {
    let temp = create_temp_dir().map_err(to_eval_error)?;

    let test_content = "Hello\x01World\x02This\x03is\x04a\x05test\x06with\x07printable\x10and\x11unprintable\x08chars";
    let temp_dir_path =
        create_file_with_content(&temp, "test.txt", test_content).map_err(to_eval_error)?;

    let principal = get_test_rex_principal();
    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [{}, {}],
            resource in file_system::Dir::"{temp_dir_path}"
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Read
    );
    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let strings = engine.eval_with_scope::<rhai::Array>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file("test.txt", OpenFileOptions().read(true).build());
            file_handle.extract_strings();
        "#,
    )?;

    assert_eq!(strings.len(), 8);
    // Convert the `rhai::Array` to a standard Rust vector for easier assertions
    let strings_vec: Vec<String> = strings
        .iter()
        .map(|s| s.clone().into_string().unwrap())
        .collect();

    // Verify that only printable strings of at least 4 characters are returned
    let expected_included_strings = vec![
        "Hello",
        "World",
        "This",
        "test",
        "with",
        "printable",
        "unprintable",
        "chars",
    ];
    for string in expected_included_strings {
        assert!(strings_vec.contains(&string.to_string()));
    }

    // Verify that short strings are not returned
    let expected_excluded_strings = vec!["is", "a", "and"];
    for string in expected_excluded_strings {
        assert!(!strings_vec.contains(&string.to_string()));
    }

    temp.close().unwrap();
    Ok(())
}

/// Given: A file and a user unauthorized to read the file
/// When: The extract_strings method is called
/// Then: An authorization error is returned
#[test]
fn test_unauthorized_extract_strings() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [
                file_system::Action::"open"
            ],
            resource in file_system::Dir::"{temp_dir_path}"
        );
        
        forbid(
            principal == User::"{principal}",
            action == {},
            resource is file_system::File in file_system::Dir::"{temp_dir_path}"
        );"#,
        FilesystemAction::Read
    );

    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let test_file = "test_file.txt";
    temp_dir.child(test_file).write_str("test content").unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("test_file", test_file);

    let result = engine.eval_with_scope::<rhai::Array>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file(test_file, OpenFileOptions().read(true).build());
            file_handle.extract_strings();
        "#,
    );

    assert!(result.is_err());
    let error_message = extract_error_message(&result.unwrap_err());
    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Read
    );

    assert!(
        error_message.contains(&expected_error),
        "Expected error to contain '{}', but got: '{}'",
        expected_error,
        error_message
    );

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A file not opened with read permissions
/// When: The extract_strings method is called
/// Then: An error is returned indicating read permission is required
#[test]
fn test_extract_strings_no_read_permission() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;

    let test_content = "test content with printable strings";
    let temp_dir_path =
        create_file_with_content(&temp, "test.txt", test_content).map_err(to_eval_error)?;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<rhai::Array>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file("test.txt", OpenFileOptions().write(true).build());
            file_handle.extract_strings();
        "#,
    );

    assert_error_contains(result, READ_FILE_FLAG_ERR);
    temp.close().unwrap();
    Ok(())
}

/// Given: A source file with content and a destination directory
/// When: The file is moved using RhaiFileHandle::move_file
/// Then: The file is successfully moved to the destination with content intact
#[test]
fn test_rhai_move_file_success() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    let src_dir = temp.child("source");
    src_dir.create_dir_all().unwrap();

    let dest_dir = temp.child("dest");
    dest_dir.create_dir_all().unwrap();

    let test_file = "test_file.txt";
    let test_content = get_rand_string();
    src_dir.child(test_file).write_str(&test_content).unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let src_dir = DirConfig()
                .path(temp_dir_path + "/source")
                .build()
                .open(OpenDirOptions().build());
                
            let dest_dir = DirConfig()
                .path(temp_dir_path + "/dest")
                .build()
                .open(OpenDirOptions().build());
                
            let src_file = src_dir.open_file("test_file.txt", OpenFileOptions().read(true).build());
            
            let move_options = MoveOptions().backup(false).build();
            let moved_file = src_file.move(dest_dir, "moved_file.txt", move_options);
            
            let content = moved_file.read();
        "#,
    );

    assert_with_registration_details(&result, || result.is_ok(), &engine, "move");

    assert!(!src_dir.child(test_file).exists());

    assert!(dest_dir.child("moved_file.txt").exists());

    let moved_content = read_to_string(dest_dir.child("moved_file.txt").path()).unwrap();
    assert_eq!(moved_content, test_content);

    Ok(())
}

/// Given: A source file and a user without permission to move files
/// When: Attempting to move the file using RhaiFileHandle::move_dir
/// Then: An authorization error is returned and the file is not moved
#[test]
fn test_rhai_move_file_unauthorized() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let dest_filename = get_rand_string();
    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [
                file_system::Action::"open",
                file_system::Action::"read"
            ],
            resource
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource
        ) when {{
            context has destination && 
            context.destination has name && 
            context.destination.name == "{dest_filename}"
        }};"#,
        FilesystemAction::Move
    );

    let test_cedar_auth = create_test_cedar_auth_with_policy(&test_policy);
    let engine = create_test_engine_with_auth(test_cedar_auth);

    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    let src_dir = temp.child("source");
    src_dir.create_dir_all().unwrap();

    let dest_dir = temp.child("dest");
    dest_dir.create_dir_all().unwrap();

    let test_file = "test_file.txt";
    let test_content = "test content";
    src_dir.child(test_file).write_str(test_content).unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("dest_filename", dest_filename.clone());

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let src_dir = DirConfig()
                .path(temp_dir_path + "/source")
                .build()
                .open(OpenDirOptions().build());
                
            let dest_dir = DirConfig()
                .path(temp_dir_path + "/dest")
                .build()
                .open(OpenDirOptions().build());
                
            let src_file = src_dir.open_file("test_file.txt", OpenFileOptions().read(true).build());
            
            let move_options = MoveOptions().backup(false).build();
            let moved_file = src_file.move(dest_dir, dest_filename, move_options);
        "#,
    );

    assert!(result.is_err());
    let error_message = extract_error_message(&result.unwrap_err());
    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Move
    );
    assert!(
        error_message.contains(&expected_error),
        "Expected error to contain '{}', but got: '{}'",
        expected_error,
        error_message
    );

    let source_path = src_dir.child(test_file);
    assert!(
        source_path.exists(),
        "Source file should still exist after failed move"
    );

    Ok(())
}

/// Given: A non-existent source file
/// When: Attempting to move the file using RhaiFileHandle::move_file
/// Then: An error is returned indicating the file does not exist
#[test]
fn test_rhai_move_file_nonexistent_file() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    let src_dir = temp.child("source");
    src_dir.create_dir_all().unwrap();

    let dest_dir = temp.child("dest");
    dest_dir.create_dir_all().unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let src_dir = DirConfig()
                .path(temp_dir_path + "/source")
                .build()
                .open(OpenDirOptions().build());
                
            let dest_dir = DirConfig()
                .path(temp_dir_path + "/dest")
                .build()
                .open(OpenDirOptions().build());
                
            let src_file = src_dir.open_file("nonexistent_file.txt", OpenFileOptions().read(true).build());
        "#,
    );

    assert_error_contains(result, FILE_DNE_ERR);

    Ok(())
}

/// Given: A source directory and a user without permission to move directories
/// When: Attempting to move the directory using RhaiDirHandle::move_dir
/// Then: An authorization error is returned and the directory is not moved
#[test]
#[cfg(target_os = "linux")]
fn test_rhai_move_dir_unauthorized() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let dest_dirname = get_rand_string();
    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [
                file_system::Action::"open",
                file_system::Action::"read"
            ],
            resource
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource
        ) when {{
            context has destination && 
            context.destination has name && 
            context.destination.name == "{dest_dirname}"
        }};"#,
        FilesystemAction::Move
    );

    let test_cedar_auth = create_test_cedar_auth_with_policy(&test_policy);
    let engine = create_test_engine_with_auth(test_cedar_auth);

    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    let src_parent_dir = temp.child("src_parent");
    src_parent_dir.create_dir_all().unwrap();

    let source_dir = src_parent_dir.child("source_dir");
    source_dir.create_dir_all().unwrap();

    let dest_parent_dir = temp.child("dest_parent");
    dest_parent_dir.create_dir_all().unwrap();

    let test_file = "test_file.txt";
    let test_content = "test content";
    source_dir.child(test_file).write_str(test_content).unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("dest_dirname", dest_dirname.clone());

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let src_parent_dir = DirConfig()
                .path(temp_dir_path + "/src_parent")
                .build()
                .open(OpenDirOptions().build());

            let dest_parent_dir = DirConfig()
                .path(temp_dir_path + "/dest_parent")
                .build()
                .open(OpenDirOptions().build());

            let source_dir = DirConfig()
                .path(temp_dir_path + "/src_parent/source_dir")
                .build()
                .open(OpenDirOptions().build());

            let move_options = MoveOptions().build(); 

            let moved_dir = src_parent_dir.move(source_dir, dest_parent_dir, dest_dirname, move_options);
        "#,
    );
    assert!(result.is_err());
    let error_message = extract_error_message(&result.unwrap_err());
    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Move
    );
    assert!(
        error_message.contains(&expected_error),
        "Expected error to contain '{}', but got: '{}'",
        expected_error,
        error_message
    );

    let source_path = source_dir.path();
    assert!(
        source_path.exists(),
        "Source directory should still exist after failed move"
    );

    Ok(())
}

/// Given: A source directory with content and a destination parent directory
/// When: The directory is moved using RhaiDirHandle::move_dir
/// Then: The directory is successfully moved to the destination with content intact
#[test]
#[cfg(target_os = "linux")]
fn test_rhai_move_dir_success() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    let src_parent_dir = temp.child("src_parent");
    src_parent_dir.create_dir_all().unwrap();

    let source_dir = src_parent_dir.child("source_dir");
    source_dir.create_dir_all().unwrap();

    let test_file = "test_file.txt";
    let test_content = get_rand_string();
    source_dir
        .child(test_file)
        .write_str(&test_content)
        .unwrap();

    let dest_parent_dir = temp.child("dest_parent");
    dest_parent_dir.create_dir_all().unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let src_parent_dir = DirConfig()
                .path(temp_dir_path + "/src_parent")
                .build()
                .open(OpenDirOptions().build());

            let source_dir = DirConfig()
                .path(temp_dir_path + "/src_parent/source_dir")
                .build()
                .open(OpenDirOptions().build());

            let dest_parent_dir = DirConfig()
                .path(temp_dir_path + "/dest_parent")
                .build()
                .open(OpenDirOptions().build());

            let move_options = MoveOptions().build();

            let moved_dir = src_parent_dir.move(source_dir, dest_parent_dir, "moved_dir", move_options);
        "#,
    );

    assert_with_registration_details(&result, || result.is_ok(), &engine, "move");

    assert!(!source_dir.exists());

    let moved_dir = dest_parent_dir.child("moved_dir");
    assert!(moved_dir.exists());

    let moved_file = moved_dir.child(test_file);
    assert!(moved_file.exists());

    let moved_content = read_to_string(moved_file.path()).unwrap();
    assert_eq!(moved_content, test_content);

    Ok(())
}

/// Given: A file not opened with write permissions
/// When: The truncate method is called
/// Then: An error is returned
#[test]
#[cfg(target_os = "linux")]
fn test_truncate_fails() -> Result<(), Box<EvalAltResult>> {
    use rust_safe_io::error_constants::INVALID_SIZE;

    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;

    let test_content = "test content";
    let temp_dir_path =
        create_file_with_content(&temp, "test.txt", test_content).map_err(to_eval_error)?;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file("test.txt", OpenFileOptions().read(true).write(true).build());
            file_handle.truncate(TruncateOptions().size(-10).build());
        "#,
    );

    assert_error_contains(result, INVALID_SIZE);
    temp.close().unwrap();
    Ok(())
}

/// Given: A file that will be truncated
/// When: When truncation is attempted
/// Then: The file is truncated
#[test]
#[cfg(target_os = "linux")]
fn test_truncate_succeeds() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;

    let test_content = "test content";
    let temp_dir_path =
        create_file_with_content(&temp, "test.txt", test_content).map_err(to_eval_error)?;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file("test.txt", OpenFileOptions()
                .read(true)
                .write(true)
                .build());
            file_handle.truncate(TruncateOptions().size(10).build());
        "#,
    );

    assert_with_registration_details(&result, || result.is_ok(), &engine, "truncate");
    let metadata_res = fs::metadata(temp.join("test.txt"));
    assert_eq!(metadata_res.unwrap().len() as i64, 10);

    temp.close().unwrap();
    Ok(())
}

/// Given: A file that will be truncated
/// When: When truncation is attempted with a Kibibyte
/// Then: The file is truncated to the correct size
#[test]
#[cfg(target_os = "linux")]
fn test_truncate_format() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;

    let test_content = "test content";
    let temp_dir_path =
        create_file_with_content(&temp, "test.txt", test_content).map_err(to_eval_error)?;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file("test.txt", OpenFileOptions()
                .read(true)
                .write(true)
                .build());
            file_handle.truncate(TruncateOptions().size(20).format(SizeUnit::KIBIBYTES).build());
        "#,
    );

    assert!(result.is_ok(), "error: {}", result.unwrap_err());
    let metadata_res = fs::metadata(temp.join("test.txt"));
    assert_eq!(metadata_res.unwrap().len() as i64, 20 * 1024);

    temp.close().unwrap();
    Ok(())
}

/// Given: A directory handle and valid target/link names with authorized user
/// When: create_symlink is called via Rhai
/// Then: Symlink is created successfully
#[rstest]
#[case::relative_path("target.txt")]
#[case::absolute_path("/tmp")]
#[cfg(target_os = "linux")]
fn test_rhai_create_symlink_success(#[case] target: &str) -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [{}, {}],
            resource in file_system::Dir::"{temp_dir_path}"
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Create,
    );

    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("target", target.to_string());

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let symlink_options = CreateSymlinkOptions().force(false).build();
            dir_handle.create_symlink(target, "link.txt", symlink_options);
        "#,
    );

    assert!(result.is_ok(), "err: {:?}", result.unwrap_err());

    let link_path = temp_dir.path().join("link.txt");
    assert!(link_path.is_symlink());

    let target_path = read_link(&link_path).map_err(to_eval_error)?;
    assert_eq!(target_path, Path::new(target));

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A directory handle and unauthorized user to create symlinks
/// When: create_symlink is called via Rhai
/// Then: Access is denied for Create action
#[test]
#[cfg(target_os = "linux")]
fn test_rhai_create_symlink_unauthorized() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action == {},
            resource in file_system::Dir::"{temp_dir_path}"
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource in file_system::Dir::"{temp_dir_path}"
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Create
    );

    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let symlink_options = CreateSymlinkOptions().force(false).build();
            dir_handle.create_symlink("target.txt", "link.txt", symlink_options);
        "#,
    );

    assert!(result.is_err());
    let error_message = extract_error_message(&result.unwrap_err());
    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Create
    );
    assert!(
        error_message.contains(&expected_error),
        "Expected error to contain '{}', but got: '{}'",
        expected_error,
        error_message
    );

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A directory handle and user with Create but not Delete permission
/// When: create_symlink is called via Rhai with force=true on existing symlink
/// Then: Access is denied for Delete action
#[test]
#[cfg(target_os = "linux")]
fn test_rhai_unauthorized_create_symlink_delete_permission() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let existing_link = temp_dir.child("existing_link.txt");
    existing_link.symlink_to_file("target.txt").unwrap();

    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [{}, {}],
            resource in file_system::Dir::"{temp_dir_path}"
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource in file_system::Dir::"{temp_dir_path}"
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Create,
        FilesystemAction::Delete
    );

    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let symlink_options = CreateSymlinkOptions().force(true).build();
            dir_handle.create_symlink("target.txt", "existing_link.txt", symlink_options);
        "#,
    );

    assert!(result.is_err());
    let error_message = extract_error_message(&result.unwrap_err());
    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Delete
    );
    assert!(
        error_message.contains(&expected_error),
        "Expected error to contain '{}', but got: '{}'",
        expected_error,
        error_message
    );

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A directory handle with existing symlink and force flag combinations
/// When: create_symlink is called via Rhai with different force values
/// Then: Success varies based on force flag and atomic replacement occurs
#[rstest]
#[case::force_false_existing_fails(false, true)]
#[case::force_true_existing_succeeds(true, false)]
#[cfg(target_os = "linux")]
fn test_rhai_create_symlink_force_behavior(
    #[case] force: bool,
    #[case] should_fail: bool,
) -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [{}, {}, {}],
            resource in file_system::Dir::"{temp_dir_path}"
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Create,
        FilesystemAction::Delete,
    );

    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let existing_link = temp_dir.child("existing_link.txt");
    existing_link.symlink_to_file("old_target.txt").unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("force", force);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let symlink_options = CreateSymlinkOptions().force(force).build();
            dir_handle.create_symlink("new_target.txt", "existing_link.txt", symlink_options);
        "#,
    );

    let link_path = temp_dir.path().join("existing_link.txt");

    if should_fail {
        assert!(result.is_err());
        assert_error_contains(result, "File exists");

        assert!(link_path.is_symlink());
        let unchanged_target = read_link(&link_path).map_err(to_eval_error)?;
        assert_eq!(unchanged_target, Path::new("old_target.txt"));
    } else {
        assert_with_registration_details(&result, || result.is_ok(), &engine, "create_symlink");

        assert!(link_path.is_symlink());
        let updated_target = read_link(&link_path).map_err(to_eval_error)?;
        assert_eq!(updated_target, Path::new("new_target.txt"));
    }

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A directory tree containing subdirectories, files, a symlink and a FIFO pipe
/// When: safe_find is called with FindOptions and a callback that reads file contents
/// Then: The callback successfully reads files and collects their contents
#[test]
#[cfg(target_os = "linux")]
fn test_safe_find_with_read_callback_success() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [
                file_system::Action::"open",
                file_system::Action::"read",
                file_system::Action::"stat"
            ],
            resource in file_system::Dir::"{temp_dir_path}"
        );"#
    );
    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let file1_content = "Content of file 1";
    let file2_content = "Content of file 2";
    temp_dir
        .child("file1.txt")
        .write_str(file1_content)
        .unwrap();
    temp_dir
        .child("file2.txt")
        .write_str(file2_content)
        .unwrap();

    let subdir = temp_dir.child("subdir");
    subdir.create_dir_all().unwrap();
    let file3_content = "Content of nested file";
    subdir.child("nested.txt").write_str(file3_content).unwrap();

    temp_dir
        .child("symlink_file")
        .symlink_to_file("regular_file.txt")
        .unwrap();

    let fifo_name = "test_fifo";
    let fifo_path = temp_dir.path().join(fifo_name);

    Command::new("mkfifo")
        .arg(&fifo_path)
        .status()
        .expect("Failed to create FIFO");

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());

            let size_range = SizeRange::max_only(1000, SizeUnit::BYTES);
            let find_options = FindOptions()
                .name("*.txt")
                .size_range(size_range)
                .build();

            let file_contents = [];

            dir_handle.find(find_options, |entry| {
                if entry.type() == EntryType::FILE {
                    let file_handle = entry.open_as_file(OpenFileOptions().read(true).build());
                    let content = file_handle.read();
                    file_contents.push(#{
                        "name": entry.name,
                        "content": content
                    });
                }
                return ();
            });
        "#,
    );

    assert!(
        result.is_ok(),
        "safe_find with read callback failed: {:?}",
        result.unwrap_err()
    );

    let contents_len = engine.eval_with_scope::<i64>(&mut scope, "file_contents.len()")?;
    assert_eq!(contents_len, 3, "Should find 3 text files");

    let file1_found_content = engine.eval_with_scope::<String>(
        &mut scope,
        r#"file_contents.find(|item| item.name == "file1.txt").content"#,
    )?;
    assert_eq!(file1_found_content, file1_content);

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A directory with files and a Cedar policy forbidding chmod
/// When: safe_find is called with a callback that attempts chmod
/// Then: The callback fails with Callback Error for chmod action
#[test]
fn test_safe_find_callback_unauthorized_chmod() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [
                file_system::Action::"open",
                file_system::Action::"read",
                file_system::Action::"stat"
            ],
            resource in file_system::Dir::"{temp_dir_path}"
        );

        forbid(
            principal == User::"{principal}",
            action == file_system::Action::"chmod",
            resource in file_system::Dir::"{temp_dir_path}"
        );"#
    );
    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    temp_dir
        .child("test1.txt")
        .write_str("test content 1")
        .unwrap();
    temp_dir
        .child("test2.txt")
        .write_str("test content 2")
        .unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());

            let size_range = SizeRange::between(1, 100, SizeUnit::BYTES);
            let find_options = FindOptions()
                .regex("test.*\\.txt$")
                .size_range(size_range)
                .build();

            dir_handle.find(find_options, |entry| {
                if entry.type() == EntryType::FILE {
                    let file_handle = entry.open_as_file(OpenFileOptions().read(true).write(true).build());
                    // This chmod attempt should fail due to Cedar policy
                    let new_perms = 0o600;
                    file_handle.chmod(new_perms);
                }
                return ();
            });
        "#,
    );

    assert!(
        result.is_err(),
        "Expected chmod to be forbidden by Cedar policy"
    );

    assert_error_kind(&result, &RhaiSafeIoErrorKind::CallbackError);

    let expected_error = "Permission denied";
    assert_error_contains(result, expected_error);

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: FindOptions with mutually exclusive patterns (name and iname)
/// When: Building FindOptions via Rhai script
/// Then: Should return validation error for mutually exclusive patterns
#[test]
fn test_rhai_find_options_invalid_patterns() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    temp_dir
        .child("test.txt")
        .write_str("test content")
        .unwrap();
    temp_dir
        .child("TEST.txt")
        .write_str("TEST content")
        .unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            
            let find_options = FindOptions()
                .name("test")
                .iname("TEST")
                .build();
            
            let results = [];
            dir_handle.find(find_options, |entry| {
                results.push(entry.name);
            });
        "#,
    );

    assert!(result.is_err());
    assert_error_contains(
        result,
        "Only one of 'name', 'iname', or 'regex' can be specified",
    );

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: FindOptions with regex pattern and between size range filter
/// When: Calling find via Rhai script with these options
/// Then: Should return only matching files within the size range
#[test]
fn test_rhai_find_regex_with_between_size_filter() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    temp_dir
        .child("file1.txt")
        .write_str("small content")
        .unwrap();
    temp_dir
        .child("file2.txt")
        .write_str("medium content here")
        .unwrap();
    temp_dir
        .child("file3.log")
        .write_str("log content")
        .unwrap();
    temp_dir
        .child("large.txt")
        .write_str(&"x".repeat(2000))
        .unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<i64>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            
            let size_range = SizeRange::between(1, 100, SizeUnit::BYTES);
            let find_options = FindOptions()
                .regex(".*\\.txt$")
                .size_range(size_range)
                .build();
            
            let results = [];
            dir_handle.find(find_options, |entry| {
                results.push(entry.name);
            });
            
            results.len()
        "#,
    );

    assert!(
        result.is_ok(),
        "Find with regex and size filter failed: {:?}",
        result.err()
    );
    let count = result.unwrap();
    assert!(
        count >= 1,
        "Should find at least one .txt file within size range"
    );

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: FindOptions with max_only size range filter
/// When: Calling find via Rhai script with these options
/// Then: Should return only files under the maximum size
#[test]
fn test_rhai_find_max_only_size_range() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    temp_dir.child("small.txt").write_str("tiny").unwrap();
    temp_dir
        .child("medium.txt")
        .write_str("medium content here")
        .unwrap();
    temp_dir
        .child("large.txt")
        .write_str(&"x".repeat(200))
        .unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<i64>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            
            let size_range = SizeRange::max_only(50, SizeUnit::BYTES);
            let find_options = FindOptions()
                .size_range(size_range)
                .build();
            
            let results = [];
            dir_handle.find(find_options, |entry| {
                results.push(entry.name);
            });
            
            results.len()
        "#,
    );

    assert!(
        result.is_ok(),
        "Find with max_only size filter failed: {:?}",
        result.err()
    );
    let count = result.unwrap();
    assert!(count >= 1, "Should find at least one file under 50 bytes");

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: FindOptions with min_only size range filter
/// When: Calling find via Rhai script with these options
/// Then: Should return only files over the minimum size
#[test]
fn test_rhai_find_min_only_size_range() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    temp_dir.child("tiny.txt").write_str("x").unwrap();
    temp_dir
        .child("medium.txt")
        .write_str("medium content here")
        .unwrap();
    temp_dir
        .child("large.txt")
        .write_str(&"x".repeat(200))
        .unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<i64>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            
            let size_range = SizeRange::min_only(10, SizeUnit::BYTES);
            let find_options = FindOptions()
                .size_range(size_range)
                .build();
            
            let results = [];
            dir_handle.find(find_options, |entry| {
                results.push(entry.name);
            });
            
            results.len()
        "#,
    );

    assert!(
        result.is_ok(),
        "Find with min_only size filter failed: {:?}",
        result.err()
    );
    let count = result.unwrap();
    assert!(count >= 1, "Should find at least one file over 10 bytes");

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: SizeRange functions with invalid parameters (negative values, min > max)
/// When: Creating SizeRange instances and using them in FindOptions
/// Then: Validation errors should be returned for each error case
#[test]
fn test_size_range_validation_errors() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;
    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path.clone());

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            
            let size_range = SizeRange::min_only(-100, SizeUnit::BYTES);
            let find_options = FindOptions()
                .size_range(size_range)
                .build();
        "#,
    );
    assert!(result.is_err());
    assert_error_contains(result, "Size range minimum must be non-negative");

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let size_range = SizeRange::max_only(-50, SizeUnit::KILOBYTES);
            let find_options = FindOptions()
                .size_range(size_range)
                .build();
        "#,
    );
    assert!(result.is_err());
    assert_error_contains(result, "Size range maximum must be non-negative");

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let size_range = SizeRange::between(-10, 100, SizeUnit::BYTES);
            let find_options = FindOptions()
                .size_range(size_range)
                .build();
        "#,
    );
    assert!(result.is_err());
    assert_error_contains(result, "Size range minimum must be non-negative");

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let size_range = SizeRange::between(10, -100, SizeUnit::BYTES);
            let find_options = FindOptions()
                .size_range(size_range)
                .build();
        "#,
    );
    assert!(result.is_err());
    assert_error_contains(result, "Size range maximum must be non-negative");

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A directory tree with root + 5 levels of nested subdirectories, each containing text files with varying sizes
/// When: safe_find is called with FindOptions including min_depth, max_depth, name pattern, and SizeRange
/// Then: Only files within the specified depth range (2-4) and size constraints (10-100 bytes) are found
#[test]
fn test_rhai_find_with_min_max_depth_and_size_range() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    temp_dir.child("level1.txt").write_str("L1").unwrap();

    let subdir1 = temp_dir.child("subdir1");
    subdir1.create_dir_all().unwrap();
    subdir1
        .child("level2.txt")
        .write_str("Level 2 content")
        .unwrap(); // ~15 bytes

    let subdir2 = subdir1.child("subdir2");
    subdir2.create_dir_all().unwrap();
    subdir2
        .child("level3.txt")
        .write_str("Level 3 content here")
        .unwrap(); // ~20 bytes
    subdir2
        .child("large_file.txt")
        .write_str(&"x".repeat(200))
        .unwrap(); // ~200 bytes

    let subdir3 = subdir2.child("subdir3");
    subdir3.create_dir_all().unwrap();
    subdir3
        .child("level4.txt")
        .write_str("Level 4 content is here")
        .unwrap(); // ~23 bytes

    let subdir4 = subdir3.child("subdir5");
    subdir4.create_dir_all().unwrap();
    subdir4
        .child("level5.txt")
        .write_str("Level 5 content goes here")
        .unwrap(); // ~26 bytes

    let subdir5 = subdir4.child("subdir5");
    subdir5.create_dir_all().unwrap();
    subdir5
        .child("level6.txt")
        .write_str("Level 6 content")
        .unwrap(); // ~15 bytes

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<i64>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());

            let size_range = SizeRange::between(10, 100, SizeUnit::BYTES);
            let find_options = FindOptions()
                .name("*.txt")
                .min_depth(2)
                .max_depth(4)
                .size_range(size_range)
                .build();

            let results = [];
            dir_handle.find(find_options, |entry| {
                results.push(entry.name);
            });
            
            results.len()
        "#,
    );

    assert!(
        result.is_ok(),
        "Find operation failed: {:?}",
        result.unwrap_err()
    );

    let found_count = result.unwrap();
    assert_eq!(
        found_count, 3,
        "Expected to find exactly 3 files matching depth and size criteria"
    );

    let found_files = engine.eval_with_scope::<rhai::Array>(&mut scope, "results")?;
    let file_names: Vec<String> = found_files
        .iter()
        .map(|f| f.clone().into_string().unwrap())
        .collect();

    assert!(
        file_names.contains(&"level2.txt".to_string()),
        "Should find level2.txt"
    );
    assert!(
        file_names.contains(&"level3.txt".to_string()),
        "Should find level3.txt"
    );
    assert!(
        file_names.contains(&"level4.txt".to_string()),
        "Should find level4.txt"
    );

    temp_dir.close().unwrap();
    Ok(())
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
) -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let (symlink_temp_dir, _) = create_temp_dir_and_path().map_err(to_eval_error)?;
    let (target_temp_dir, _) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let target_root = target_temp_dir.child("target_root");
    target_root.create_dir_all().map_err(to_eval_error)?;
    let target_subdir = target_root.child("subdir");
    target_subdir.create_dir_all().map_err(to_eval_error)?;

    let test_content = "symlink path component content";
    create_file_with_content(&target_subdir.path(), "test_file.txt", test_content)
        .map_err(to_eval_error)?;

    let absolute_symlink = symlink_temp_dir.child("link_to_target");
    absolute_symlink
        .symlink_to_dir(target_root.path())
        .map_err(to_eval_error)?;

    let path_with_symlink = format!("{}/subdir", absolute_symlink.path().to_string_lossy());

    let mut scope = Scope::new();
    scope.push_constant("path_with_symlink", path_with_symlink);
    scope.push_constant("follow_symlinks", follow_symlinks);
    scope.push_constant("test_content", test_content);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(path_with_symlink)
                .build()
                .open(OpenDirOptions().follow_symlinks(follow_symlinks).build());
            
            let file_handle = dir_handle.open_file("test_file.txt", OpenFileOptions().read(true).build());
            let content = file_handle.read();
        "#,
    );

    if should_fail {
        assert_error_contains(result, expected_error);
    } else {
        assert!(result.is_ok());
        let content = engine.eval_with_scope::<String>(&mut scope, "content")?;
        assert_eq!(content, test_content);
    }

    Ok(())
}

/// When: safe_open is called with follow_symlinks=true
/// Then: The final target is resolved correctly and Aurora file is accessible
#[test]
#[cfg(target_os = "linux")]
fn test_safe_open_symlink_chain_success() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let (appbin_temp, _) = create_temp_dir_and_path().map_err(to_eval_error)?;
    let (appbin1_temp, _) = create_temp_dir_and_path().map_err(to_eval_error)?;
    let (versions_temp, _) = create_temp_dir_and_path().map_err(to_eval_error)?;

    // Create the final target directory structure: versions_temp/aurora-16.7.16.7.0.33723.0/share/postgresql/extension/apgdbcc--1.0.sql
    let final_target = versions_temp.child("aurora-16.7.16.7.0.33723.0");
    final_target.create_dir_all().map_err(to_eval_error)?;

    let share_dir = final_target
        .child("share")
        .child("postgresql")
        .child("extension");
    share_dir.create_dir_all().map_err(to_eval_error)?;

    let test_content = "-- Aurora extension SQL";
    create_file_with_content(&share_dir.path(), "apgdbcc--1.0.sql", test_content)
        .map_err(to_eval_error)?;

    // Create symlink chain 1: appbin1_temp/aurora-16.7.16.7.0.33723.0 -> versions_temp/aurora-16.7.16.7.0.33723.0
    let intermediate_link = appbin1_temp.child("aurora-16.7.16.7.0.33723.0");
    intermediate_link
        .symlink_to_dir(final_target.path())
        .map_err(to_eval_error)?;

    // 2. appbin_temp/aurora -> appbin1_temp/aurora-16.7.16.7.0.33723.0
    let main_link = appbin_temp.child("aurora");
    main_link
        .symlink_to_dir(intermediate_link.path())
        .map_err(to_eval_error)?;

    // Final filesystem structure: appbin_temp/aurora -> appbin1_temp/aurora-16.7.16.7.0.33723.0 -> versions_temp/aurora-16.7.16.7.0.33723.0/
    // When accessing appbin_temp/aurora/share/postgresql/extension/, it resolves to:
    // versions_temp/aurora-16.7.16.7.0.33723.0/share/postgresql/extension/
    let aurora_extension_path = format!(
        "{}/share/postgresql/extension",
        main_link.path().to_string_lossy()
    );

    let mut scope = Scope::new();
    scope.push_constant("aurora_extension_path", aurora_extension_path);

    let result = engine.eval_with_scope::<String>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(aurora_extension_path)
                .build()
                .open(OpenDirOptions().follow_symlinks(true).build());
            
            let file_handle = dir_handle.open_file("apgdbcc--1.0.sql", OpenFileOptions().read(true).build());
            file_handle.read()
        "#,
    )?;

    assert_eq!(result, test_content);
    Ok(())
}

/// Given: Symlink with different Cedar authorization scenarios
/// When: safe_open is called with follow_symlinks=true
/// Then: Authorization is checked on both symlink and target paths
#[test]
#[cfg(target_os = "linux")]
fn test_safe_open_symlink_unauthorized_target() -> Result<(), Box<EvalAltResult>> {
    let (source_temp_dir, _) = create_temp_dir_and_path().map_err(to_eval_error)?;
    let (target_temp_dir, _) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let target_dir = target_temp_dir.child("restricted_target");
    target_dir.create_dir_all().map_err(to_eval_error)?;
    let final_dir = target_dir.child("final_dir");
    final_dir.create_dir_all().map_err(to_eval_error)?;
    let target_absolute_path = target_dir.path().to_string_lossy().to_string();

    let symlink_dir = source_temp_dir.child("public_symlink");
    symlink_dir
        .symlink_to_dir(&target_absolute_path)
        .map_err(to_eval_error)?;
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

    let auth = create_test_cedar_auth_with_policy(&test_policy);
    let engine = create_test_engine_with_auth(auth);

    let mut scope = Scope::new();
    scope.push_constant("path_through_symlink", path_through_symlink);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(path_through_symlink)
                .build()
                .open(OpenDirOptions().follow_symlinks(true).build());
        "#,
    );

    let error_message = extract_error_message(&result.unwrap_err());
    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Open
    );

    assert!(
        error_message.contains(&expected_error),
        "Expected error to contain '{}', but got: '{}'",
        expected_error,
        error_message
    );

    Ok(())
}

/// Given: A circular symlink (symlink pointing to itself or creating a loop)
/// When: safe_open is called with follow_symlinks=true
/// Then: A TOO_MANY_SYMLINKS is returned due to too many levels of symbolic links
#[test]
#[cfg(target_os = "linux")]
fn test_safe_open_follow_symlinks_circular_link() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let (temp_dir, _) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let link1 = temp_dir.child("link1");
    let link2 = temp_dir.child("link2");

    link1.symlink_to_dir(link2.path()).map_err(to_eval_error)?;
    link2.symlink_to_dir(link1.path()).map_err(to_eval_error)?;

    let link1_path = link1.path().to_string_lossy().to_string();

    let mut scope = Scope::new();
    scope.push_constant("link1_path", link1_path);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(link1_path)
                .build()
                .open(OpenDirOptions().follow_symlinks(true).build());
        "#,
    );

    assert_error_contains(result, TOO_MANY_SYMLINKS);
    Ok(())
}

/// Given: An absolute symlink pointing to a regular file (not directory)
/// When: safe_open is called with follow_symlinks=true
/// Then: A directory open error is returned because O_DIRECTORY flag fails on file
#[test]
#[cfg(target_os = "linux")]
fn test_safe_open_symlink_to_file_error() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let (symlink_temp_dir, _) = create_temp_dir_and_path().map_err(to_eval_error)?;
    let (target_temp_dir, _) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let target_file_content = "file";
    create_file_with_content(
        &target_temp_dir.path(),
        "target_file.txt",
        target_file_content,
    )
    .map_err(to_eval_error)?;

    let target_file_path = target_temp_dir.path().join("target_file.txt");

    let symlink_to_file = symlink_temp_dir.child("link_to_file");
    symlink_to_file
        .symlink_to_file(target_file_path)
        .map_err(to_eval_error)?;

    let path_with_symlink = format!("{}/subdir", symlink_to_file.path().to_string_lossy());

    let mut scope = Scope::new();
    scope.push_constant("path_with_symlink", path_with_symlink);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(path_with_symlink)
                .build()
                .open(OpenDirOptions().follow_symlinks(true).build());
        "#,
    );

    assert_error_contains(result, NOT_A_DIR);
    Ok(())
}

/// Given: A directory with subdirectories and files
/// When: disk_usage is called with default options via Rhai
/// Then: Disk usage entries are returned and all getters work
#[test]
#[cfg(unix)]
fn test_disk_usage_success() {
    let engine = create_test_engine_and_register();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().unwrap();

    create_file_with_content(&temp_dir.path(), "file1.txt", "Content 1").unwrap();

    let subdir = temp_dir.child("subdir");
    subdir.create_dir_all().unwrap();
    create_file_with_content(&subdir.path(), "file2.txt", "Content 2").unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path.clone());

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build()
                .open(OpenDirOptions().build());
            
            let options = DiskUsageOptions().build();
            let entries = dir_handle.disk_usage(options).entries;
            
            let first = entries[0];
            let path_val = first.path;
            let size_val = first.size_bytes;
            let inode_val = first.inode_count;
            
        "#,
    );

    assert!(
        result.is_ok(),
        "disk_usage() should return valid disk usage entries: {:?}",
        result.unwrap_err()
    );
}

/// Given: A directory and a user unauthorized to access it
/// When: disk_usage is called via Rhai
/// Then: An authorization error is returned
#[test]
#[cfg(unix)]
fn test_disk_usage_unauthorized() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    create_file_with_content(&temp_dir.path(), "file.txt", "Content").map_err(to_eval_error)?;

    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action == {},
            resource == file_system::Dir::"{temp_dir_path}"
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::Dir::"{temp_dir_path}"
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Stat
    );

    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build()
                .open(OpenDirOptions().build());
            
            let options = DiskUsageOptions().build();
            let entries = dir_handle.disk_usage(options);
        "#,
    );

    assert!(result.is_err());
    let error_message = extract_error_message(&result.unwrap_err());
    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Stat
    );
    assert!(
        error_message.contains(&expected_error),
        "Expected error to contain '{}', but got: '{}'",
        expected_error,
        error_message
    );

    Ok(())
}

/// Given: A file with known content
/// When: disk_usage is called via Rhai with default options
/// Then: Disk usage entry is returned with correct size and inode count
#[test]
#[cfg(unix)]
fn test_file_disk_usage_success() {
    let engine = create_test_engine_and_register();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().unwrap();

    let file_content = "Test file content";
    create_file_with_content(&temp_dir.path(), "test.txt", file_content).unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path.clone());

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build()
                .open(OpenDirOptions().build());
            
            let file_handle = dir_handle.open_file("test.txt", OpenFileOptions().read(true).build());
            
            let options = DiskUsageOptions().build();
            let entry = file_handle.disk_usage(options);
            
            let path_val = entry.path;
            let size_val = entry.size_bytes;
            let inode_val = entry.inode_count;
            
        "#,
    );

    assert!(
        result.is_ok(),
        "file disk_usage() should return valid disk usage entry: {:?}",
        result.unwrap_err()
    );
}

/// Given: A file and a user unauthorized to access it
/// When: disk_usage is called via Rhai
/// Then: An authorization error is returned
#[test]
#[cfg(unix)]
fn test_file_disk_usage_unauthorized() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    create_file_with_content(&temp_dir.path(), "test.txt", "Content").map_err(to_eval_error)?;

    let test_file_path = format!("{}/test.txt", temp_dir_path);

    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action == {},
            resource == file_system::Dir::"{temp_dir_path}"
        );
        permit(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{test_file_path}"
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{test_file_path}"
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Open,
        FilesystemAction::Stat
    );

    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build()
                .open(OpenDirOptions().build());
            
            let file_handle = dir_handle.open_file("test.txt", OpenFileOptions().read(true).build());
            
            let options = DiskUsageOptions().build();
            let entries = file_handle.disk_usage(options);
        "#,
    );

    assert!(result.is_err());
    let error_message = extract_error_message(&result.unwrap_err());
    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Stat
    );
    assert!(
        error_message.contains(&expected_error),
        "Expected error to contain '{}', but got: '{}'",
        expected_error,
        error_message
    );

    Ok(())
}

/// Given: A directory with subdirectories
/// When: disk_usage is called with track_largest_subdir option via Rhai
/// Then: The largest_dir_handle is accessible and usable
#[test]
#[cfg(unix)]
fn test_disk_usage_track_largest_subdir() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let subdir1 = temp_dir.child("subdir1");
    subdir1.create_dir_all().unwrap();
    create_file_with_content(&subdir1.path(), "file1.txt", "Small").map_err(to_eval_error)?;

    let subdir2 = temp_dir.child("subdir2");
    subdir2.create_dir_all().unwrap();
    create_file_with_content(&subdir2.path(), "file2.txt", &"x".repeat(50))
        .map_err(to_eval_error)?;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path.clone());

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build()
                .open(OpenDirOptions().build());
            
            let options = DiskUsageOptions()
                .track_largest_subdir(true)
                .build();
            let result = dir_handle.disk_usage(options);
            
            let largest_subdir_handle = result.largest_subdir_handle;
            let metadata = largest_subdir_handle.metadata();
        "#,
    );

    assert!(
        result.is_ok(),
        "Should be able to access and use largest_dir_handle: {:?}",
        result.unwrap_err()
    );

    temp_dir.close().unwrap();
    Ok(())
}

fn setup_elf_info(
    binary_name: String,
    binary_path: Option<String>,
    script: &str,
    succeed: bool,
) -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;

    let test_content = "test content";
    let temp_dir_path =
        create_file_with_content(&temp, "test.txt", test_content).map_err(to_eval_error)?;

    let script_path = format!("{temp_dir_path}/{binary_name}");
    let binary_path =
        binary_path.unwrap_or_else(|| format!("tests/fixtures/elf_info/{binary_name}"));
    fs::copy(binary_path, &script_path).unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("binary_name", binary_name);

    let result = engine.eval_with_scope::<()>(&mut scope, script);
    if succeed {
        assert_with_registration_details(&result, || result.is_ok(), &engine, "elf_info");
    } else {
        assert_with_registration_details(&result, || result.is_err(), &engine, "elf_info");
    }
    result
}

/// Given: A gdb core dump
/// When: elf_info is called
/// Then: All functions available provide expected values
#[test]
#[cfg(target_os = "linux")]
fn test_elf_info_succeeds() -> Result<(), Box<EvalAltResult>> {
    let script = r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file(binary_name, OpenFileOptions().read(true).build());
            let elf_info = file_handle.elf_info();

            if elf_info.execfn != "/usr/bin/sleep" {
                throw `execfn: ${elf_info.execfn} did not match expected execfn`
            }
            if elf_info.platform != "x86_64" {
                throw `Platform: ${elf_info.platform} did not match expected platform`
            }
            if elf_info.interpreter != () {
                throw `Interpreter: ${elf_info.interpreter} expected to be empty`
            }
            if elf_info.is_64bit != true {
                throw `is_64bit: ${elf_info.is_64bit} did not match expected is_64bit value`
            }
        "#;

    let _ = setup_elf_info("core.3922".to_string(), None, script, true);
    Ok(())
}

/// Given: Binary (ls) that's not a core dump
/// When: elf_info is called
/// Then: All functions available provide expected values
#[test]
#[cfg(target_os = "linux")]
fn test_elf_info_non_coredump() -> Result<(), Box<EvalAltResult>> {
    let script = r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file(binary_name, OpenFileOptions().read(true).build());
            let elf_info = file_handle.elf_info();

            if elf_info.execfn != () {
                throw `execfn: '${elf_info.execfn}' was not null as expected`
            }
            if elf_info.platform != () {
                throw `platform: '${elf_info.platform}' was not null as expected`
            }
            if elf_info.interpreter == () {
                throw `interpreter: ${elf_info.interpreter} was empty for 'ls' when it should have an interpreter`
            }
        "#;

    let _ = setup_elf_info("ls".to_string(), Some("/bin/ls".to_string()), script, true);
    Ok(())
}

/// Given: Unknown MIME type
/// When: elf_info is called
/// Then: Script fails with an error
#[test]
#[cfg(target_os = "linux")]
fn test_elf_info_fails() -> Result<(), Box<EvalAltResult>> {
    let script = r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file(binary_name, OpenFileOptions().read(true).build());
            let elf_info = file_handle.elf_info();

            if elf_info.execfn != () {
                throw `execfn: '${elf_info.execfn}' was not null as expected`
            }
            if elf_info.platform != () {
                throw `platform: '${elf_info.platform}' was not null as expected`
            }
            if elf_info.interpreter == () {
                throw `interpreter: ${elf_info.interpreter} was empty for 'ls' when it should have an interpreter`
            }
        "#;
    let result = setup_elf_info("foo.tar".to_string(), None, script, false);
    assert_error_contains(result, "Validation error");
    Ok(())
}

/// Given: A directory with a symlink to a nested dir containing a file at depth 4
/// When: find is called with max depth=3 and follow_symlinks=true
/// Then: The file is accessible through the symlink but not through regular traversal
#[test]
#[cfg(target_os = "linux")]
fn test_find_symlink_provides_access_to_unreachable_target() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let deep_dir = temp_dir.child("deep");
    deep_dir.create_dir_all().unwrap();
    let deeper_dir = deep_dir.child("deeper");
    deeper_dir.create_dir_all().unwrap();
    let deepest_dir = deeper_dir.child("deepest");
    deepest_dir.create_dir_all().unwrap();
    let target_file = deepest_dir.child("target.txt");
    target_file.write_str("unreachable content").unwrap();

    let shortcut = temp_dir.child("shortcut");
    shortcut.symlink_to_dir(deepest_dir.path()).unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path.clone());

    let result = engine.eval_with_scope::<rhai::Array>(
        &mut scope,
        r#"
        let found_files = [];
        let dir_handle = DirConfig()
            .path(temp_dir_path)
            .build()
            .open(OpenDirOptions().build());

        let find_options = FindOptions()
            .max_depth(3)
            .follow_symlinks(true)
            .build();

        let found_files = [];

        dir_handle.find(find_options, |entry| {
            if entry.type() == EntryType::FILE {
                found_files.push(entry.name);
            }
        });
        found_files
    "#,
    )?;

    let found_files: Vec<String> = result
        .iter()
        .map(|s| s.clone().into_string().unwrap())
        .collect();

    assert_eq!(found_files.len(), 1);

    Ok(())
}

/// Given: A file with an invalid negative size parameter
/// When: The fallocate method is called
/// Then: An error is returned
#[test]
#[cfg(target_os = "linux")]
fn test_fallocate_fail() -> Result<(), Box<EvalAltResult>> {
    use rust_safe_io::error_constants::INVALID_LENGTH;

    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;

    let test_content = "test content";
    let temp_dir_path =
        create_file_with_content(&temp, "test.txt", test_content).map_err(to_eval_error)?;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file("test.txt", OpenFileOptions().read(true).write(true).build());
            file_handle.fallocate(FallocateOptions().length(-10).build());
        "#,
    );

    assert_error_contains(result, INVALID_LENGTH);
    temp.close().unwrap();
    Ok(())
}

/// Given: A file that will be preallocated
/// When: When fallocate is attempted
/// Then: The file is preallocated to the specified size
#[test]
#[cfg(target_os = "linux")]
fn test_fallocate_success() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;

    let test_content = "test content";
    let temp_dir_path =
        create_file_with_content(&temp, "test.txt", test_content).map_err(to_eval_error)?;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file("test.txt", OpenFileOptions()
                .read(true)
                .write(true)
                .build());
            file_handle.fallocate(FallocateOptions().length(1024).build());
        "#,
    );

    assert_with_registration_details(&result, || result.is_ok(), &engine, "fallocate");
    let metadata_res = fs::metadata(temp.join("test.txt"));
    assert!(metadata_res.unwrap().len() >= 1024);

    temp.close().unwrap();
    Ok(())
}

/// Given: A file that will be preallocated
/// When: When fallocate is attempted with a Kibibyte
/// Then: The file is preallocated to the correct size
#[test]
#[cfg(target_os = "linux")]
fn test_fallocate_format() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;

    let test_content = "test content";
    let temp_dir_path =
        create_file_with_content(&temp, "test.txt", test_content).map_err(to_eval_error)?;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file("test.txt", OpenFileOptions()
                .read(true)
                .write(true)
                .build());
            file_handle.fallocate(FallocateOptions().length(2).format(SizeUnit::KIBIBYTES).build());
        "#,
    );

    assert!(result.is_ok(), "error: {}", result.unwrap_err());
    let metadata_res = fs::metadata(temp.join("test.txt"));
    assert!(metadata_res.unwrap().len() >= 2 * 1024);

    temp.close().unwrap();
    Ok(())
}

/// Given: A source file with content and a destination file
/// When: compress_gzip is called via Rhai
/// Then: The file is compressed to gzip format
#[test]
#[cfg(target_os = "linux")]
fn test_safe_compress_gzip_success() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [{}, {}, {}, {}],
            resource in file_system::Dir::"{temp_dir_path}"
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Read,
        FilesystemAction::Create,
        FilesystemAction::Write
    );
    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let src_file = "source.txt";
    let content = "Test content for gzip compression";
    temp_dir.child(src_file).write_str(content).unwrap();

    let dest_file = "source.txt.gz";

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("src_file", src_file);
    scope.push_constant("dest_file", dest_file);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());

            let source = dir_handle.open_file(src_file, OpenFileOptions().read(true).build());
            let dest = dir_handle.open_file(dest_file, OpenFileOptions().write(true).create(true).build());

            let options = CompressGzipOptions()
                .level(6)
                .build();

            source.compress_gzip(dest, options);
        "#,
    );

    assert_with_registration_details(&result, || result.is_ok(), &engine, "compress_gzip");

    let dest_path = temp_dir.child(dest_file);
    assert!(dest_path.exists());
    assert!(dest_path.path().metadata().unwrap().len() > 0);

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A server certificate directly signed by root CA
/// When: verify_cert is called via Rhai
/// Then: Verification should succeed
#[test]
fn test_rhai_verify_cert_valid() -> Result<(), Box<EvalAltResult>> {
    let (mut scope, engine, temp_dir) = create_temp_test_env_with_cert_fixtures();

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            
            let server_fh = dir_handle.open_file("server-direct.pem", OpenFileOptions().read(true).build());
            let root_fh = dir_handle.open_file("root-ca.pem", OpenFileOptions().read(true).build());
            
            server_fh.verify_cert(root_fh);
        "#,
    );

    assert!(
        result.is_ok(),
        "Direct root signing should verify: {:?}",
        result.unwrap_err()
    );

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A self-signed server certificate verified against a different root CA
/// When: verify_cert is called via Rhai
/// Then: Verification should fail
#[test]
fn test_rhai_verify_cert_invalid() -> Result<(), Box<EvalAltResult>> {
    let (mut scope, engine, temp_dir) = create_temp_test_env_with_cert_fixtures();

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            
            let server_fh = dir_handle.open_file("self-signed-server.pem", OpenFileOptions().read(true).build());
            let root_fh = dir_handle.open_file("root-ca.pem", OpenFileOptions().read(true).build());
            
            server_fh.verify_cert(root_fh);
        "#,
    );

    assert!(
        result.is_err(),
        "Self-signed cert should not verify against different root"
    );
    assert_error_contains(result, "Certificate chain verification failed");

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A valid certificate chain (root -> intermediate -> server)
/// When: verify_cert_chain is called via Rhai
/// Then: Verification should succeed
#[test]
fn test_rhai_verify_cert_chain_valid() -> Result<(), Box<EvalAltResult>> {
    let (mut scope, engine, temp_dir) = create_temp_test_env_with_cert_fixtures();

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            
            let server_fh = dir_handle.open_file("server.pem", OpenFileOptions().read(true).build());
            let root_fh = dir_handle.open_file("root-ca.pem", OpenFileOptions().read(true).build());
            let intermediate_fh = dir_handle.open_file("intermediate-ca.pem", OpenFileOptions().read(true).build());
            
            server_fh.verify_cert_chain(root_fh, [intermediate_fh]);
        "#,
    );

    assert!(
        result.is_ok(),
        "Valid chain should verify: {:?}",
        result.unwrap_err()
    );

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: An empty certificate file
/// When: verify_cert_chain is called via Rhai
/// Then: Should return CertificateParseError
#[test]
fn test_rhai_verify_cert_chain_invalid() -> Result<(), Box<EvalAltResult>> {
    let (mut scope, engine, temp_dir) = create_temp_test_env_with_cert_fixtures();
    let temp_dir_path: String = std::fs::canonicalize(temp_dir.path())
        .unwrap()
        .to_string_lossy()
        .into();

    // Create empty server cert file for this negative test case
    fs::write(format!("{}/empty-server.pem", temp_dir_path), "").unwrap();

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            
            let server_fh = dir_handle.open_file("empty-server.pem", OpenFileOptions().read(true).build());
            let root_fh = dir_handle.open_file("root-ca.pem", OpenFileOptions().read(true).build());
            let intermediate_fh = dir_handle.open_file("intermediate-ca.pem", OpenFileOptions().read(true).build());
            
            server_fh.verify_cert_chain(root_fh, [intermediate_fh]);
        "#,
    );

    assert!(result.is_err(), "Empty cert should fail verification");
    assert_error_contains(result, "No certificates found");

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A source file not opened with read option
/// When: compress_gzip is called via Rhai
/// Then: An error is returned indicating read option is required
#[test]
#[cfg(target_os = "linux")]
fn test_unauthorized_safe_compress_gzip_read() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [{}, {}, {}, {}],
            resource in file_system::Dir::"{temp_dir_path}"
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Read,
        FilesystemAction::Create,
        FilesystemAction::Write
    );
    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let src_file = "source.txt";
    let content = "Test content for gzip compression";
    temp_dir.child(src_file).write_str(content).unwrap();

    let dest_file = "source.txt.gz";

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("src_file", src_file);
    scope.push_constant("dest_file", dest_file);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());

            // Open source file WITHOUT read option
            let source = dir_handle.open_file(src_file, OpenFileOptions().write(true).build());
            let dest = dir_handle.open_file(dest_file, OpenFileOptions().write(true).create(true).build());

            let options = CompressGzipOptions()
                .level(6)
                .build();

            source.compress_gzip(dest, options);
        "#,
    );

    assert!(result.is_err());
    assert_error_contains(result, READ_FILE_FLAG_ERR);

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A directory containing a symlink
/// When: open_symlink is called with proper authorization
/// Then: The symlink handle is successfully returned
#[test]
#[cfg(target_os = "linux")]
fn test_open_symlink_success() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let target_file = temp_dir.child("target.txt");
    target_file.write_str("target content").unwrap();

    let symlink = temp_dir.child("test_symlink");
    symlink.symlink_to_file("target.txt").unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let symlink_handle = dir_handle.open_symlink("test_symlink");
        "#,
    );

    assert_with_registration_details(&result, || result.is_ok(), &engine, "open_symlink");

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A symlink and unauthorized user
/// When: open_symlink is called without Open permission
/// Then: An authorization error is returned
#[test]
#[cfg(target_os = "linux")]
fn test_unauthorized_open_symlink() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let target_file = temp_dir.child("target.txt");
    target_file.write_str("target content").unwrap();

    let symlink = temp_dir.child("test_symlink");
    symlink.symlink_to_file("target.txt").unwrap();

    let symlink_path = symlink.path().to_string_lossy().to_string();

    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action,
            resource
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{symlink_path}"
        );"#,
        FilesystemAction::Open
    );

    let test_cedar_auth = create_test_cedar_auth_with_policy(&test_policy);
    let engine = create_test_engine_with_auth(test_cedar_auth);

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let symlink_handle = dir_handle.open_symlink("test_symlink");
        "#,
    );

    assert!(result.is_err());
    let error_message = extract_error_message(&result.unwrap_err());
    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Open
    );
    assert!(
        error_message.contains(&expected_error),
        "Expected error to contain '{}', but got: '{}'",
        expected_error,
        error_message
    );

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A valid symlink
/// When: The set_ownership function is called with the current owning user and group
/// Then: The symlink's ownership is set successfully
#[test]
#[cfg(target_os = "linux")]
fn test_set_symlink_ownership_success() -> Result<(), Box<EvalAltResult>> {
    let (username, groupname) = get_current_user_and_group();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let target_file = temp_dir.child("target.txt");
    target_file.write_str("target content").unwrap();

    let symlink = temp_dir.child("test_symlink");
    symlink.symlink_to_file("target.txt").unwrap();

    let policy = format!(
        r#"permit(
            principal == User::"{username}",
            action in [
                file_system::Action::"open",
                file_system::Action::"chown"
            ],
            resource in file_system::Dir::"{temp_dir_path}"
        );"#
    );

    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("username", username);
    scope.push_constant("groupname", groupname);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let symlink_handle = dir_handle.open_symlink("test_symlink");
            symlink_handle.set_ownership(SetOwnershipOptions().user(username).group(groupname).build());
        "#,
    );

    assert_with_registration_details(&result, || result.is_ok(), &engine, "set_ownership");

    temp_dir.close().unwrap();
    Ok(())
}

/// Returns true if SELinux is disabled, meaning tests that require SELinux should be skipped.
/// Runs `getenforce` command and checks if output is "Disabled".
fn should_skip_selinux_tests() -> bool {
    Command::new("/usr/sbin/getenforce")
        .output()
        .map(|output| {
            String::from_utf8(output.stdout)
                .unwrap_or_default()
                .trim()
                .eq_ignore_ascii_case("disabled")
        })
        .unwrap_or(true) // Skip if getenforce command fails (SELinux not installed)
}

/// Given: A file and an unauthorized user
/// When: `set_extended_attr` is called with SetXAttr action forbidden
/// Then: An error is returned indicating the user is unauthorized
#[test]
#[cfg(target_os = "linux")]
fn test_set_extended_attr_error() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let test_file = "test_file.txt";
    temp_dir.child(test_file).write_str("test content").unwrap();

    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [
                file_system::Action::"read",
                file_system::Action::"open"
            ],
            resource in file_system::Dir::"{temp_dir_path}"
        );
        
        forbid(
            principal == User::"{principal}",
            action == file_system::Action::"set_xattr",
            resource is file_system::File in file_system::Dir::"{temp_dir_path}"
        );"#
    );

    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("test_file", test_file);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file(test_file, OpenFileOptions().read(true).build());
            
            let options = SetXAttrOptions()
                .name("security.selinux")
                .selinux_type("test_type")
                .build();
            
            file_handle.set_extended_attr(options);
        "#,
    );

    assert!(result.is_err());
    let error_message = extract_error_message(&result.unwrap_err());
    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::SetXAttr
    );
    assert!(
        error_message.contains(&expected_error),
        "Expected error to contain '{}', but got: '{}'",
        expected_error,
        error_message
    );

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A file and an authorized user with SELinux enabled
/// When: `set_extended_attr` is called with security.selinux attribute
/// Then: The xattr type is successfully updated
#[test]
#[cfg(target_os = "linux")]
fn test_set_extended_attr_success() -> Result<(), Box<EvalAltResult>> {
    if should_skip_selinux_tests() {
        println!("Skipping SELinux xattr test - SELinux is disabled or not installed");
        return Ok(());
    }

    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let test_file = "test_file.txt";
    temp_dir.child(test_file).write_str("test content").unwrap();

    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [
                file_system::Action::"read",
                file_system::Action::"open",
                file_system::Action::"set_x_attr"
            ],
            resource in file_system::Dir::"{temp_dir_path}"
        );"#
    );

    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("test_file", test_file);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file(test_file, OpenFileOptions().read(true).build());
            
            let options = SetXAttrOptions()
                .name("security.selinux")
                .selinux_type("svirt_sandbox_file_t")
                .build();
            
            file_handle.set_extended_attr(options);
        "#,
    );

    assert!(
        result.is_ok(),
        "Expected success but got: {:?}",
        result.err()
    );

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A valid symlink
/// When: metadata is called on the symlink handle
/// Then: The symlink metadata is returned successfully including the target path
#[test]
#[cfg(target_os = "linux")]
fn test_symlink_metadata_success() -> Result<(), Box<EvalAltResult>> {
    let (username, _groupname) = get_current_user_and_group();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let target_file = temp_dir.child("target.txt");
    target_file.write_str("target content").unwrap();

    let symlink = temp_dir.child("test_symlink");
    symlink.symlink_to_file("target.txt").unwrap();

    let policy = format!(
        r#"permit(
            principal == User::"{username}",
            action in [
                file_system::Action::"open",
                file_system::Action::"stat",
                file_system::Action::"read"
            ],
            resource in file_system::Dir::"{temp_dir_path}"
        );"#
    );

    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let symlink_handle = dir_handle.open_symlink("test_symlink");
            let metadata = symlink_handle.metadata();
            let permissions = metadata.permissions();
            let symlink_target = metadata.symlink_target();
        "#,
    );

    assert_with_registration_details(&result, || result.is_ok(), &engine, "metadata");

    let symlink_target = engine.eval_with_scope::<String>(&mut scope, "symlink_target")?;
    assert_eq!(symlink_target, "target.txt");

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A symlink and an unauthorized user (missing stat permission)
/// When: metadata is called on the symlink handle
/// Then: An authorization error is returned
#[test]
#[cfg(target_os = "linux")]
fn test_symlink_metadata_unauthorized() -> Result<(), Box<EvalAltResult>> {
    let (username, _groupname) = get_current_user_and_group();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let target_file = temp_dir.child("target.txt");
    target_file.write_str("target content").unwrap();

    let symlink = temp_dir.child("test_symlink");
    symlink.symlink_to_file("target.txt").unwrap();

    let symlink_path = symlink.path().to_string_lossy().to_string();

    let policy = format!(
        r#"permit(
            principal == User::"{username}",
            action in [
                file_system::Action::"open",
                file_system::Action::"read"
            ],
            resource in file_system::Dir::"{temp_dir_path}"
        );
        forbid(
            principal == User::"{username}",
            action == file_system::Action::"stat",
            resource == file_system::File::"{symlink_path}"
        );"#
    );

    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let symlink_handle = dir_handle.open_symlink("test_symlink");
            let metadata = symlink_handle.metadata();
        "#,
    );

    assert!(result.is_err());
    let error_message = extract_error_message(&result.unwrap_err());
    let expected_error = format!(
        "Permission denied: {username} unauthorized to perform {}",
        FilesystemAction::Stat
    );
    assert!(
        error_message.contains(&expected_error),
        "Expected error to contain '{}', but got: '{}'",
        expected_error,
        error_message
    );

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A symlink and an unauthorized user
/// When: set_ownership is called on a symlink
/// Then: an error is returned
#[test]
#[cfg(target_os = "linux")]
fn test_set_symlink_ownership_error() -> Result<(), Box<EvalAltResult>> {
    let (username, groupname) = get_current_user_and_group();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let target_file = temp_dir.child("target.txt");
    target_file.write_str("target content").unwrap();

    let symlink = temp_dir.child("test_symlink");
    symlink.symlink_to_file("target.txt").unwrap();

    let symlink_path = symlink.path().to_string_lossy().to_string();

    let policy = format!(
        r#"permit(
            principal == User::"{username}",
            action in [
                file_system::Action::"read",
                file_system::Action::"open"
            ],
            resource in file_system::Dir::"{temp_dir_path}"
        );
        forbid(
            principal == User::"{username}",
            action in [
                file_system::Action::"chown"
            ],
            resource == file_system::File::"{symlink_path}"
        );"#
    );

    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("username", username.clone());
    scope.push_constant("groupname", groupname);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let symlink_handle = dir_handle.open_symlink("test_symlink");
            symlink_handle.set_ownership(SetOwnershipOptions().user(username).group(groupname).build());
        "#,
    );

    let error_message = extract_error_message(&result.unwrap_err());
    let expected_error = format!(
        "Permission denied: {username} unauthorized to perform {}",
        FilesystemAction::Chown
    );
    assert!(
        error_message.contains(&expected_error),
        "Expected error to contain '{}', but got: '{}'",
        expected_error,
        error_message
    );

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: a WordCount obtained from counts()
/// When: calling to_map() on it
/// Then: the map contains the correct serialized fields
#[test]
fn test_word_count_to_map() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;
    temp_dir
        .child("test.txt")
        .write_str("hello world\nfoo bar\n")
        .unwrap();

    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [{}, {}],
            resource in file_system::Dir::"{temp_dir_path}"
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Read
    );
    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);
    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<rhai::Map>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let fh = dir_handle.open_file("test.txt", OpenFileOptions().read(true).build());
            let wc = fh.counts();

            let expected = #{
                "line_count": wc.line_count,
                "word_count": wc.word_count,
                "byte_count": wc.byte_count,
            };

            #{
                "expected": expected.to_json(),
                "actual": wc.to_map().to_json()
            }
        "#,
    )?;

    let expected: String = result.get("expected").unwrap().clone().into_string()?;
    let actual: String = result.get("actual").unwrap().clone().into_string()?;
    assert_eq!(expected, actual);
    Ok(())
}

/// Given: a GzipInfo obtained from gzip_info()
/// When: calling to_map() on it
/// Then: the map contains the correct serialized fields
#[test]
fn test_gzip_info_to_map() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;
    temp_dir
        .child("source.txt")
        .write_str(&"hello gzip\n".repeat(10))
        .unwrap();

    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [{}, {}, {}, {}],
            resource in file_system::Dir::"{temp_dir_path}"
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Read,
        FilesystemAction::Create,
        FilesystemAction::Write
    );
    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);
    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<rhai::Map>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let source = dir_handle.open_file("source.txt", OpenFileOptions().read(true).build());
            let dest = dir_handle.open_file("source.txt.gz", OpenFileOptions().read(true).write(true).create(true).build());
            source.compress_gzip(dest, CompressGzipOptions().build());
            let info = dest.gzip_info();

            let expected = #{
                "compressed_size_bytes": info.compressed_size_bytes,
                "uncompressed_size_bytes": info.uncompressed_size_bytes,
                "compression_ratio": info.compression_ratio,
            };

            #{
                "expected": expected.to_json(),
                "actual": info.to_map().to_json()
            }
        "#,
    )?;

    let expected: String = result.get("expected").unwrap().clone().into_string()?;
    let actual: String = result.get("actual").unwrap().clone().into_string()?;
    assert_eq!(expected, actual);
    Ok(())
}

/// Given: a DiskUsageEntry obtained from disk_usage()
/// When: calling to_map() on it
/// Then: the map contains the correct serialized fields
#[test]
#[cfg(unix)]
fn test_disk_usage_entry_to_map() {
    let engine = create_test_engine_and_register();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().unwrap();
    create_file_with_content(&temp_dir, "file1.txt", "Content 1").unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<rhai::Map>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let entries = dir_handle.disk_usage(DiskUsageOptions().build()).entries;
            let entry = entries[0];

            let expected = #{
                "path": entry.path,
                "size_bytes": entry.size_bytes.to_int(),
                "inode_count": entry.inode_count.to_int(),
            };

            let actual = entry.to_map();
            actual["size_bytes"] = actual["size_bytes"].to_int();
            actual["inode_count"] = actual["inode_count"].to_int();

            #{
                "expected": expected.to_json(),
                "actual": actual.to_json()
            }
        "#,
    );

    assert!(result.is_ok(), "Error: {:?}", result.err());
    let map = result.unwrap();
    let expected: String = map.get("expected").unwrap().clone().into_string().unwrap();
    let actual: String = map.get("actual").unwrap().clone().into_string().unwrap();
    assert_eq!(expected, actual);
}
