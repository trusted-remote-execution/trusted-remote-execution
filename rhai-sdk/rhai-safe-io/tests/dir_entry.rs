use assert_fs::prelude::*;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::get_test_rex_principal;
use rex_test_utils::io::create_temp_dir;
use rex_test_utils::rhai::common::{
    assert_with_registration_details, create_test_cedar_auth_with_policy,
    create_test_engine_and_register, create_test_engine_with_auth, extract_error_message,
    to_eval_error,
};
use rhai::{EvalAltResult, Scope};
use rust_safe_io::dir_entry::EntryType;
use std::os::unix::fs::PermissionsExt;

/// Given: a rhai engine and a rhai script that returns EntryType.to_string()
/// When: the script runs
/// Then: the output is correct
#[test]
fn test_rhai_dir_entry_type_to_string() {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    let result = engine.eval_with_scope::<String>(
        &mut scope,
        r#"
            let dir_entry_type = EntryType::FILE;
            dir_entry_type.to_string()
        "#,
    );
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "File");
}

/// Given: a rhai engine and a rhai script that compares 2 EntryTypes using the equals "==" operator
/// When: the script runs
/// Then: the output is correct
#[test]
fn test_rhai_dir_entry_type_equals() {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    let result = engine.eval_with_scope::<bool>(
        &mut scope,
        r#"
            let dir_entry_type1 = EntryType::FILE;
            let dir_entry_type2 = EntryType::FILE;
            dir_entry_type1 == dir_entry_type2
        "#,
    );
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), true);
}

/// Given: a rhai engine and a rhai script that compares 2 EntryTypes using the not equals "!=" operator
/// When: the script runs
/// Then: the output is correct
#[test]
fn test_rhai_dir_entry_type_not_equals() {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    let result = engine.eval_with_scope::<bool>(
        &mut scope,
        r#"
            let dir_entry_type1 = EntryType::FILE;
            let dir_entry_type2 = EntryType::DIR;
            dir_entry_type1 != dir_entry_type2
        "#,
    );
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), true);
}

/// Given: a rhai engine and a rhai script that calls DirEntry.name
/// When: the script runs
/// Then: the output is correct
#[test]
fn test_rhai_dir_entry_name() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    let test_file_name = "test_file.txt";
    temp.child(test_file_name).touch().unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);

    let result = engine.eval_with_scope::<String>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let entries = dir_handle.list_entries();
            
            // Get the first entry (should be our test file)
            let entry = entries.values()[0];
            entry.name
        "#,
    )?;

    assert_eq!(result, test_file_name);

    temp.close().unwrap();
    Ok(())
}

/// Given: a rhai engine and a rhai script that calls DirEntry.dir_entry_type() on a regular file
/// When: the script runs
/// Then: the output is "File"
#[test]
fn test_rhai_dir_entry_dir_entry_type_file() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    let test_file_name = "test_file.txt";
    temp.child(test_file_name).touch().unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("test_file_name", test_file_name);

    let result = engine.eval_with_scope::<String>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let entries = dir_handle.list_entries();
            
            let file_entry = entries[test_file_name];
            file_entry.type().to_string()
        "#,
    );

    assert_with_registration_details(&result, || result.is_ok(), &engine, "entries");
    assert_eq!(result.unwrap(), "File");

    temp.close().unwrap();
    Ok(())
}

/// Given: a rhai engine and a rhai script that calls DirEntry.dir_entry_type() on a directory
/// When: the script runs
/// Then: the output is "Dir"
#[test]
fn test_rhai_dir_entry_dir_entry_type_dir() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    let test_dir_name = "test_dir";
    temp.child(test_dir_name).create_dir_all().unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("test_dir_name", test_dir_name);

    let result = engine.eval_with_scope::<String>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let entries = dir_handle.list_entries();
            
            let dir_entry = entries[test_dir_name];
            dir_entry.type().to_string()
        "#,
    );

    assert_with_registration_details(&result, || result.is_ok(), &engine, "open");
    let dir_type_result = result.unwrap();
    assert_eq!(dir_type_result, "Dir");

    temp.close().unwrap();
    Ok(())
}

/// Given: a rhai engine and a rhai script that calls DirEntry.dir_entry_type() on a symlink
/// When: the script runs
/// Then: the output is "Symlink"
#[test]
fn test_rhai_dir_entry_dir_entry_type_symlink() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    let test_file_name = "test_file.txt";
    let test_symlink_name = "test_symlink";

    temp.child(test_file_name).touch().unwrap();

    let binding = temp.child(test_file_name);
    let file_path = binding.path();
    temp.child(test_symlink_name)
        .symlink_to_file(file_path)
        .unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("test_symlink_name", test_symlink_name);

    let symlink_type_result = engine.eval_with_scope::<String>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let entries = dir_handle.list_entries();
            
            let symlink_entry = entries[test_symlink_name];
            symlink_entry.type().to_string()
        "#,
    )?;

    assert_eq!(symlink_type_result, "Symlink");

    temp.close().unwrap();
    Ok(())
}

/// Given: a rhai engine and a rhai script that calls DirEntry.dir_entry_type() on a fifo
/// When: the script runs
/// Then: the output is "Fifo"
#[test]
#[cfg(unix)]
fn test_rhai_dir_entry_dir_entry_type_fifo() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    let fifo_name = "test_fifo";
    let fifo_path = temp.path().join(fifo_name);

    std::process::Command::new("mkfifo")
        .arg(fifo_path.to_str().unwrap())
        .output()
        .map_err(to_eval_error)?;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("fifo_name", fifo_name);

    let fifo_type_result = engine.eval_with_scope::<String>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let entries = dir_handle.list_entries();
            
            let fifo_entry = entries[fifo_name];
            fifo_entry.type().to_string()
        "#,
    )?;

    assert_eq!(fifo_type_result, "Fifo");

    temp.close().unwrap();
    Ok(())
}

/// Given: a rhai engine and a rhai script that calls DirEntry.dir_entry_type() on a socket
/// When: the script runs
/// Then: the output is "Socket"
#[test]
#[cfg(target_os = "linux")]
fn test_rhai_dir_entry_dir_entry_type_socket() -> Result<(), Box<EvalAltResult>> {
    use std::os::unix::net::UnixListener;

    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    let socket_name = "test_socket";
    let socket_path = temp.path().join(socket_name);

    let _listener = UnixListener::bind(&socket_path).map_err(to_eval_error)?;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("socket_name", socket_name);

    let socket_type_result = engine.eval_with_scope::<String>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let entries = dir_handle.list_entries();
            
            let socket_entry = entries[socket_name];
            socket_entry.type().to_string()
        "#,
    )?;

    assert_eq!(socket_type_result, "Socket");

    temp.close().unwrap();
    Ok(())
}

/// Given: a rhai engine and a rhai script that returns an Unknown `EntryType`
/// When: the script runs
/// Then: the output is "Unknown"
#[test]
fn test_rhai_dir_entry_dir_entry_type_unknown() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    let symlink_type_result = engine.eval_with_scope::<String>(
        &mut scope,
        r#"
            EntryType::UNKNOWN.to_string()
        "#,
    )?;

    assert_eq!(symlink_type_result, "Unknown");
    Ok(())
}

/// Given: a rhai engine and a rhai script that calls DirEntry.open_as_file() and a user who is authorized to open the file
/// When: the script runs
/// Then: the file is opened successfully
#[test]
fn test_rhai_dir_entry_open_as_file_authorized() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    let test_file_name = "test_file.txt";
    let test_content = "test content";
    temp.child(test_file_name).write_str(test_content).unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("test_file_name", test_file_name);

    let result = engine.eval_with_scope::<String>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let entries = dir_handle.list_entries();
            let file_entry = entries[test_file_name];
            let file_handle = file_entry.open_as_file(OpenFileOptions().read(true).build());
            file_handle.read()
        "#,
    )?;

    assert_eq!(result, test_content);

    temp.close().unwrap();
    Ok(())
}

/// Given: a rhai engine and a rhai script that calls DirEntry.open_as_file() and a user who is not authorized to open the file
/// When: the script runs
/// Then: an error is returned
#[test]
fn test_rhai_dir_entry_open_as_file_unauthorized() -> Result<(), Box<EvalAltResult>> {
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
            action == file_system::Action::"open",
            resource is file_system::File in file_system::Dir::"{temp_dir_path}"
        );"#
    );

    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let test_file_name = "test_file.txt";
    temp.child(test_file_name).touch().unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("test_file_name", test_file_name);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let entries = dir_handle.list_entries();
            let file_entry = entries[test_file_name];
            let file_handle = file_entry.open_as_file(OpenFileOptions().read(true).build());
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

    temp.close().unwrap();
    Ok(())
}

/// Given: a rhai engine and a rhai script that calls DirEntry.open_as_dir() and a user who is authorized to open the file
/// When: the script runs
/// Then: the file is opened successfully
#[test]
fn test_rhai_dir_entry_open_as_dir_authorized() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    let test_dir_name = "test_dir";
    temp.child(test_dir_name).create_dir_all().unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("test_dir_name", test_dir_name);

    let result = engine.eval_with_scope::<bool>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let entries = dir_handle.list_entries();
            let dir_entry = entries[test_dir_name];
            let subdir_handle = dir_entry.open_as_dir(OpenDirOptions().build());
            true
        "#,
    )?;

    assert!(result);

    temp.close().unwrap();
    Ok(())
}

/// Given: a rhai engine and a rhai script that calls DirEntry.open_as_dir() and a user who is not authorized to open the file
/// When: the script runs
/// Then: an error is returned
#[test]
fn test_rhai_dir_entry_open_as_dir_unauthorized() -> Result<(), Box<EvalAltResult>> {
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    let principal = get_test_rex_principal();
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
            action == file_system::Action::"open",
            resource in file_system::Dir::"{temp_dir_path}/test_dir"
        );
        "#
    );

    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let test_dir_name = "test_dir";
    temp.child(test_dir_name).create_dir_all().unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("test_dir_name", test_dir_name);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let entries = dir_handle.list_entries();
            let dir_entry = entries[test_dir_name];
            let subdir_handle = dir_entry.open_as_dir(OpenDirOptions().build());
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

    temp.close().unwrap();
    Ok(())
}

/// Given: a rhai engine and a rhai script that calls DirEntry.metadata() and a user who is authorized to get the file metadata
/// When: the script runs
/// Then: the metadata is retrieved succesfully for regular files, symlinks, and FIFOs
#[test]
fn test_rhai_dir_entry_metadata_authorized() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    let test_file_name = "test_file.txt";
    let test_content = "test content";
    temp.child(test_file_name).write_str(test_content).unwrap();

    let test_dir_name = "test_dir";
    temp.child(test_dir_name).create_dir_all().unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path.clone());
    scope.push_constant("test_file_name", test_file_name);
    scope.push_constant("test_dir_name", test_dir_name);
    scope.push_constant("expected_len", test_content.len() as i64);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let entries = dir_handle.list_entries();
            let file_entry = entries[test_file_name];
            let metadata = file_entry.metadata();
            if metadata.type() != EntryType::FILE {
                throw `can't match type`
            }
            if metadata.file_size() != expected_len {
                throw `len doesn't match`
            }
        "#,
    );
    assert_with_registration_details(&result, || result.is_ok(), &engine, "metadata");

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let entries = dir_handle.list_entries();
            let dir_entry = entries[test_dir_name];
            let metadata = dir_entry.metadata();
            if metadata.type() != EntryType::DIR {
                throw `can't match type`
            }
        "#,
    );
    assert_with_registration_details(&result, || result.is_ok(), &engine, "metadata");

    #[cfg(target_os = "linux")]
    {
        let test_symlink_name = "test_symlink";
        let binding = temp.child(test_file_name);
        let file_path = binding.path();
        temp.child(test_symlink_name)
            .symlink_to_file(file_path)
            .unwrap();

        scope.push_constant("test_symlink_name", test_symlink_name);

        let result = engine.eval_with_scope::<()>(
            &mut scope,
            r#"
                let dir_handle = DirConfig()
                    .path(temp_dir_path)
                    .build().open(OpenDirOptions().build());
                let entries = dir_handle.list_entries();
                let symlink_entry = entries[test_symlink_name];
                let metadata = symlink_entry.metadata();
                if metadata.type() != EntryType::SYMLINK {
                    throw `can't match type`
                }
            "#,
        );
        assert_with_registration_details(&result, || result.is_ok(), &engine, "metadata");
    }

    #[cfg(unix)]
    {
        let fifo_name = "test_fifo";
        let fifo_path = temp.path().join(fifo_name);
        std::process::Command::new("mkfifo")
            .arg(fifo_path.to_str().unwrap())
            .output()
            .map_err(to_eval_error)?;

        scope.push_constant("fifo_name", fifo_name);

        let result = engine.eval_with_scope::<()>(
            &mut scope,
            r#"
                let dir_handle = DirConfig()
                    .path(temp_dir_path)
                    .build().open(OpenDirOptions().build());
                let entries = dir_handle.list_entries();
                let fifo_entry = entries[fifo_name];
                let metadata = fifo_entry.metadata();
                if metadata.type() != EntryType::FIFO {
                    throw `can't match type`
                }
            "#,
        );
        assert_with_registration_details(&result, || result.is_ok(), &engine, "metadata");
    }

    temp.close().unwrap();

    Ok(())
}

/*

    let mut symlink_metadata = engine.eval_with_scope::<RhaiFileMetadata>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let entries = dir_handle.list_entries();
            let symlink_entry = entries[test_symlink_name];
            symlink_entry.metadata()
        "#,
    )?;

    assert_eq!(symlink_metadata.dir_entry_type()?, EntryType::SYMLINK);

    #[cfg(unix)]
    {
        let fifo_name = "test_fifo";
        let fifo_path = temp.path().join(fifo_name);
        std::process::Command::new("mkfifo")
            .arg(fifo_path.to_str().unwrap())
            .output()
            .map_err(to_eval_error)?;

        scope.push_constant("fifo_name", fifo_name);

        let mut fifo_metadata = engine.eval_with_scope::<RhaiFileMetadata>(
            &mut scope,
            r#"
                let dir_handle = DirConfig()
                    .path(temp_dir_path)
                    .build().open(OpenDirOptions().build());
                let entries = dir_handle.list_entries();
                let fifo_entry = entries[fifo_name];
                fifo_entry.metadata()
            "#,
        )?;

        assert_eq!(
            fifo_metadata.dir_entry_type()?,
            DirEntryType::Ext(EntryTypeExt::Fifo)
        );
    }

    temp.close().unwrap();
    Ok(())
}*/

/// Given: a rhai engine and a rhai script that calls DirEntry.metadata() and a user who is not authorized to get the file metadata
/// When: the script runs
/// Then: an error is returned
#[test]
fn test_rhai_dir_entry_metadata_unauthorized() -> Result<(), Box<EvalAltResult>> {
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

    // Create a test file
    let test_file_name = "test_file.txt";
    temp.child(test_file_name).touch().unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("test_file_name", test_file_name);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let entries = dir_handle.list_entries();
            let file_entry = entries[test_file_name];
            let metadata = file_entry.metadata();
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

/// Given: a rhai engine and a rhai script that calls DirEntry.metadata().file_type()
/// When: the script runs
/// Then: the file type is retrieved and has the correct value
#[test]
fn test_rhai_dir_entry_metadata_file_type() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    let test_file_name = "test_file.txt";
    let test_content = "some content";
    temp.child(test_file_name).write_str(test_content).unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("test_file_name", test_file_name);

    let result = engine.eval_with_scope::<EntryType>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let entries = dir_handle.list_entries();
            let file_entry = entries[test_file_name];
            file_entry.metadata().type();
        "#,
    )?;

    assert_eq!(result, EntryType::File);

    temp.close().unwrap();
    Ok(())
}

/// Given: a rhai engine and a rhai script that calls DirEntry.metadata().file_size()
/// When: the script runs
/// Then: the file size is retrieved and has the correct value
#[test]
fn test_rhai_dir_entry_metadata_file_size() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    // Create a test file with known content
    let test_file_name = "test_file.txt";
    let test_content = "test content with known size";
    temp.child(test_file_name).write_str(test_content).unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("test_file_name", test_file_name);

    let result = engine.eval_with_scope::<i64>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let entries = dir_handle.list_entries();
            let file_entry = entries[test_file_name];
            let metadata = file_entry.metadata();
            metadata.file_size()
        "#,
    )?;

    assert_eq!(result, test_content.len() as i64);

    temp.close().unwrap();
    Ok(())
}

/// Given: a rhai engine and a rhai script that calls DirEntry.metadata().blocks()
/// When: the script runs
/// Then: the blocks are retrieved and have the correct value
#[test]
fn test_rhai_dir_entry_metadata_blocks() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    let test_file_name = "test_file.txt";
    let test_content = "test content";
    temp.child(test_file_name).write_str(test_content).unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("test_file_name", test_file_name);

    let result = engine.eval_with_scope::<i64>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let entries = dir_handle.list_entries();
            let file_entry = entries[test_file_name];
            let metadata = file_entry.metadata();
            metadata.blocks()
        "#,
    )?;

    let file_path = temp.path().join(test_file_name);

    let expected_blocks;
    #[cfg(not(target_vendor = "apple"))]
    {
        use std::os::linux::fs::MetadataExt;
        expected_blocks = std::fs::metadata(file_path).unwrap().st_blocks();
    }
    #[cfg(target_vendor = "apple")]
    {
        use std::os::darwin::fs::MetadataExt;
        expected_blocks = std::fs::metadata(file_path).unwrap().st_blocks();
    }

    assert_eq!(result, expected_blocks as i64);

    temp.close().unwrap();
    Ok(())
}

/// Given: a rhai engine and a rhai script that calls DirEntry.metadata().allocated_size()
/// When: the script runs
/// Then: the allocated_size is retrieved and have the correct value
#[test]
fn test_rhai_dir_entry_metadata_allocated_size() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    let test_file_name = "test_file.txt";
    let test_content = "test content";
    temp.child(test_file_name).write_str(test_content).unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("test_file_name", test_file_name);

    let result = engine.eval_with_scope::<i64>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let entries = dir_handle.list_entries();
            let file_entry = entries[test_file_name];
            let metadata = file_entry.metadata();
            metadata.allocated_size()
        "#,
    )?;

    let file_path = temp.path().join(test_file_name);

    let expected_allocated_size;
    #[cfg(not(target_vendor = "apple"))]
    {
        use std::os::linux::fs::MetadataExt;
        expected_allocated_size = std::fs::metadata(file_path).unwrap().st_blocks() * 512;
    }
    #[cfg(target_vendor = "apple")]
    {
        use std::os::darwin::fs::MetadataExt;
        expected_allocated_size = std::fs::metadata(file_path).unwrap().st_blocks() * 512;
    }

    assert_eq!(result, expected_allocated_size as i64);

    temp.close().unwrap();
    Ok(())
}

/// Given: a rhai engine and a rhai script that calls DirEntry.metadata().num_hardlinks()
/// When: the script runs
/// Then: the number of hardlinks is retrieved and has the correct value
#[test]
fn test_rhai_dir_entry_metadata_num_hardlinks() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    let test_file_name = "test_file.txt";
    temp.child(test_file_name)
        .write_str("test content")
        .unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("test_file_name", test_file_name);

    let result = engine.eval_with_scope::<i64>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let entries = dir_handle.list_entries();
            let file_entry = entries[test_file_name];
            let metadata = file_entry.metadata();
            metadata.num_hardlinks()
        "#,
    )?;

    let file_path = temp.path().join(test_file_name);
    let expected_hardlinks;
    #[cfg(not(target_vendor = "apple"))]
    {
        use std::os::linux::fs::MetadataExt;
        expected_hardlinks = std::fs::metadata(file_path).unwrap().st_nlink();
    }
    #[cfg(target_vendor = "apple")]
    {
        use std::os::darwin::fs::MetadataExt;
        expected_hardlinks = std::fs::metadata(file_path).unwrap().st_nlink();
    }

    assert_eq!(result, expected_hardlinks as i64);

    temp.close().unwrap();
    Ok(())
}

/// Given: a rhai engine and a rhai script that calls last_modified_time() and last_modified_time_nanos_component() on DirEntry.metadata()
/// When: the script runs
/// Then: the last_modified_time in seconds and the nanosecond component are retrieved and have the correct values
#[test]
fn test_rhai_dir_entry_metadata_last_modified_time() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    let test_file_name = "test_file.txt";
    temp.child(test_file_name)
        .write_str("test content")
        .unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("test_file_name", test_file_name);

    let result = engine.eval_with_scope::<rhai::Map>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let entries = dir_handle.list_entries();
            let file_entry = entries[test_file_name];
            let metadata = file_entry.metadata();
            #{
                "mtime": metadata.last_modified_time(),
                "mtime_nsec": metadata.last_modified_time_nanos_component()
            }
        "#,
    )?;

    let file_path = temp.path().join(test_file_name);

    let expected_mtime;
    let expected_mtime_nsec;
    #[cfg(not(target_vendor = "apple"))]
    {
        use std::os::linux::fs::MetadataExt;
        expected_mtime = std::fs::metadata(&file_path).unwrap().st_mtime();
        expected_mtime_nsec = std::fs::metadata(&file_path).unwrap().st_mtime_nsec();
    }
    #[cfg(target_vendor = "apple")]
    {
        use std::os::darwin::fs::MetadataExt;
        expected_mtime = std::fs::metadata(&file_path).unwrap().st_mtime();
        expected_mtime_nsec = std::fs::metadata(&file_path).unwrap().st_mtime_nsec();
    }

    let mtime = result["mtime"].clone().cast::<i64>();
    let mtime_nsec = result["mtime_nsec"].clone().cast::<i64>();
    assert_eq!(mtime, expected_mtime);
    assert_eq!(mtime_nsec, expected_mtime_nsec);

    temp.close().unwrap();
    Ok(())
}

/// Given: a rhai engine and a rhai script that calls DirEntry.metadata().permissions()
/// When: the script runs
/// Then: the permissions are retrieved and have the correct value
#[test]
#[cfg(unix)]
fn test_rhai_dir_entry_metadata_permissions() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    let test_file_name = "test_file.txt";
    let test_file = temp.child(test_file_name);
    test_file.write_str("test content").unwrap();

    let permissions = std::fs::Permissions::from_mode(0o644);
    std::fs::set_permissions(test_file.path(), permissions).unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("test_file_name", test_file_name);

    let result = engine.eval_with_scope::<i64>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let entries = dir_handle.list_entries();
            let file_entry = entries[test_file_name];
            let metadata = file_entry.metadata();
            metadata.permissions()
        "#,
    )?;

    assert_eq!(result & 0o777, 0o644);

    temp.close().unwrap();
    Ok(())
}

/// Given: a rhai engine and a rhai script that calls DirEntry.metadata().ownership()
/// When: the script runs
/// Then: the ownership is retrieved and matches the result of file_handle.get_ownership()
#[test]
#[cfg(unix)]
fn test_rhai_dir_entry_metadata_ownership() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let temp = create_temp_dir().map_err(to_eval_error)?;
    let temp_dir_path: String = temp.path().to_string_lossy().into();

    let test_file_name = "test_file.txt";
    temp.child(test_file_name)
        .write_str("test content")
        .unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("test_file_name", test_file_name);

    // Get ownership from DirEntry.metadata().ownership()
    let metadata_ownership = engine.eval_with_scope::<rhai::Map>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let entries = dir_handle.list_entries();
            let file_entry = entries[test_file_name];
            let metadata = file_entry.metadata();
            let ownership = metadata.owner;
            #{
                "user": ownership.user,
                "group": ownership.group
            }
        "#,
    )?;

    // Get ownership from file_handle.get_ownership()
    let result = engine.eval_with_scope::<rhai::Map>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file(test_file_name, OpenFileOptions().read(true).build());
            let ownership = file_handle.get_ownership();
            #{
                "user": ownership.user,
                "group": ownership.group
            }
        "#,
    );
    assert_with_registration_details(&result, || result.is_ok(), &engine, "get_ownership");
    let file_handle_ownership = result.unwrap();

    // Compare the two ownership results
    let metadata_user = metadata_ownership["user"].clone().into_string().unwrap();
    let metadata_group = metadata_ownership["group"].clone().into_string().unwrap();
    let file_handle_user = file_handle_ownership["user"].clone().into_string().unwrap();
    let file_handle_group = file_handle_ownership["group"]
        .clone()
        .into_string()
        .unwrap();

    assert_eq!(metadata_user, file_handle_user);
    assert_eq!(metadata_group, file_handle_group);

    temp.close().unwrap();
    Ok(())
}

/// Given: a DirEntry obtained from list_entries
/// When: calling to_map() on it
/// Then: the map contains the correct serialized fields
#[test]
fn test_dir_entry_to_map() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) =
        rex_test_utils::io::create_temp_dir_and_path().map_err(to_eval_error)?;
    temp_dir.child("test.txt").write_str("hello").unwrap();

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
            let entry = dir_handle.list_entries()["test.txt"];

            let expected = #{
                "name": entry.name,
                "type": entry.type().to_string(),
                "inode": entry.inode.to_int(),
            };

            #{
                "expected": expected.to_json(),
                "actual": entry.to_map().to_json()
            }
        "#,
    )?;

    let expected: String = result.get("expected").unwrap().clone().into_string()?;
    let actual: String = result.get("actual").unwrap().clone().into_string()?;
    assert_eq!(expected, actual);
    Ok(())
}

/// Given: a Metadata obtained from a file
/// When: calling to_map() on it
/// Then: the map contains the correct serialized fields
#[test]
fn test_metadata_to_map() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) =
        rex_test_utils::io::create_temp_dir_and_path().map_err(to_eval_error)?;
    temp_dir.child("test.txt").write_str("hello").unwrap();

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

    let result = engine.eval_with_scope::<rhai::Map>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let fh = dir_handle.open_file("test.txt", OpenFileOptions().read(true).build());
            let meta = fh.metadata();

            let expected = #{
                "type": meta.type().to_string(),
                "permissions": meta.permissions(),
                "file_size": meta.file_size(),
                "allocated_size": meta.allocated_size(),
                "last_modified_time": meta.last_modified_time(),
                "num_hardlinks": meta.num_hardlinks(),
                "owner_user": meta.owner.user,
                "owner_group": meta.owner.group,
                "symlink_target": meta.symlink_target(),
            };

            #{
                "expected": expected.to_json(),
                "actual": meta.to_map().to_json()
            }
        "#,
    )?;

    let expected: String = result.get("expected").unwrap().clone().into_string()?;
    let actual: String = result.get("actual").unwrap().clone().into_string()?;
    assert_eq!(expected, actual);
    Ok(())
}

/// Given: a Metadata obtained from a symlink
/// When: calling to_map() on it
/// Then: the map contains symlink_target with the correct target path
#[test]
#[cfg(target_os = "linux")]
fn test_symlink_metadata_to_map() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let (temp_dir, temp_dir_path) =
        rex_test_utils::io::create_temp_dir_and_path().map_err(to_eval_error)?;
    temp_dir.child("target.txt").write_str("hello").unwrap();
    temp_dir
        .child("link.txt")
        .symlink_to_file("target.txt")
        .unwrap();

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

    let result = engine.eval_with_scope::<rhai::Map>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(temp_dir_path)
                .build().open(OpenDirOptions().build());
            let symlink_handle = dir_handle.open_symlink("link.txt");
            let meta = symlink_handle.metadata();

            let expected = #{
                "type": meta.type().to_string(),
                "permissions": meta.permissions(),
                "file_size": meta.file_size(),
                "allocated_size": meta.allocated_size(),
                "last_modified_time": meta.last_modified_time(),
                "num_hardlinks": meta.num_hardlinks(),
                "owner_user": meta.owner.user,
                "owner_group": meta.owner.group,
                "symlink_target": meta.symlink_target(),
            };

            #{
                "expected": expected.to_json(),
                "actual": meta.to_map().to_json()
            }
        "#,
    )?;

    let expected: String = result.get("expected").unwrap().clone().into_string()?;
    let actual: String = result.get("actual").unwrap().clone().into_string()?;
    assert_eq!(expected, actual);

    // Also verify symlink_target is actually populated
    assert!(actual.contains("\"symlink_target\":\"target.txt\""));

    Ok(())
}
