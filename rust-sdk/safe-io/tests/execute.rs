#![cfg(target_os = "linux")]

use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rex_test_utils::io::create_temp_dir_and_path;

use rust_safe_io::errors::RustSafeIoError::AuthorizationError;
use rust_safe_io::execute::{ChildNamespaceOptionsBuilder, ExecuteOptionsBuilder};
use rust_safe_io::options::{OpenDirOptionsBuilder, OpenFileOptionsBuilder};
use rust_safe_io::{DirConfigBuilder, RcDirHandle};

use anyhow::Result;
use assert_fs::fixture::PathChild;
use assert_fs::prelude::FileWriteStr;
use caps::Capability;
use std::fs::{metadata, set_permissions};
use std::os::unix::fs::PermissionsExt;

fn open_test_dir_handle(temp_dir_path: &String) -> RcDirHandle {
    DirConfigBuilder::default()
        .path(temp_dir_path.clone())
        .build()
        .unwrap()
        .safe_open(
            &DEFAULT_TEST_CEDAR_AUTH,
            OpenDirOptionsBuilder::default().build().unwrap(),
        )
        .unwrap()
}

/// Given: A file handle to a command that outputs to stdout
/// When: safe_execute is called with arguments
/// Then: Returns success with captured stdout
#[test]
fn test_execute_captures_stdout() -> Result<()> {
    let dir_config = DirConfigBuilder::default()
        .path("/usr/bin".to_string())
        .build()?;

    let dir_handle = dir_config.safe_open(
        &DEFAULT_TEST_CEDAR_AUTH,
        OpenDirOptionsBuilder::default().build().unwrap(),
    )?;

    let file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "echo",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let args = vec![("Hello World".to_string(), None)];

    let options = ExecuteOptionsBuilder::default().args(args).build().unwrap();

    let result = file_handle.safe_execute(&DEFAULT_TEST_CEDAR_AUTH, options)?;

    assert_eq!(*result.exit_code(), 0);
    assert_eq!(result.stdout().trim(), "Hello World");
    assert!(result.stderr().is_empty());

    Ok(())
}

/// Given: ExecuteOptions with namespace configuration for invalid PID 0
/// When: safe_execute is called with invalid PID
/// Then: Returns validation error for invalid PID
#[test]
fn test_execute_with_invalid_zero_pid_namespace() -> Result<()> {
    let dir_config = DirConfigBuilder::default()
        .path("/usr/bin".to_string())
        .build()?;

    let dir_handle = dir_config.safe_open(
        &DEFAULT_TEST_CEDAR_AUTH,
        OpenDirOptionsBuilder::default().build().unwrap(),
    )?;

    let file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "echo",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let namespace_options = ChildNamespaceOptionsBuilder::default()
        .target_process(0)
        .build()
        .unwrap();

    let options = ExecuteOptionsBuilder::default()
        .namespace(namespace_options)
        .args(vec![("test".to_string(), None)])
        .build()
        .unwrap();

    let result = file_handle.safe_execute(&DEFAULT_TEST_CEDAR_AUTH, options);

    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(error_message.contains("File descriptor operation failed"));

    Ok(())
}

/// Given: ExecuteOptions with namespace configuration for non-existent PID
/// When: safe_execute is called with non-existent PID
/// Then: Returns system error for failed namespace operation
#[test]
fn test_execute_with_nonexistent_pid_namespace() -> Result<()> {
    let dir_config = DirConfigBuilder::default()
        .path("/usr/bin".to_string())
        .build()?;

    let dir_handle = dir_config.safe_open(
        &DEFAULT_TEST_CEDAR_AUTH,
        OpenDirOptionsBuilder::default().build().unwrap(),
    )?;

    let file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "echo",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let namespace_options = ChildNamespaceOptionsBuilder::default()
        .target_process(999999)
        .build()
        .unwrap();

    let options = ExecuteOptionsBuilder::default()
        .namespace(namespace_options)
        .args(vec![("test".to_string(), None)])
        .build()
        .unwrap();

    let result = file_handle.safe_execute(&DEFAULT_TEST_CEDAR_AUTH, options);
    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(error_message.contains("File descriptor operation failed"));

    Ok(())
}

/// Given: ExecuteOptions with namespace switching combined
/// When: safe_execute is called with both namespace and user options
/// Then: Fails due to missing capabilities in test environment
#[test]
fn test_execute_with_namespace_switching() -> Result<()> {
    let dir_config = DirConfigBuilder::default()
        .path("/usr/bin".to_string())
        .build()?;

    let dir_handle = dir_config.safe_open(
        &DEFAULT_TEST_CEDAR_AUTH,
        OpenDirOptionsBuilder::default().build().unwrap(),
    )?;

    let file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "echo",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let current_pid = std::process::id();
    let namespace_options = ChildNamespaceOptionsBuilder::default()
        .target_process(current_pid)
        .build()
        .unwrap();

    let options = ExecuteOptionsBuilder::default()
        .namespace(namespace_options)
        .args(vec![("Combined test".to_string(), None)])
        .build()
        .unwrap();

    let result = file_handle.safe_execute(&DEFAULT_TEST_CEDAR_AUTH, options);

    // This should fail due to missing capabilities CAP_SYS_ADMIN in the test environment
    assert!(result.is_err());

    Ok(())
}

/// Given: A file handle to a command that outputs to stderr
/// When: safe_execute is called with invalid arguments
/// Then: Returns non-zero exit code with captured stderr
#[test]
fn test_execute_captures_stderr() -> Result<()> {
    let dir_config = DirConfigBuilder::default()
        .path("/usr/bin".to_string())
        .build()?;

    let dir_handle = dir_config.safe_open(
        &DEFAULT_TEST_CEDAR_AUTH,
        OpenDirOptionsBuilder::default().build().unwrap(),
    )?;

    let file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "ls",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let args = vec![("--invalid-option".to_string(), None)];

    let options = ExecuteOptionsBuilder::default().args(args).build().unwrap();

    let result = file_handle.safe_execute(&DEFAULT_TEST_CEDAR_AUTH, options)?;

    assert_ne!(*result.exit_code(), 0);
    assert!(
        result.stderr().contains("unrecognized option")
            || result.stderr().contains("invalid option")
    );

    Ok(())
}

/// Given: An executable script created and opened with write permissions
/// When: safe_execute is called
/// Then: Returns an error indicating file must be opened with read-only
#[test]
fn test_execute_fails_with_write_permissions() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let script = temp_dir.child("test_script.sh");
    script.write_str("#!/bin/bash\necho 'Hello from script'")?;

    let mut perms = metadata(script.path())?.permissions();
    perms.set_mode(0o755);
    set_permissions(script.path(), perms)?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "test_script.sh",
        OpenFileOptionsBuilder::default()
            .read(true)
            .write(true)
            .build()
            .unwrap(),
    )?;

    let options = ExecuteOptionsBuilder::default().build().unwrap();

    let result = file_handle.safe_execute(&DEFAULT_TEST_CEDAR_AUTH, options);

    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(error_message.contains("Attempted to execute a file opened with write permissions"));
    assert!(error_message.contains("Files must be opened read-only for execution"));

    Ok(())
}

/// Given: A file handle to a command that exits with non-zero code
/// When: safe_execute is called
/// Then: Returns the correct exit code
#[test]
fn test_execute_returns_exit_code() -> Result<()> {
    let dir_config = DirConfigBuilder::default()
        .path("/usr/bin".to_string())
        .build()?;

    let dir_handle = dir_config.safe_open(
        &DEFAULT_TEST_CEDAR_AUTH,
        OpenDirOptionsBuilder::default().build().unwrap(),
    )?;

    let file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "false",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let options = ExecuteOptionsBuilder::default().build().unwrap();

    let result = file_handle.safe_execute(&DEFAULT_TEST_CEDAR_AUTH, options)?;

    assert_eq!(*result.exit_code(), 1);
    assert!(result.stdout().is_empty());
    assert!(result.stderr().is_empty());

    Ok(())
}

/// Given: A file handle and custom environment variables
/// When: safe_execute is called with environment variables
/// Then: Command runs with only the provided environment
#[test]
fn test_execute_with_custom_environment() -> Result<()> {
    let dir_config = DirConfigBuilder::default()
        .path("/usr/bin".to_string())
        .build()?;

    let dir_handle = dir_config.safe_open(
        &DEFAULT_TEST_CEDAR_AUTH,
        OpenDirOptionsBuilder::default().build().unwrap(),
    )?;

    let file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "env",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let env = vec![
        ("TEST_VAR".to_string(), "test_value".to_string()),
        ("PATH".to_string(), "/usr/bin:/bin".to_string()),
    ];

    let options = ExecuteOptionsBuilder::default().env(env).build().unwrap();

    let result = file_handle.safe_execute(&DEFAULT_TEST_CEDAR_AUTH, options)?;

    assert_eq!(*result.exit_code(), 0);
    assert!(result.stdout().contains("TEST_VAR=test_value"));
    assert!(result.stdout().contains("PATH=/usr/bin:/bin"));
    assert!(!result.stdout().contains("HOME="));

    Ok(())
}

/// Given: A file handle without custom environment
/// When: safe_execute is called without environment variables
/// Then: Command runs with empty environment
#[test]
fn test_execute_empty_environment() -> Result<()> {
    unsafe {
        std::env::set_var("TEST_NO_INHERIT_VAR", "should_not_be_inherited");
    }

    let dir_config = DirConfigBuilder::default()
        .path("/usr/bin".to_string())
        .build()?;

    let dir_handle = dir_config.safe_open(
        &DEFAULT_TEST_CEDAR_AUTH,
        OpenDirOptionsBuilder::default().build().unwrap(),
    )?;

    let file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "env",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let options = ExecuteOptionsBuilder::default().build().unwrap();

    let result = file_handle.safe_execute(&DEFAULT_TEST_CEDAR_AUTH, options)?;

    assert_eq!(*result.exit_code(), 0);
    assert_eq!(result.stdout().trim(), "");

    unsafe {
        std::env::remove_var("TEST_NO_INHERIT_VAR");
    }

    Ok(())
}

/// Given: A file that cannot be executed
/// When: safe_execute is called on it
/// Then: Returns exit code 1 due to execution failure
#[test]
fn test_execute_execution_failure() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let non_exec = temp_dir.child("not_executable.txt");
    non_exec.write_str("This is not a script")?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "not_executable.txt",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let options = ExecuteOptionsBuilder::default().build().unwrap();

    let result = file_handle.safe_execute(&DEFAULT_TEST_CEDAR_AUTH, options)?;

    assert_eq!(*result.exit_code(), 1);

    Ok(())
}

/// Given: Mixed flags and key-value arguments
/// When: safe_execute is called with various argument types
/// Then: Correctly processes flags and values
#[test]
fn test_execute_processes_mixed_arguments() -> Result<()> {
    let dir_config = DirConfigBuilder::default()
        .path("/usr/bin".to_string())
        .build()?;

    let dir_handle = dir_config.safe_open(
        &DEFAULT_TEST_CEDAR_AUTH,
        OpenDirOptionsBuilder::default().build().unwrap(),
    )?;

    let file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "echo",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let args = vec![
        ("--verbose".to_string(), None),
        ("--file".to_string(), Some("test.txt".to_string())),
        ("-v".to_string(), None),
    ];

    let options = ExecuteOptionsBuilder::default().args(args).build().unwrap();

    let result = file_handle.safe_execute(&DEFAULT_TEST_CEDAR_AUTH, options)?;

    assert_eq!(*result.exit_code(), 0);
    let output = result.stdout().trim();
    assert!(output.contains("--verbose"));
    assert!(output.contains("--file"));
    assert!(output.contains("test.txt"));
    assert!(output.contains("-v"));

    Ok(())
}

/// Given: A file handle and capabilities not in the permitted set
/// When: safe_execute is called with invalid capabilities
/// Then: Returns error code 1 because capabilities are not present in Permitted set
#[test]
fn test_execute_with_invalid_capabilities() -> Result<()> {
    let dir_config = DirConfigBuilder::default()
        .path("/usr/bin".to_string())
        .build()?;

    let dir_handle = dir_config.safe_open(
        &DEFAULT_TEST_CEDAR_AUTH,
        OpenDirOptionsBuilder::default().build().unwrap(),
    )?;

    let file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "echo",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let options = ExecuteOptionsBuilder::default()
        .capabilities(vec![Capability::CAP_DAC_OVERRIDE])
        .args(vec![("test".to_string(), None)])
        .build()
        .unwrap();

    let result = file_handle.safe_execute(&DEFAULT_TEST_CEDAR_AUTH, options);
    assert_eq!(
        *result.unwrap().exit_code(),
        1,
        "Should fail with exit code 1 when missing capabilities"
    );

    Ok(())
}

/// Given: A file handle and empty capabilities list
/// When: safe_execute is called with no capabilities
/// Then: Executes successfully without capability setup
#[test]
fn test_execute_with_empty_capabilities() -> Result<()> {
    let dir_config = DirConfigBuilder::default()
        .path("/usr/bin".to_string())
        .build()?;

    let dir_handle = dir_config.safe_open(
        &DEFAULT_TEST_CEDAR_AUTH,
        OpenDirOptionsBuilder::default().build().unwrap(),
    )?;

    let file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "echo",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let args = vec![("Hello Capabilities".to_string(), None)];

    let options = ExecuteOptionsBuilder::default()
        .capabilities(vec![])
        .args(args)
        .build()
        .unwrap();

    let result = file_handle.safe_execute(&DEFAULT_TEST_CEDAR_AUTH, options)?;

    assert_eq!(*result.exit_code(), 0);
    assert_eq!(result.stdout().trim(), "Hello Capabilities");
    assert!(result.stderr().is_empty());

    Ok(())
}

/// Given: A valid executable but an unauthorized user
/// When: safe_execute is called
/// Then: Access is denied
#[test]
fn test_unauthorized_execute() -> Result<()> {
    let dir_config = DirConfigBuilder::default()
        .path("/usr/bin".to_string())
        .build()?;

    let dir_handle = dir_config.safe_open(
        &DEFAULT_TEST_CEDAR_AUTH,
        OpenDirOptionsBuilder::default().build().unwrap(),
    )?;

    let file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "echo",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"forbid(
            principal == User::"{principal}",
            action == file_system::Action::"execute",
            resource
        );"#
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let options = ExecuteOptionsBuilder::default().build().unwrap();

    let result = file_handle.safe_execute(&test_cedar_auth, options);

    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(error_message.contains("Permission denied"));

    Ok(())
}

/// Given: A Cedar policy that permits execution only with specific arguments using hasTag
/// When: safe_execute is called with different arguments
/// Then: Access is denied
#[test]
fn test_unauthorized_execute_with_arguments() -> Result<()> {
    let dir_config = DirConfigBuilder::default()
        .path("/usr/bin".to_string())
        .build()?;

    let dir_handle = dir_config.safe_open(
        &DEFAULT_TEST_CEDAR_AUTH,
        OpenDirOptionsBuilder::default().build().unwrap(),
    )?;

    let file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "echo",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action == file_system::Action::"execute",
            resource
        ) when {{
            context.arguments.hasTag("--file") &&
            context.arguments.getTag("--file") == "allowed.txt" &&
            context.arguments.hasTag("--mode") &&
            context.arguments.getTag("--mode") == "read"
        }};"#
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let args = vec![
        ("--file".to_string(), Some("different.txt".to_string())),
        ("--mode".to_string(), Some("write".to_string())),
    ];
    let options = ExecuteOptionsBuilder::default().args(args).build().unwrap();

    let result = file_handle.safe_execute(&test_cedar_auth, options);

    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(error_message.contains("Permission denied"));

    Ok(())
}

/// Given: A Cedar policy that permits execution only with specific environment variables
/// When: safe_execute is called with different environment variables
/// Then: Access is denied
#[test]
fn test_unauthorized_execute_with_environment() -> Result<()> {
    let dir_config = DirConfigBuilder::default()
        .path("/usr/bin".to_string())
        .build()?;

    let dir_handle = dir_config.safe_open(
        &DEFAULT_TEST_CEDAR_AUTH,
        OpenDirOptionsBuilder::default().build().unwrap(),
    )?;

    let file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "env",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action == file_system::Action::"execute",
            resource
        ) when {{
            context.environment.hasTag("ALLOWED_VAR") &&
            context.environment.getTag("ALLOWED_VAR") == "allowed_value" &&
            context.environment.hasTag("LANG") &&
            context.environment.getTag("LANG") == "en_US.UTF-8"
        }};"#
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let env = vec![("DIFFERENT_VAR".to_string(), "some_value".to_string())];
    let options = ExecuteOptionsBuilder::default().env(env).build().unwrap();

    let result = file_handle.safe_execute(&test_cedar_auth, options);

    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(error_message.contains("Permission denied"));

    Ok(())
}

/// Given: A Cedar policy that permits execution only with a specific user
/// When: safe_execute is called with a different user
/// Then: Access is denied
#[test]
fn test_unauthorized_execute_with_user() -> Result<()> {
    let dir_config = DirConfigBuilder::default()
        .path("/usr/bin".to_string())
        .build()?;

    let dir_handle = dir_config.safe_open(
        &DEFAULT_TEST_CEDAR_AUTH,
        OpenDirOptionsBuilder::default().build().unwrap(),
    )?;

    let file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "echo",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action == file_system::Action::"execute",
            resource
        ) when {{
            context.user.username == "allowed_user" &&
            context.user.uid == 1000
        }};"#
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let options = ExecuteOptionsBuilder::default()
        .user("root")
        .build()
        .unwrap();

    let result = file_handle.safe_execute(&test_cedar_auth, options);

    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(error_message.contains("Permission denied"));

    Ok(())
}

/// Given: A Cedar policy that permits execution only with a specific group
/// When: safe_execute is called with a different group
/// Then: Access is denied
#[test]
fn test_unauthorized_execute_with_group() -> Result<()> {
    let dir_config = DirConfigBuilder::default()
        .path("/usr/bin".to_string())
        .build()?;

    let dir_handle = dir_config.safe_open(
        &DEFAULT_TEST_CEDAR_AUTH,
        OpenDirOptionsBuilder::default().build().unwrap(),
    )?;

    let file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "echo",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action == file_system::Action::"execute",
            resource
        ) when {{
            context.group.groupname == "allowed_group" &&
            context.group.gid == 1000
        }};"#
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let options = ExecuteOptionsBuilder::default()
        .group("root")
        .build()
        .unwrap();

    let result = file_handle.safe_execute(&test_cedar_auth, options);

    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(error_message.contains("Permission denied"));

    Ok(())
}

/// Given: A Cedar policy that permits execution only with a specific namespace
/// When: safe_execute is called with a different namespace
/// Then: Access is denied
#[test]
fn test_unauthorized_execute_with_namespace() -> Result<()> {
    let dir_config = DirConfigBuilder::default()
        .path("/usr/bin".to_string())
        .build()?;

    let dir_handle = dir_config.safe_open(
        &DEFAULT_TEST_CEDAR_AUTH,
        OpenDirOptionsBuilder::default().build().unwrap(),
    )?;

    let file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "echo",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action == file_system::Action::"execute",
            resource
        ) when {{
            context has namespace &&
            context.namespace.target_process_id == 12345
        }};"#
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let current_pid = std::process::id();
    let namespace_options = ChildNamespaceOptionsBuilder::default()
        .target_process(current_pid)
        .build()
        .unwrap();

    let options = ExecuteOptionsBuilder::default()
        .namespace(namespace_options)
        .build()
        .unwrap();

    let result = file_handle.safe_execute(&test_cedar_auth, options);

    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(error_message.contains("Permission denied"));

    Ok(())
}

/// Given: A file handle opened with Cedar authorization
/// When: safe_execute_util is called from Wrapper SDK API
/// Then: Command executes successfully and captures output
#[test]
fn test_safe_execute_util() -> Result<()> {
    let dir_config = DirConfigBuilder::default()
        .path("/usr/bin".to_string())
        .build()?;

    let dir_handle = dir_config.safe_open(
        &DEFAULT_TEST_CEDAR_AUTH,
        OpenDirOptionsBuilder::default().build().unwrap(),
    )?;

    let file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "echo",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let args = vec![("Hello from safe_execute_util".to_string(), None)];
    let options = ExecuteOptionsBuilder::default().args(args).build().unwrap();

    let result = file_handle.safe_execute_util(&options)?;

    assert_eq!(*result.exit_code(), 0);
    assert_eq!(result.stdout().trim(), "Hello from safe_execute_util");
    assert!(result.stderr().is_empty());

    Ok(())
}

/// Given: A Cedar policy that permits execution with specific arguments and environment variables
/// When: safe_execute is called with matching arguments and environment
/// Then: Authorization succeeds and command executes successfully
#[test]
fn test_authorized_execute_with_arguments_and_environment() -> Result<()> {
    let dir_config = DirConfigBuilder::default()
        .path("/usr/bin".to_string())
        .build()?;

    let dir_handle = dir_config.safe_open(
        &DEFAULT_TEST_CEDAR_AUTH,
        OpenDirOptionsBuilder::default().build().unwrap(),
    )?;

    let file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "echo",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action == file_system::Action::"execute",
            resource
        ) when {{
            context.arguments.hasTag("--mode") &&
            context.arguments.getTag("--mode") == "safe" &&
            context.arguments.hasTag("--output") &&
            context.arguments.getTag("--output") == "stdout" &&
            context.environment.hasTag("EXECUTION_ENV") &&
            context.environment.getTag("EXECUTION_ENV") == "test" &&
            context.environment.hasTag("LOG_LEVEL") &&
            context.environment.getTag("LOG_LEVEL") == "info"
        }};"#
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let args = vec![
        ("--mode".to_string(), Some("safe".to_string())),
        ("--output".to_string(), Some("stdout".to_string())),
    ];

    let env = vec![
        ("EXECUTION_ENV".to_string(), "test".to_string()),
        ("LOG_LEVEL".to_string(), "info".to_string()),
    ];

    let options = ExecuteOptionsBuilder::default()
        .args(args)
        .env(env)
        .build()
        .unwrap();

    let result = file_handle.safe_execute(&test_cedar_auth, options)?;

    assert_eq!(*result.exit_code(), 0);
    assert!(result.stdout().contains("--mode"));
    assert!(result.stdout().contains("safe"));
    assert!(result.stdout().contains("--output"));
    assert!(result.stdout().contains("stdout"));
    assert!(result.stderr().is_empty());

    Ok(())
}

/// Given: A Cedar authorization setup with a schema that requires a context field not provided by safe_execute
/// When: safe_execute is called
/// Then: An authorization error is returned due to Cedar evaluation failure
#[test]
fn test_safe_execute_authorization_error() -> Result<()> {
    let dir_config = DirConfigBuilder::default()
        .path("/usr/bin".to_string())
        .build()?;

    let dir_handle = dir_config.safe_open(
        &DEFAULT_TEST_CEDAR_AUTH,
        OpenDirOptionsBuilder::default().build().unwrap(),
    )?;

    let file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "echo",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action == file_system::Action::"execute",
            resource
        ) when {{
            context.security_level >= 5
        }};"#
    );

    let test_schema = r#"entity User;

    namespace file_system {
        entity File;

        action execute appliesTo {
            principal: [User],
            resource: [File],
            context: {
                security_level: Long
            }
        };
    }"#;

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .schema(test_schema.to_string())
        .build()
        .unwrap()
        .create();

    let options = ExecuteOptionsBuilder::default().build().unwrap();

    let result = file_handle.safe_execute(&test_cedar_auth, options);

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(matches!(error, AuthorizationError { .. }));
    assert!(error.to_string().contains("Authorization check failed"));

    Ok(())
}
