#![cfg(target_os = "linux")]

use rex_test_utils::rhai::common::create_test_engine_and_register;
use rex_test_utils::rhai::safe_io::create_temp_test_env;
use rstest::rstest;
use rust_safe_io::execute::ExecuteResult;

/// Given: A file handle to echo command
/// When: Executing with args and env via Rhai
/// Then: Returns success with expected output
#[test]
fn test_rhai_execute_success() {
    let (mut scope, engine) = create_temp_test_env();

    let result = engine.eval_with_scope::<ExecuteResult>(
        &mut scope,
        r#"
            let dir_config = DirConfig()
                .path("/usr/bin")
                .build();
            let dir_handle = dir_config.open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file("echo", OpenFileOptions().read(true).build());

            let args = [
                "Hello",
                "--flag",
                ["--key", "value"],
                ["World"]
            ];

            let env = #{
                "TEST_VAR": "test_value",
                "PATH": "/usr/bin:/bin"
            };

            let options = ExecuteOptions()
                .args(args)
                .env(env)
                .build();

            let result = file_handle.execute(options);

            let exit_code = result.exit_code;
            let stdout = result.stdout;
            let stderr = result.stderr;

            result
        "#,
    );

    assert!(result.is_ok(), "Error: {:?}", result.err());
    let exec_result = result.unwrap();

    assert_eq!(*exec_result.exit_code(), 0);
    let stdout = exec_result.stdout().trim();
    assert!(stdout.contains("Hello"));
    assert!(stdout.contains("World"));
    assert_eq!(exec_result.stderr(), "");
}

/// Given: A file handle to a non-executable file
/// When: Attempting to execute it via Rhai
/// Then: Returns execution failure with non-zero exit code
#[test]
fn test_rhai_execute_error() {
    let (mut scope, engine) = create_temp_test_env();

    let result = engine.eval_with_scope::<ExecuteResult>(
        &mut scope,
        r#"
            let dir_config = DirConfig()
                .path(temp_dir_path)
                .build();
            let dir_handle = dir_config.open(OpenDirOptions().create(true).build());

            let file_handle = dir_handle.open_file("not_executable.txt", OpenFileOptions().create(true).write(true).build());
            file_handle = file_handle.write("This is not an executable file");
            
            let file_handle = dir_handle.open_file("not_executable.txt", OpenFileOptions().read(true).build());
            let options = ExecuteOptions().build();

            file_handle.execute(options)
        "#,
    );

    assert!(
        result.is_ok(),
        "Script execution failed: {:?}",
        result.err()
    );
    let exec_result = result.unwrap();
    assert_eq!(*exec_result.exit_code(), 1);
}

/// Given: ExecuteOptions builder
/// When: Setting user, group, and capabilities options via Rhai
/// Then: Builds ExecuteOptions successfully with setters
#[test]
fn test_rhai_execute_options_setters() {
    let engine = create_test_engine_and_register();

    let result = engine.eval::<()>(
        r#"
            let caps = [
                "CAP_DAC_OVERRIDE",
                "CAP_NET_ADMIN"
            ];
            
            let options = ExecuteOptions()
                .user("testuser")
                .group("testgroup")
                .capabilities(caps)
                .build()
        "#,
    );

    assert!(result.is_ok());
}

/// Given: ExecuteOptions builder with invalid input
/// When: Building the options with the invalid input
/// Then: Validation fails with appropriate error message
#[rstest]
#[case(
    "Non-string argument key",
    r#"ExecuteOptions().args([[123]]).build();"#,
    "Argument key must be a string"
)]
#[case(
    "Non-string argument value",
    r#"ExecuteOptions().args([["key", 123]]).build();"#,
    "Argument value must be a string"
)]
#[case(
    "Empty environment variable key",
    r#"ExecuteOptions().env(#{"": "value"}).build();"#,
    "Environment variable at index 0 should have non-empty key and value"
)]
#[case(
    "Non-string environment variable value",
    r#"ExecuteOptions().env(#{"KEY": 123}).build();"#,
    "Environment variable value for key 'KEY' must be a string"
)]
#[case(
    "Invalid capability string",
    r#"ExecuteOptions().capabilities(["NOT_A_CAPABILITY"]).build();"#,
    "Invalid capability format: 'NOT_A_CAPABILITY'"
)]
#[case(
    "Non-string capability",
    r#"ExecuteOptions().capabilities([123]).build();"#,
    "Capability at index 0 must be a string"
)]
#[case(
    "Empty argument array",
    r#"ExecuteOptions().args([[]]).build();"#,
    "Argument array at index 0 cannot be empty"
)]
#[case(
    "Argument array with more than 2 elements",
    r#"ExecuteOptions().args([["key", "value1", "value2"]]).build();"#,
    "Argument array at index 0 cannot have more than 2 elements"
)]
#[case(
    "Non-string and non-array argument",
    r#"ExecuteOptions().args([123]).build();"#,
    "Argument at index 0 must be a string or an array"
)]
fn test_rhai_execute_validation_errors(
    #[case] case: &str,
    #[case] script: &str,
    #[case] expected_error: &str,
) {
    let engine = create_test_engine_and_register();

    let result = engine.eval::<()>(script);

    assert!(result.is_err(), "Expected failure for {}", case);
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains(expected_error),
        "Expected message '{}' to contain '{}' for case '{}'",
        error_message,
        expected_error,
        case
    );
}

/// Given: an ExecuteResult from running echo
/// When: calling to_map() on it
/// Then: the map contains the correct serialized fields
#[test]
fn test_execute_result_to_map() {
    let engine = create_test_engine_and_register();
    let mut scope = rhai::Scope::new();

    let result = engine.eval_with_scope::<rhai::Map>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path("/usr/bin")
                .build().open(OpenDirOptions().build());
            let fh = dir_handle.open_file("echo", OpenFileOptions().read(true).build());
            let result = fh.execute(ExecuteOptions().args(["hello"]).build());

            let expected = #{
                "exit_code": result.exit_code,
                "stdout": result.stdout,
                "stderr": result.stderr,
            };

            #{
                "expected": expected.to_json(),
                "actual": result.to_map().to_json()
            }
        "#,
    );

    assert!(result.is_ok(), "Error: {:?}", result.err());
    let map = result.unwrap();
    let expected: String = map.get("expected").unwrap().clone().into_string().unwrap();
    let actual: String = map.get("actual").unwrap().clone().into_string().unwrap();
    assert_eq!(expected, actual);
}

/// Given: an ElfInfo from elf_info() on a binary
/// When: calling to_map() on it
/// Then: the map contains the correct serialized fields
#[test]
fn test_elf_info_to_map() {
    let engine = create_test_engine_and_register();
    let mut scope = rhai::Scope::new();

    let result = engine.eval_with_scope::<rhai::Map>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path("/usr/bin")
                .build().open(OpenDirOptions().build());
            let fh = dir_handle.open_file("echo", OpenFileOptions().read(true).build());
            let info = fh.elf_info();

            let expected = #{
                "execfn": info.execfn,
                "platform": info.platform,
                "interpreter": info.interpreter,
                "is_64bit": info.is_64bit,
            };

            #{
                "expected": expected.to_json(),
                "actual": info.to_map().to_json()
            }
        "#,
    );

    assert!(result.is_ok(), "Error: {:?}", result.err());
    let map = result.unwrap();
    let expected: String = map.get("expected").unwrap().clone().into_string().unwrap();
    let actual: String = map.get("actual").unwrap().clone().into_string().unwrap();
    assert_eq!(expected, actual);
}
