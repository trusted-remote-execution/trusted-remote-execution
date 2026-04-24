use assertables::assert_contains;
use rex_cedar_auth::test_utils::get_default_test_rex_policy;
use rex_logger::{LoggingOptionBuilder, get_script_handle, init_logger};
use rex_runner_registrar::rhai_engine_builder::{RhaiContext, RhaiEngineBuilder};
use rex_test_utils::io::create_and_write_to_test_file;
use rex_test_utils::rhai::common::create_test_engine_and_register;
use rhai::{Dynamic, EvalAltResult, Position, Scope};
use sealed_test::prelude::{rusty_fork_test, sealed_test};

#[allow(clippy::needless_pass_by_value)]
pub fn to_eval_error(e: impl ToString) -> Box<EvalAltResult> {
    Box::new(EvalAltResult::ErrorRuntime(
        Dynamic::from(e.to_string()),
        Position::NONE,
    ))
}

/// Creates and configures a Rhai engine with registered safe I/O functions for
/// testing.
///
/// This function sets up a Rhai scripting engine with file and directory operations
/// that are protected by Cedar authorization checks. It is designed for use in doctests
/// and integration tests for Rhai.
///
/// # Returns
/// A configured Rhai [`Engine`] with registered safe I/O functions
///
#[allow(clippy::expect_used)]
pub fn create_test_engine() -> RhaiContext {
    let test_policy = &get_default_test_rex_policy();
    RhaiEngineBuilder::with_policy_content(test_policy.to_string())
        .create()
        .expect("Failed to create test engine")
}

/// Given: A new Rhai engine is created and registered
/// When: A script is compiled that tries to use a variable before declaring it
/// Then: The compilation fails with an error
#[test]
fn test_engine_strict_variable_mode_enabled() -> Result<(), Box<EvalAltResult>> {
    let mut engine = create_test_engine_and_register();
    engine.set_strict_variables(true);

    let result = engine.compile(
        r#"
            info(`${text}`);
            let text = read_file("/tmp", "test.txt");
        "#,
    );

    assert!(
        result.is_err(),
        "We expect the compilation to fail because of undeclared variable in script"
    );
    let error = result.unwrap_err().to_string();
    assert_contains!(error, "Undefined variable:");
    Ok(())
}

#[cfg(target_os = "linux")] // macOS /var -> /private/var symlink triggers path traversal detection
/// Given: A file that is a real file and a real directory
/// When: The file is read with safe I/O plugin in Rhai
/// Then: The file is read correctly with no errors in a Rhai script
#[test]
fn test_safe_io_module_registered() -> Result<(), Box<EvalAltResult>> {
    let context = create_test_engine();

    let temp_dir = assert_fs::TempDir::new().unwrap();
    let file_name = "example_file.txt";

    let temp_dir_path =
        create_and_write_to_test_file(&temp_dir, file_name).map_err(to_eval_error)?;

    let mut scope = Scope::new();
    scope.push("file_name", file_name);
    scope.push("directory_path", temp_dir_path);

    let result = context.engine().eval_with_scope::<String>(
        &mut scope,
        r#"
            let dir_handle = DirConfig()
                .path(directory_path)
                .build().open(OpenDirOptions().build());
            let file_handle = dir_handle.open_file(file_name, OpenFileOptions().read(true).build());
            file_handle.read();
        "#,
    );
    assert!(
        result.is_ok(),
        "The engine couldn't execute the Rhai script"
    );

    temp_dir.close().unwrap();
    Ok(())
}

/// Given: A simple rhai script
/// When: logging methods are called in rhai script to log with log level set as DEBUG
/// Then: The statements are logged in memory except the trace log
#[sealed_test]
fn test_logging_in_script() -> Result<(), Box<EvalAltResult>> {
    let context = create_test_engine();
    let engine = context.engine();

    let config = LoggingOptionBuilder::default()
        .script_log(true)
        .console(false)
        .syslog(false)
        .build()
        .unwrap();

    let _ = init_logger(&config);

    let script = r#"
        trace("trace message");
        debug("debug message");
        info("info message");
        warn("warn message");
        error("error message");
    "#;

    let result = engine.eval::<()>(script);
    assert!(result.is_ok(), "Script should execute successfully");

    let handle = get_script_handle();
    assert!(handle.is_some());

    if let Some(h) = handle {
        let logs = h.get_logs();
        assert_eq!(logs.len(), 3, "Should have exactly 3 log messages");

        assert_eq!(
            logs[0].message, "info message",
            "log message doesn't match expected content"
        );

        assert_eq!(
            logs[1].message, "warn message",
            "log message doesn't match expected content"
        );

        assert_eq!(
            logs[2].message, "error message",
            "log message doesn't match expected content"
        );
    }

    Ok(())
}
