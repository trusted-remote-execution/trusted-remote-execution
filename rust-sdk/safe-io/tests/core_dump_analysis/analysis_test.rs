use anyhow::Result;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{TestCedarAuthBuilder, get_test_rex_principal};
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::io::create_temp_dir_and_path;
use rust_safe_io::CoreDump;
use rust_safe_io::errors::RustSafeIoError;
use std::fs;
use std::path::Path;
use std::process::Command;

fn should_skip_tests() -> bool {
    !std::path::Path::new("/usr/bin/gdb").exists()
}

/// Given: A compiled C program that crashes and generates a core dump
/// When: Using CoreDump API to analyze the backtrace and variables
/// Then: Successfully extracts meaningful debugging information from the core dump
#[test]
fn test_gdb_core_dump_analysis() -> Result<()> {
    if should_skip_tests() {
        println!("Skipping GDB test for this platform");
        return Ok(());
    } else {
        println!("Running GDB test for this platform");
    }

    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    fs::create_dir_all(&temp_dir).unwrap();

    let Some((exe_path, core_path)) = setup_exe_and_core_file(&temp_dir_path)? else {
        return Ok(());
    };

    let principal = get_test_rex_principal();
    let cedar_auth = TestCedarAuthBuilder::default()
        .policy(default_allow_gdb_policy(&principal, &temp_dir_path))
        .build()
        .unwrap()
        .create();

    // Test the CoreDump API with real core dump
    let mut core_dump = CoreDump::new(exe_path.to_string(), core_path.to_string());

    // Test backtrace analysis
    let _ = core_dump.backtrace(&cedar_auth)?;
    // Validate that lazy initialization works by calling again
    let backtrace_result = core_dump.backtrace(&cedar_auth)?;

    assert_eq!(backtrace_result.threads().len(), 1);
    let main_thread = &backtrace_result.threads()[0];

    assert_eq!(main_thread.frames().len(), 1);
    let main_frame = &main_thread.frames()[0];
    assert_eq!(main_frame.function_name(), "main");
    assert_eq!(*main_frame.frame_number(), 0);
    assert_eq!(main_frame.source().clone().unwrap(), "crash.c");
    assert_eq!(main_frame.line_number().unwrap(), 9);
    assert!(
        main_frame
            .instruction_ptr()
            .clone()
            .unwrap()
            .starts_with("0x")
    );

    // Test variable analysis
    let vars = vec!["x".to_string()];
    let _ = core_dump.get_variables(
        &cedar_auth,
        0, // frame 0
        vars.clone(),
    )?;
    // Validate that lazy initialization works by calling again
    let variables = core_dump.get_variables(
        &cedar_auth,
        0, // frame 0
        vars,
    )?;

    assert!(variables.contains_key("x"));
    assert_eq!(variables.get("x"), Some(&"42".to_string()));

    // Test variable analysis with thread_id
    let vars = vec!["x".to_string()];
    let variables = core_dump.get_variables_with_thread(
        &cedar_auth,
        1, // thread 1
        0, // frame 0
        vars,
    )?;
    assert!(variables.contains_key("x"));
    assert_eq!(variables.get("x"), Some(&"42".to_string()));

    // If an invalid thread id is specified, gdb defaults to thread 1
    let vars = vec!["x".to_string()];
    let variables = core_dump.get_variables_with_thread(
        &cedar_auth,
        5, // thread 1
        0, // frame 0
        vars,
    )?;
    assert!(variables.contains_key("x"));
    assert_eq!(variables.get("x"), Some(&"42".to_string()));

    // Clean up
    let _ = fs::remove_dir_all(&temp_dir);

    Ok(())
}

/// Given: an invalid core dump file
/// When: CoreDump is used to analyze the backtrace
/// Then: An error is returned
#[test]
fn test_invalid_core_dump() -> Result<()> {
    if should_skip_tests() {
        println!("Skipping GDB test for this platform");
        return Ok(());
    }

    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    fs::create_dir_all(&temp_dir).unwrap();

    let Some((exe_path, core_path)) = setup_exe_and_core_file(&temp_dir_path)? else {
        return Ok(());
    };

    let invalid_core_dump_content = "not a real core dump";
    fs::write(&core_path, invalid_core_dump_content)?;

    let principal = get_test_rex_principal();
    let cedar_auth = TestCedarAuthBuilder::default()
        .policy(default_allow_gdb_policy(&principal, &temp_dir_path))
        .build()
        .unwrap()
        .create();

    let mut core_dump = CoreDump::new(exe_path.to_string(), core_path.to_string());
    let backtrace_result = core_dump.backtrace(&cedar_auth);
    assert_error_contains(
        backtrace_result,
        format!("Unable to parse trace for executable {exe_path} and core file {core_path}")
            .as_str(),
    );

    Ok(())
}

/// Given: an invalid exe file
/// When: CoreDump is used to analyze the backtrace
/// Then: An error is returned
#[test]
fn test_invalid_exe() -> Result<()> {
    if should_skip_tests() {
        println!("Skipping GDB test for this platform");
        return Ok(());
    }

    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    fs::create_dir_all(&temp_dir).unwrap();

    let Some((exe_path, core_path)) = setup_exe_and_core_file(&temp_dir_path)? else {
        return Ok(());
    };

    let invalid_exe_content = "not a real exe";
    fs::write(&exe_path, invalid_exe_content)?;

    let principal = get_test_rex_principal();
    let cedar_auth = TestCedarAuthBuilder::default()
        .policy(default_allow_gdb_policy(&principal, &temp_dir_path))
        .build()
        .unwrap()
        .create();

    let mut core_dump = CoreDump::new(exe_path.to_string(), core_path.to_string());
    let backtrace_result = core_dump.backtrace(&cedar_auth);
    assert_error_contains(backtrace_result, "Invalid executable");

    Ok(())
}

mod auth_tests {
    use super::*;

    /// Given: A cedar policy that forbids various permissions required to analyze a core dump
    /// When: Using CoreDump API to analyze the backtrace and variables
    /// Then: An authorization error is returned
    #[test]
    fn test_authorization_failures() -> Result<()> {
        if should_skip_tests() {
            println!("Skipping GDB test for this platform");
            return Ok(());
        }

        let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
        fs::create_dir_all(&temp_dir).unwrap();

        // see tests/fixures/core_dump_analysis/crash.c for the source code that generated this exe + core dump
        // to regenerate the exe, run `gcc -g -o $OUTPUT_LOCATION crash.c`
        // to regenerate the core file, run `bash -c "ulimit -c unlimited && $OUTPUT_LOCATION || true`
        let Some((exe_path, core_path)) = setup_exe_and_core_file(&temp_dir_path)? else {
            return Ok(());
        };

        let principal = get_test_rex_principal();
        let default_policy = default_allow_gdb_policy(&principal, &temp_dir_path);

        let forbid_policy_template = r#"forbid(
            principal,
            action == $$ACTION$$,
            resource == file_system::File::"$$FORBID_FILE_LOCATION$$"
        );"#;

        let test_cases = vec![
            (FilesystemAction::Open, exe_path.clone()),
            (FilesystemAction::Read, exe_path.clone()),
            (FilesystemAction::Open, core_path.clone()),
            (FilesystemAction::Read, core_path.clone()),
            (FilesystemAction::Open, "/usr/bin/gdb".to_string()),
        ];

        for (action, forbid_file_location) in test_cases {
            let policy = default_policy.clone()
                + forbid_policy_template
                    .replace("$$ACTION$$", &action.to_string())
                    .replace("$$FORBID_FILE_LOCATION$$", &forbid_file_location)
                    .as_str();

            let cedar_auth = TestCedarAuthBuilder::default()
                .policy(policy)
                .build()
                .unwrap()
                .create();

            // Test the CoreDump API with real core dump
            let mut core_dump = CoreDump::new(exe_path.to_string(), core_path.to_string());

            let expected_error_message = format!(
                "Permission denied: {principal} unauthorized to perform {action} for file_system::File::{forbid_file_location}"
            );
            let bt_result = core_dump.backtrace(&cedar_auth);
            assert_error_contains(bt_result, &expected_error_message);
        }

        // Clean up
        let _ = fs::remove_dir_all(&temp_dir);

        Ok(())
    }
}

fn default_allow_gdb_policy(principal: &str, temp_dir_path: &str) -> String {
    format!(
        r#"permit(
            principal == User::"{principal}",
            action in [{}, {}],
            resource in file_system::Dir::"{temp_dir_path}"
        );

        permit(
            principal == User::"{principal}",
            action in [{}],
            resource == file_system::Dir::"/usr/bin"
        );

        permit(
            principal == User::"{principal}",
            action in [{}, {}],
            resource == file_system::File::"/usr/bin/gdb"
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Read,
        FilesystemAction::Open,
        FilesystemAction::Open,
        FilesystemAction::Execute
    )
}

/// Compiles and runs the crash.c file in tests/fixtures/core_dump_analysis, then returns the location of the generated exe file and core dump.
/// Returns None if the core dump was not generated (e.g., on CI environments where core dumps are piped to a handler).
fn setup_exe_and_core_file(
    temp_dir_path: &str,
) -> Result<Option<(String, String)>, RustSafeIoError> {
    let exe_path = format!("{}/crash", temp_dir_path);
    let c_path = format!("{}/crash.c", temp_dir_path);
    fs::copy("tests/fixtures/core_dump_analysis/crash.c", &c_path)?;

    Command::new("gcc")
        .current_dir(&temp_dir_path)
        .args(["-g", "-o", "crash", "crash.c"])
        .output()?;

    Command::new("bash")
        .current_dir(&temp_dir_path)
        .args([
            "-c",
            format!("ulimit -c unlimited && {}/crash || true", &temp_dir_path).as_str(),
        ])
        .output()?;

    let dir_entries = fs::read_dir(Path::new(&temp_dir_path))?;
    let core_file = dir_entries
        .filter_map(|r| r.ok())
        .find(|e| e.file_name().to_string_lossy().starts_with("core"));

    match core_file {
        Some(entry) => {
            let core_path = format!("{}/{}", temp_dir_path, entry.file_name().to_string_lossy());
            Ok(Some((exe_path, core_path)))
        }
        None => {
            println!("Skipping: core dump was not generated (likely disabled in this environment)");
            Ok(None)
        }
    }
}
