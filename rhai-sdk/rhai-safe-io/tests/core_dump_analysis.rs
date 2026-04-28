use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::get_test_rex_principal;
use rex_test_utils::io::create_temp_dir_and_path;
use rex_test_utils::rhai::common::{
    create_test_cedar_auth_with_policy, create_test_engine_with_auth, to_eval_error,
};
use rhai::{EvalAltResult, Map, Scope};
use std::{fs, path::Path, process::Command};

fn should_skip_tests() -> bool {
    // output == empty => gdb doesn't exist
    Command::new("command")
        .args(["-v", "gdb"])
        .output()
        .map(|output| String::from_utf8(output.stdout).unwrap_or("".to_string()) == "")
        .unwrap_or(false)
}

/// Given: A Rhai script that uses CoreDump API
/// When: Executing the script with proper authorization
/// Then: Successfully creates CoreDump and extracts backtrace information
#[test]
fn test_rhai_core_dump_backtrace() -> Result<(), Box<EvalAltResult>> {
    if should_skip_tests() {
        println!("Skipping GDB test for this platform");
        return Ok(());
    } else {
        println!("Running GDB test for this platform");
    }

    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;
    fs::create_dir_all(&temp_dir).map_err(to_eval_error)?;

    let Some((exe_path, core_path)) = setup_exe_and_core_file(&temp_dir_path)? else {
        return Ok(());
    };

    let principal = get_test_rex_principal();
    let policy = default_allow_gdb_policy(&principal, &temp_dir_path);
    let cedar_auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(cedar_auth);

    let script = r#"
        let core_dump = CoreDump(exe_path, core_dump_path);
        let backtrace = core_dump.backtrace();

        let pid = backtrace.pid;
        
        let threads = backtrace.threads;
        let thread_count = threads.len();
        let main_thread = threads[0];
        let thread_id = main_thread.id;
        let thread_tid = main_thread.tid;

        // since there's only one function call, there should only be one frame
        let frames = main_thread.frames;
        let frame_count = frames.len();
        let main_frame = frames[0];
        let function_name = main_frame.function_name;
        let source = main_frame.source;
        let line_number = main_frame.line_number;
        let instruction_pointer = main_frame.instruction_ptr;
        let frame_number = main_frame.frame_number;
        
        #{
            "thread_count": thread_count, 
            "frame_count": frame_count,
            "pid": pid,
            "thread_id": thread_id,
            "thread_tid": thread_tid,
            "function_name": function_name,
            "source": source,
            "line_number": line_number,
            "instruction_pointer": instruction_pointer,
            "frame_number": frame_number
        }
    "#;

    let mut scope = Scope::new();
    scope.push_constant("exe_path", exe_path);
    scope.push_constant("core_dump_path", core_path);

    let result: Map = engine.eval_with_scope::<Map>(&mut scope, &script)?;

    assert_eq!(result.get("thread_count").unwrap().as_int().unwrap(), 1);
    assert_eq!(result.get("frame_count").unwrap().as_int().unwrap(), 1);
    assert!(result.get("pid").unwrap().is_unit()); // this is one of the cases where the core dump doesn't record the pid or the thread tid
    assert!(result.get("thread_tid").unwrap().is_unit());
    assert_eq!(result.get("thread_id").unwrap().as_int().unwrap(), 1);
    assert_eq!(
        result
            .get("function_name")
            .unwrap()
            .clone()
            .into_string()
            .unwrap(),
        "main"
    );
    assert_eq!(
        result.get("source").unwrap().clone().into_string().unwrap(),
        "crash.c"
    );
    assert_eq!(result.get("line_number").unwrap().as_int().unwrap(), 9);
    assert!(
        result
            .get("instruction_pointer")
            .unwrap()
            .clone()
            .into_string()
            .unwrap()
            .starts_with("0x")
    );
    assert_eq!(result.get("frame_number").unwrap().as_int().unwrap(), 0);

    Ok(())
}

/// Given: A rhai script that uses the CoreDump backtrace API
/// When: the core dump is invalid
/// Then: an error is returned
#[test]
fn test_rhai_core_dump_backtrace_parsing_error() -> Result<(), Box<EvalAltResult>> {
    if should_skip_tests() {
        println!("Skipping GDB test for this platform");
        return Ok(());
    } else {
        println!("Running GDB test for this platform");
    }

    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;
    fs::create_dir_all(&temp_dir).map_err(to_eval_error)?;

    let Some((exe_path, core_path)) = setup_exe_and_core_file(&temp_dir_path)? else {
        return Ok(());
    };

    // Overwrite the core dump file to be invalid (just some random text)
    fs::write(&core_path, "This is not a valid core dump file").map_err(to_eval_error)?;

    let principal = get_test_rex_principal();
    let policy = default_allow_gdb_policy(&principal, &temp_dir_path);
    let cedar_auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(cedar_auth);

    let script = r#"
        let core_dump = CoreDump(exe_path, core_path);
        let backtrace = core_dump.backtrace();
    "#;

    let mut scope = Scope::new();
    scope.push_constant("exe_path", exe_path);
    scope.push_constant("core_path", core_path);

    // This should fail due to invalid core dump
    let result = engine.eval_with_scope::<Map>(&mut scope, &script);
    assert!(result.is_err());

    Ok(())
}

/// Given: A Rhai script that uses CoreDump variable extraction
/// When: Executing the script with proper authorization  
/// Then: Successfully extracts variable values from specific frames
#[test]
fn test_rhai_core_dump_variables() -> Result<(), Box<EvalAltResult>> {
    if should_skip_tests() {
        println!("Skipping GDB test for this platform");
        return Ok(());
    } else {
        println!("Running GDB test for this platform");
    }

    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;
    fs::create_dir_all(&temp_dir).map_err(to_eval_error)?;

    let Some((exe_path, core_path)) = setup_exe_and_core_file(&temp_dir_path)? else {
        return Ok(());
    };

    let principal = get_test_rex_principal();
    let policy = default_allow_gdb_policy(&principal, &temp_dir_path);
    let cedar_auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(cedar_auth);
    let script = r#"
        let core_dump = CoreDump(exe_path, core_dump_path);
        let variables = ["x"];
        let result = core_dump.get_variables(0, variables);
        
        result
    "#;

    let mut scope = Scope::new();
    scope.push_constant("exe_path", exe_path);
    scope.push_constant("core_dump_path", core_path);

    let result: Map = engine.eval_with_scope::<Map>(&mut scope, &script)?;

    assert_eq!(result.len(), 1);
    assert!(result.contains_key("x"));
    assert!(result.get("x").is_some());
    assert_eq!(
        result.get("x").unwrap().clone().into_string().unwrap(),
        "42"
    );

    Ok(())
}

/// Given: A Rhai script that uses CoreDump variable extraction for a specific thread id
/// When: Executing the script with proper authorization  
/// Then: Successfully extracts variable values from specific frames
#[test]
fn test_rhai_core_dump_variables_with_thread_id() -> Result<(), Box<EvalAltResult>> {
    if should_skip_tests() {
        println!("Skipping GDB test for this platform");
        return Ok(());
    } else {
        println!("Running GDB test for this platform");
    }

    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;
    fs::create_dir_all(&temp_dir).map_err(to_eval_error)?;

    let Some((exe_path, core_path)) = setup_exe_and_core_file(&temp_dir_path)? else {
        return Ok(());
    };

    let principal = get_test_rex_principal();
    let policy = default_allow_gdb_policy(&principal, &temp_dir_path);
    let cedar_auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(cedar_auth);
    let script = r#"
        let core_dump = CoreDump(exe_path, core_dump_path);
        let variables = ["x"];
        let result = core_dump.get_variables(1, 0, variables);
        
        result
    "#;

    let mut scope = Scope::new();
    scope.push_constant("exe_path", exe_path);
    scope.push_constant("core_dump_path", core_path);

    let result: Map = engine.eval_with_scope::<Map>(&mut scope, &script)?;

    assert_eq!(result.len(), 1);
    assert!(result.contains_key("x"));
    assert!(result.get("x").is_some());
    assert_eq!(
        result.get("x").unwrap().clone().into_string().unwrap(),
        "42"
    );

    Ok(())
}

/// Given: A Rhai script that uses CoreDump variable extraction
/// When: we search for a variable that doesn't exist
/// Then: the variable value is empty
#[test]
fn test_rhai_core_dump_variables_invalid_variable() -> Result<(), Box<EvalAltResult>> {
    if should_skip_tests() {
        println!("Skipping GDB test for this platform");
        return Ok(());
    } else {
        println!("Running GDB test for this platform");
    }

    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;
    fs::create_dir_all(&temp_dir).map_err(to_eval_error)?;

    let Some((exe_path, core_path)) = setup_exe_and_core_file(&temp_dir_path)? else {
        return Ok(());
    };

    let principal = get_test_rex_principal();
    let policy = default_allow_gdb_policy(&principal, &temp_dir_path);
    let cedar_auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(cedar_auth);

    let script = r#"
        let core_dump = CoreDump(exe_path, core_dump_path);
        let variables = ["nonexistent_variable"];
        let result = core_dump.get_variables(0, variables);
        
        result
    "#;

    let mut scope = Scope::new();
    scope.push_constant("exe_path", exe_path);
    scope.push_constant("core_dump_path", core_path);

    let result: Map = engine.eval_with_scope::<Map>(&mut scope, &script)?;

    assert_eq!(result.len(), 0);
    Ok(())
}

/// Given: A Rhai script that uses CoreDump variable extraction for a thread id that doesn't exist
/// When: Executing the script with proper authorization  
/// Then: the thread defaults to the main thread (#1)
#[test]
fn test_rhai_core_dump_variables_with_nonexistent_thread_id() -> Result<(), Box<EvalAltResult>> {
    if should_skip_tests() {
        println!("Skipping GDB test for this platform");
        return Ok(());
    } else {
        println!("Running GDB test for this platform");
    }

    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;
    fs::create_dir_all(&temp_dir).map_err(to_eval_error)?;

    let Some((exe_path, core_path)) = setup_exe_and_core_file(&temp_dir_path)? else {
        return Ok(());
    };

    let principal = get_test_rex_principal();
    let policy = default_allow_gdb_policy(&principal, &temp_dir_path);
    let cedar_auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(cedar_auth);
    let script = r#"
        let core_dump = CoreDump(exe_path, core_dump_path);
        let variables = ["x"];
        let result = core_dump.get_variables(3, 0, variables);
        
        result
    "#;

    let mut scope = Scope::new();
    scope.push_constant("exe_path", exe_path);
    scope.push_constant("core_dump_path", core_path);

    let result: Map = engine.eval_with_scope::<Map>(&mut scope, &script)?;

    assert_eq!(result.len(), 1);
    assert!(result.contains_key("x"));
    assert!(result.get("x").is_some());
    assert_eq!(
        result.get("x").unwrap().clone().into_string().unwrap(),
        "42"
    );

    Ok(())
}

/// Compiles and runs the crash.c file in tests/fixtures/core_dump_analysis, then returns the location of the generated exe file and core dump.
/// Returns None if the core dump was not generated (e.g., on CI environments where core dumps are piped to a handler).
fn setup_exe_and_core_file(
    temp_dir_path: &str,
) -> Result<Option<(String, String)>, Box<EvalAltResult>> {
    let exe_path = format!("{}/crash", temp_dir_path);
    let c_path = format!("{}/crash.c", temp_dir_path);
    fs::copy("tests/fixtures/core_dump_analysis/crash.c", &c_path).map_err(to_eval_error)?;

    Command::new("gcc")
        .current_dir(&temp_dir_path)
        .args(["-g", "-o", "crash", "crash.c"])
        .output()
        .map_err(to_eval_error)?;

    Command::new("bash")
        .current_dir(&temp_dir_path)
        .args([
            "-c",
            format!("ulimit -c unlimited && {}/crash || true", &temp_dir_path).as_str(),
        ])
        .output()
        .map_err(to_eval_error)?;

    let dir_entries = fs::read_dir(Path::new(&temp_dir_path)).map_err(to_eval_error)?;
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

/// Given: a CoreDump object
/// When: calling to_map() on it
/// Then: the map contains exe_path and core_dump_path (handles are skipped)
#[test]
fn test_core_dump_to_map() -> Result<(), Box<EvalAltResult>> {
    if should_skip_tests() {
        println!("Skipping GDB test for this platform");
        return Ok(());
    }

    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;
    fs::create_dir_all(&temp_dir).map_err(to_eval_error)?;

    let principal = get_test_rex_principal();
    let policy = default_allow_gdb_policy(&principal, &temp_dir_path);
    let cedar_auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(cedar_auth);

    let mut scope = Scope::new();

    let result = engine.eval_with_scope::<Map>(
        &mut scope,
        r#"
            let cd = CoreDump("/some/exe", "/some/core");
            let expected = #{
                "exe_path": "/some/exe",
                "core_dump_path": "/some/core",
            };
            #{
                "expected": expected.to_json(),
                "actual": cd.to_map().to_json()
            }
        "#,
    )?;

    let expected: String = result.get("expected").unwrap().clone().into_string()?;
    let actual: String = result.get("actual").unwrap().clone().into_string()?;
    assert_eq!(expected, actual);
    Ok(())
}

/// Given: a TracedProcess from a core dump backtrace
/// When: calling to_map() on TracedProcess, TracedThread, and Frame
/// Then: the maps contain the correct serialized fields
#[test]
fn test_traced_process_to_map() -> Result<(), Box<EvalAltResult>> {
    if should_skip_tests() {
        println!("Skipping GDB test for this platform");
        return Ok(());
    }

    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;
    fs::create_dir_all(&temp_dir).map_err(to_eval_error)?;
    let Some((exe_path, core_path)) = setup_exe_and_core_file(&temp_dir_path)? else {
        return Ok(());
    };

    let principal = get_test_rex_principal();
    let policy = default_allow_gdb_policy(&principal, &temp_dir_path);
    let cedar_auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(cedar_auth);

    let mut scope = Scope::new();
    scope.push_constant("exe_path", exe_path);
    scope.push_constant("core_dump_path", core_path);

    let result = engine.eval_with_scope::<Map>(
        &mut scope,
        r#"
            let cd = CoreDump(exe_path, core_dump_path);
            let bt = cd.backtrace();
            let process_map = bt.to_map();

            // Validate sub-level to_map() consistency
            let thr = bt.threads[0];
            let frame_map = thr.frames[0].to_map();
            let thread_map = thr.to_map();

            if frame_map != thread_map["frames"][0] {
                throw "frame.to_map() should equal thread.to_map()['frames'][0]";
            }
            if thread_map != process_map["threads"][0] {
                throw "thread.to_map() should equal process.to_map()['threads'][0]";
            }

            // Build expected from getters
            let expected = #{
                "pid": bt.pid,
                "threads": bt.threads.map(|thr| {
                    return #{
                        "id": thr.id,
                        "tid": thr.tid,
                        "frames": thr.frames.map(|frame| {
                            return #{
                                "frame_number": frame.frame_number,
                                "function_name": frame.function_name,
                                "instruction_ptr": frame.instruction_ptr,
                                "source": frame.source,
                                "line_number": frame.line_number,
                            };
                        }),
                    };
                }),
            };

            #{
                "expected": expected.to_json(),
                "actual": process_map.to_json(),
            }
        "#,
    )?;

    let expected: String = result.get("expected").unwrap().clone().into_string()?;
    let actual: String = result.get("actual").unwrap().clone().into_string()?;
    assert_eq!(expected, actual);

    Ok(())
}
