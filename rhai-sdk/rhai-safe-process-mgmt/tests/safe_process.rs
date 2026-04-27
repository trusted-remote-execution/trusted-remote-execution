#![cfg(target_os = "linux")]
use assert_fs::prelude::*;
use rex_cedar_auth::process::actions::ProcessAction;
use rex_cedar_auth::test_utils::get_test_rex_principal;
use rex_test_utils::rhai::common::{
    create_test_cedar_auth_with_policy, create_test_engine_and_register,
    create_test_engine_with_auth,
};
use rhai::{Array, EvalAltResult, Map, Scope};
use rstest::rstest;
use rust_safe_process_mgmt::{FuserInfo, ProcessInfo};
use std::process::{self, Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

/// Given: A Rhai engine with registered process management functions and a policy that allows listing processes
/// When: A script is run to get processes
/// Then: The script executes successfully and returns a list of processes with all required fields
#[test]
fn test_get_processes_success() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    // Test script that accesses all fields of a RhaiProcessInfo object
    let test_script = r#"
        let process_manager = ProcessManager();
        let processes = process_manager.processes();
        
        if len(processes) > 0 {{
            let process = processes[0];

            let pid = process.pid;
            let name = process.name;
            let ppid = process.ppid;
            let uid = process.uid;
            let username = process.username;
            let memory_usage = process.memory_usage;
            let memory_percent = process.memory_percent;
            let state = process.state;
            let command = process.command;

            process
        }} else {{
            // Return an empty array if no processes were found
            processes
        }}
    "#;

    let result = engine.eval_with_scope::<ProcessInfo>(&mut scope, &test_script)?;
    assert!(*result.pid() > 0);
    assert!(!result.name().is_empty());
    assert!(!result.username().is_empty());
    assert!(!result.state().is_empty());
    assert!(*result.memory_percent() >= 0.0);
    Ok(())
}

/// Given: A Rhai engine with registered process management functions
/// When: Getting all processes
/// Then: Should return a non-empty list of processes
#[test]
fn test_get_processes_count() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    let test_script = r#"
        let process_manager = ProcessManager();
        let processes = process_manager.processes();
        processes.len()
    "#;

    let count = engine.eval_with_scope::<i64>(&mut scope, test_script)?;
    assert!(count > 0, "Should find at least one process");

    Ok(())
}

/// Given: nsenter function with invalid namespace options (no namespaces enabled)
/// When: Calling nsenter with options that have no namespaces enabled
/// Then: Should return a validation error
#[test]
fn test_nsenter_option_validation_error() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let pm = ProcessManager();
            let processes = pm.processes();

            let current_pid = 1;
            let options = NamespaceOptions().pid(current_pid).build();
            
            pm.nsenter(options, || {
                "should not execute"
            })
        "#,
    );

    assert!(
        result.is_err(),
        "Expected validation error for no namespaces"
    );
    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("At least one namespace type (mount or net) must be enabled"),
        "Error should mention namespace validation: {error_msg}"
    );

    Ok(())
}

/// Given: nsenter function with different invalid PID values
/// When: Calling nsenter with invalid PIDs
/// Then: Should return appropriate PID validation errors
#[rstest]
#[case::negative_pid(-1, "Parameter conversion failed")]
#[case::zero_pid(0, "does not exist")]
#[case::very_large_pid(999999, "does not exist")]
fn test_nsenter_invalid_pid_errors(
    #[case] pid: i64,
    #[case] expected_error: &str,
) -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();
    scope.push("test_pid", pid);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let pm = ProcessManager();
            let processes = pm.processes();
            
            let options = NamespaceOptions().mount(true).pid(test_pid).build();
            
            pm.nsenter(options, || {
                "should not execute"
            })
        "#,
    );

    assert!(result.is_err(), "Expected error for invalid PID: {}", pid);
    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains(expected_error),
        "Error should contain '{}' for PID {}: {}",
        expected_error,
        pid,
        error_msg
    );

    Ok(())
}

/// Given: nsenter function with a nonexistent network namespace file
/// When: Calling nsenter with with a nonexistenet network namespace file
/// Then: Should return a namespace operation error
#[test]
fn test_nsenter_nonexistest_net_ns_name_error() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let pm = ProcessManager();
            let processes = pm.processes();

            let options = NamespaceOptions().net_ns_name("nonexistent-ns").build();
            
            pm.nsenter(options, || {
                "should not execute"
            })
        "#,
    );

    assert!(result.is_err(), "Expected namespace operation error");
    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("No such file or directory"),
        "Error should mention No such file or directory: {error_msg}"
    );

    Ok(())
}

/// Given: A Rhai engine with registered process management functions and a policy that allows listing file users
/// When: A script is run to get processes using a file or directory
/// Then: The script executes successfully and returns objects with all expected properties
#[test]
fn test_get_processes_using_inode_success() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    // Use the current directory as the path
    let path = ".";

    let test_script = format!(
        r#"
        let process_manager = ProcessManager();
        let processes = process_manager.processes_using_inode("{path}");
        
        if len(processes) > 0 {{
            let process = processes[0];

            let user = process.user;
            let pid = process.pid;
            let access = process.access;
            let command = process.command;

            processes[0]
        }} else {{
            // Return an empty array if no processes were found
            processes
        }}
        "#
    );

    let result = engine.eval_with_scope::<FuserInfo>(&mut scope, &test_script)?;
    assert!(*result.pid() > 0);
    Ok(())
}

/// Given: A Rhai engine with registered process management functions and a policy that allows listing file users
/// When: A script is run to get processes using a file or directory that does not exist
/// Then: The script fails as expected
#[test]
fn test_get_processes_using_inode_fail() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    let path = "/doesnotexist";

    let test_script = format!(
        r#"
        let process_manager = ProcessManager();
        process_manager.processes_using_inode("{}");
        "#,
        path
    );

    let result = engine.eval_with_scope::<FuserInfo>(&mut scope, &test_script);
    assert!(result.is_err());
    Ok(())
}

/// Given: A Rhai engine with registered process management functions and a valid KillOptions builder
/// When: A KillOptions object is built with valid parameters
/// Then: The build succeeds and returns a valid KillOptions object
#[test]
fn test_kill_options_builder_success() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let kill_options = KillOptions()
                .process_name("firefox")
                .signal(Signal::SIGTERM)
                .exact_match(true)
                .build();
        "#,
    );

    assert!(result.is_ok(), "Failed to build KillOptions: {:?}", result);
    Ok(())
}

/// Given: A Rhai engine with registered process management functions and a KillOptions builder
/// When: A KillOptions object is built with pid targeting
/// Then: The build succeeds and returns a valid KillOptions object
#[test]
fn test_kill_options_builder_with_pid() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let kill_options = KillOptions()
                .pid(1234)
                .signal(Signal::SIGTERM)
                .build();
        "#,
    );

    assert!(
        result.is_ok(),
        "Failed to build KillOptions with PID: {:?}",
        result
    );
    Ok(())
}

/// Given: A Rhai engine with registered process management functions and a KillOptions builder
/// When: A KillOptions object is built with username and command targeting
/// Then: The build succeeds and returns a valid KillOptions object
#[test]
fn test_kill_options_builder_with_username_and_command() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let kill_options = KillOptions()
                .username("testuser")
                .command("node /path/to/server.js")
                .signal(Signal::SIGKILL)
                .build();
        "#,
    );

    assert!(
        result.is_ok(),
        "Failed to build KillOptions with username and command: {:?}",
        result
    );
    Ok(())
}

/// Given: A Rhai engine with registered process management functions and a KillOptions builder
/// When: A KillOptions object is built without specifying a signal
/// Then: The build fails with an appropriate error message
#[test]
fn test_kill_options_builder_no_signal_error() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let kill_options = KillOptions()
                .pid(1234)
                .build();
        "#,
    );

    assert!(
        result.is_err(),
        "Should have failed when no signal specified"
    );
    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("signal is required"),
        "Error should mention signal is required"
    );
    Ok(())
}

/// Given: A Rhai engine with registered process management functions and a KillOptions builder
/// When: A KillOptions object is built with an invalid signal
/// Then: The build fails with an appropriate error message
#[test]
fn test_kill_options_builder_invalid_signal_error() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let kill_options = KillOptions()
                .pid(1234)
                .signal(Signal::SIGFAKE)
                .build();
        "#,
    );

    assert!(result.is_err(), "Should have failed with invalid signal");
    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("Variable not found: Signal::SIGFAKE"),
        "Error should mention invalid signal"
    );
    Ok(())
}

/// Given: A Rhai engine with registered process management functions and a KillOptions builder
/// When: A KillOptions object is built with     both pid and process_name (mutually exclusive)
/// Then: The build fails with an appropriate error message
#[test]
fn test_kill_options_builder_conflicting_targeting_error() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let kill_options = KillOptions()
                .pid(1234)
                .process_name("firefox")
                .signal(Signal::SIGTERM)
                .build();
        "#,
    );

    assert!(
        result.is_err(),
        "Should have failed with conflicting targeting methods"
    );
    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("pid cannot be used together with"),
        "Error should mention conflicting targeting"
    );
    Ok(())
}

/// Given: A Rhai engine with registered process management functions and a KillOptions builder
/// When: A KillOptions object is built with both process_name and command (mutually exclusive)
/// Then: The build fails with an appropriate error message
#[test]
fn test_kill_options_builder_process_name_and_command_error() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let kill_options = KillOptions()
                .process_name("firefox")
                .command("firefox --safe-mode")
                .signal(Signal::SIGTERM)
                .build();
        "#,
    );

    assert!(
        result.is_err(),
        "Should have failed with conflicting targeting methods"
    );
    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("process_name and command cannot be used together"),
        "Error should mention conflicting targeting"
    );
    Ok(())
}

/// Given: A Rhai engine with registered process management functions and a ProcessManager
/// When: A ProcessManager is created and processes() method is called
/// Then: The method succeeds and returns a list of processes
#[test]
fn test_process_manager_processes() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    let processes = engine.eval_with_scope::<Array>(
        &mut scope,
        r#"
            let process_manager = ProcessManager();
            process_manager.processes()
        "#,
    )?;

    assert!(
        !processes.is_empty(),
        "ProcessManager should return processes"
    );
    Ok(())
}

/// Given: A Rhai engine with registered process management functions and a ProcessManager
/// When: A ProcessManager is created and processes_using_inode() method is called
/// Then: The method succeeds and returns appropriate results
#[test]
fn test_process_manager_processes_using_inode() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    let result = engine.eval_with_scope::<Array>(
        &mut scope,
        r#"
            let process_manager = ProcessManager();
            process_manager.processes_using_inode(".")
        "#,
    );

    assert!(
        result.is_ok(),
        "ProcessManager processes_using_inode should succeed: {:?}",
        result
    );
    Ok(())
}

/// Given: A Rhai engine with registered process management functions and a policy that allows listing open files
/// When: A script is run to list open files in a directory
/// Then: The script executes successfully and returns objects with all expected properties
#[test]
fn test_process_manager_list_open_files() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    // Use the current directory as the path
    let path = ".";

    let test_script = format!(
        r#"
        let process_manager = ProcessManager();
        let options = LsofOptions().path("{path}").include_subdir(true).build();
        let open_files = process_manager.list_open_files(options);
        
        if len(open_files) > 0 {{
            let file = open_files[0];

            let pid = file.pid;
            let process_name = file.process_name;
            let user = file.user;
            let command = file.command;
            let file_path = file.file_path;
            let file_type = file.file_type;
            let access = file.access;

            open_files[0]
        }} else {{
            // Return an empty array if no files were found
            open_files
        }}
        "#
    );

    let result =
        engine.eval_with_scope::<rust_safe_process_mgmt::OpenFileInfo>(&mut scope, &test_script)?;
    assert!(result.pid > 0);
    Ok(())
}

/// Given: A Rhai engine with registered process management functions
/// When: A script is run to list open files by PID (a process we own)
/// Then: The script executes successfully and returns open files for that process
#[test]
fn test_process_manager_list_open_files_by_pid() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    let mut child = std::process::Command::new("sleep")
        .arg("300")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to spawn sleep");

    let pid = child.id();

    let test_script = format!(
        r#"
        let process_manager = ProcessManager();
        let options = LsofOptions().pid({pid}).build();
        let open_files = process_manager.list_open_files(options);
        open_files
        "#
    );

    let result = engine.eval_with_scope::<Array>(&mut scope, &test_script)?;
    assert!(!result.is_empty(), "Should have open files for PID {}", pid);

    let _ = child.kill();
    Ok(())
}

/// Given: A Rhai engine with registered process management functions
/// When: A script is run to list open files by an invalid PID
/// Then: The script fails with ProcessNotFound error
#[test]
fn test_process_manager_list_open_files_by_pid_fail() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    let test_script = r#"
        let process_manager = ProcessManager();
        let options = LsofOptions().pid(999999999).build();
        process_manager.list_open_files(options);
    "#;

    let result = engine.eval_with_scope::<Array>(&mut scope, test_script);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("Process not found"),
        "Error should contain 'Process not found', got: {}",
        err_msg
    );
    Ok(())
}

/// Given: A Rhai engine with registered process management functions and a policy that allows listing open files
/// When: A script is run to list open files in a directory that does not exist
/// Then: The script fails as expected
#[test]
fn test_process_manager_list_open_files_fail() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    let path = "/doesnotexist";

    let test_script = format!(
        r#"
        let process_manager = ProcessManager();
        let options = LsofOptions().path("{}").build();
        process_manager.list_open_files(options);
        "#,
        path
    );

    let result = engine.eval_with_scope::<Array>(&mut scope, &test_script);
    assert!(result.is_err());
    Ok(())
}

/// Given: A Rhai engine with registered process management functions and a ProcessManager
/// When: A ProcessManager is created and kill() method is called with a non-existent PID
/// Then: The method fails with an appropriate error message
#[test]
fn test_process_manager_kill_nonexistent_process() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    let result = engine.eval_with_scope::<Array>(
        &mut scope,
        r#"
            let process_manager = ProcessManager();
            let kill_options = KillOptions()
                .pid(999999)  // Very unlikely to exist
                .signal(Signal::SIGTERM)
                .build();
            process_manager.kill(kill_options)
        "#,
    );

    assert!(
        result.is_err(),
        "Should have failed when trying to kill non-existent process"
    );
    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("Process") && error_msg.contains("not found"),
        "Error should mention process not found"
    );
    Ok(())
}

/// Given: A Rhai engine with registered process management functions and a KillOptions builder
/// When: A KillOptions object is built with an invalid PID (negative number)
/// Then: The build fails with an appropriate error message
#[test]
fn test_kill_options_builder_invalid_pid_error() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let kill_options = KillOptions()
                .pid(-1234)
                .signal(Signal::SIGTERM)
                .build();
        "#,
    );

    assert!(result.is_err(), "Should have failed with negative PID");
    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("PID cannot be negative"),
        "Error should mention invalid PID"
    );
    Ok(())
}

/// Given: A Rhai engine with registered process management functions and a KillOptions builder
/// When: A KillOptions object is built with no targeting method specified
/// Then: The build fails with an appropriate error message
#[test]
fn test_kill_options_builder_no_targeting_method_error() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let kill_options = KillOptions()
                .signal(Signal::SIGTERM)
                .build();
        "#,
    );

    assert!(
        result.is_err(),
        "Should have failed when no targeting method specified"
    );
    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("At least one targeting method must be specified"),
        "Error should mention targeting method required"
    );
    Ok(())
}

/// Given: A ProcessManager instance
/// When: The ProcessManager is cloned
/// Then: The clone should work correctly and be independent
#[test]
fn test_process_manager_clone() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    let result = engine.eval_with_scope::<Array>(
        &mut scope,
        r#"
            let process_manager1 = ProcessManager();
            let process_manager2 = process_manager1;  // This triggers Clone
            
            // Both should work independently
            let processes1 = process_manager1.processes();
            let processes2 = process_manager2.processes();
            
            processes1
        "#,
    );

    assert!(result.is_ok(), "Clone should work properly: {:?}", result);
    let processes = result.unwrap();
    assert!(!processes.is_empty(), "Should return processes after clone");
    Ok(())
}

/// Given: A ProcessManager and a spawned sleep process
/// When: The kill method is called with PID targeting after finding the process in the process list
/// Then: The method should successfully kill the process and return information about the killed process
#[test]
fn test_process_manager_kill_success() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    let mut child = Command::new("sleep")
        .arg("60")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to spawn child process");

    let child_pid = child.id();
    sleep(Duration::from_millis(200));

    let kill_script = format!(
        r#"
        let process_manager = ProcessManager();
        let processes = process_manager.processes();
        let target_pid = {};
        let found = false;
        
        for process in processes {{
            if process.pid == target_pid {{
                found = true;
                break;
            }}
        }}
        
        if found {{
            let kill_options = KillOptions()
                .pid(target_pid)
                .signal(Signal::SIGTERM)
                .build();
            process_manager.kill(kill_options)
        }} else {{
            throw "Process not found";
        }}
    "#,
        child_pid
    );

    let result = engine.eval_with_scope::<Array>(&mut scope, &kill_script);

    let _ = child.kill();
    let _ = child.wait();

    match result {
        Ok(killed_processes) => {
            assert!(
                !killed_processes.is_empty(),
                "Should have killed the process"
            );
            let killed_process = killed_processes[0].clone().cast::<Map>();
            assert!(
                killed_process.contains_key("name"),
                "Should contain 'name' field"
            );
            assert!(
                killed_process.contains_key("pid"),
                "Should contain 'pid' field"
            );
            Ok(())
        }
        Err(e) => {
            let error_msg = e.to_string();
            assert!(
                error_msg.contains("not found")
                    || error_msg.contains("No such process")
                    || error_msg.contains("No matching processes found"),
                "Error should be about process not found: {}",
                error_msg
            );
            Err(e)
        }
    }
}

/// Given: A Rhai engine with registered process management functions and a policy that allows filesystem access
/// When: A script calls ipcs_info() to get System V IPC information
/// Then: The method executes successfully and returns IpcsInfo with all three IPC types accessible
#[test]
fn test_ipcs_info() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();

    let result = engine.eval::<String>(
        r#"
        let pm = ProcessManager();
        let ipcs_info = pm.ipcs_info();
        
        let shm = ipcs_info.shared_memory;
        let queues = ipcs_info.queues;
        let sems = ipcs_info.semaphores;
        
        ipcs_info.to_string()
    "#,
    )?;

    assert!(result.contains("Shared Memory Segments:"));
    assert!(result.contains("Message Queues:"));
    assert!(result.contains("Semaphore Arrays:"));

    Ok(())
}

/// Given: A spawned tail process
/// When: Getting process information via Rhai ProcessManager
/// Then: ProcessInfo fields should match values from ps command
#[test]
fn test_process_info_fields_match_ps() -> Result<(), Box<EvalAltResult>> {
    let tail_process = Command::new("/usr/bin/tail")
        .arg("-f")
        .arg("/dev/null")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to spawn tail process");

    let tail_pid = tail_process.id();

    let ps_output = Command::new("ps")
        .arg("-p")
        .arg(tail_pid.to_string())
        .arg("-o")
        .arg("pid,ppid,uid,user,comm,state")
        .arg("--no-headers")
        .output()
        .expect("Failed to execute ps command");

    let ps_line = String::from_utf8_lossy(&ps_output.stdout);
    let ps_fields: Vec<&str> = ps_line.split_whitespace().collect();

    let expected_pid: i64 = ps_fields[0].parse().expect("Failed to parse PID");
    let expected_ppid: i64 = ps_fields[1].parse().expect("Failed to parse PPID");
    let expected_uid: i64 = ps_fields[2].parse().expect("Failed to parse UID");
    let expected_username = ps_fields[3];
    let expected_name = ps_fields[4];

    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();
    scope.push("target_pid", expected_pid);

    let script = r#"
        let pm = ProcessManager();
        let processes = pm.processes();
        
        let process = ();
        for p in processes {
            if p.pid == target_pid {
                process = p;
                break;
            }
        }
        
        let memory_usage = process.memory_usage;
        let memory_percent = process.memory_percent;
        
        if memory_usage < 0 {
            throw "Memory usage should be non-negative";
        }
        
        if memory_percent < 0.0 {
            throw "Memory percent should be non-negative";
        }
        
        #{
            pid: process.pid,
            name: process.name,
            ppid: process.ppid,
            uid: process.uid,
            username: process.username,
        }
    "#;

    let result_map = engine
        .eval_with_scope::<Map>(&mut scope, script)
        .expect("Failed to get process from Rhai");

    let pid = result_map["pid"]
        .as_int()
        .expect("PID should be an integer");
    assert_eq!(pid, expected_pid, "Rhai PID should match ps output");

    let name = result_map["name"]
        .clone()
        .into_string()
        .expect("Name should be a string");
    assert_eq!(name, expected_name, "Rhai name should match ps output");

    let ppid = &result_map["ppid"];
    if !ppid.is::<()>() {
        let ppid_val = ppid.as_int().expect("PPID should be an integer");
        assert_eq!(ppid_val, expected_ppid, "Rhai PPID should match ps output");
    }

    let uid = &result_map["uid"];
    if !uid.is::<()>() {
        let uid_val = uid.as_int().expect("UID should be an integer");
        assert_eq!(uid_val, expected_uid, "Rhai UID should match ps output");
    }

    let username = result_map["username"]
        .clone()
        .into_string()
        .expect("Username should be a string");
    assert_eq!(
        username, expected_username,
        "Rhai username should match ps output"
    );

    Ok(())
}

/// Given: A Rhai engine with registered process management functions and a policy that allows tracing processes
/// When: A script is run to trace a process
/// Then: The script executes successfully and returns trace information with proper structure
#[test]
fn test_process_manager_trace_success() -> Result<(), Box<EvalAltResult>> {
    if should_skip_trace_tests() {
        // AL2023 doesn't have pstack installed by default
        println!("Skipping pstack test for this platform");
        return Ok(());
    } else {
        println!("Running pstack test for this platform");
    }

    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    // Start a background sleep process that we can trace
    let mut sleep_process = Command::new("/bin/sleep")
        .arg("30")
        .spawn()
        .expect("Failed to start sleep process");

    let sleep_pid = sleep_process.id() as i64;

    // Inject the PID into the scope
    scope.push("target_pid", sleep_pid);

    // Test script that first populates the cache, then traces the sleep process
    let test_script = r#"
        let process_manager = ProcessManager();
        
        // First populate the process cache
        let processes = process_manager.processes();
        
        // Now trace the target process
        let trace = process_manager.trace(target_pid);
        
        // Validate trace structure
        let trace_pid = trace.pid;
        let threads = trace.threads;
        
        // Return validation results
        #{
            "has_pid": trace_pid != (),
            "has_threads": len(threads) > 0,
            "pid_matches": trace_pid == target_pid
        }
    "#;

    let result = engine.eval_with_scope::<Map>(&mut scope, &test_script)?;

    // Clean up the sleep process
    let _ = sleep_process.kill();
    let _ = sleep_process.wait();

    // Validate trace structure
    assert_eq!(
        result["has_pid"].as_bool().unwrap(),
        true,
        "Trace should have a PID"
    );
    assert_eq!(
        result["has_threads"].as_bool().unwrap(),
        true,
        "Trace should have threads"
    );
    assert_eq!(
        result["pid_matches"].as_bool().unwrap(),
        true,
        "Trace PID should match target PID"
    );

    Ok(())
}

/// Given: A Rhai engine with registered process management functions
/// When: A script is run to trace a process with invalid PID
/// Then: The script should fail with an appropriate error
#[test]
fn test_process_manager_trace_invalid_pid() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    // Test script that attempts to trace with an invalid PID
    let test_script = r#"
        let process_manager = ProcessManager();
        
        let result = ();
        try {
            let trace = process_manager.trace(999999);
            result = "unexpected_success"
        } catch(e) {
            // Expected: process not found or other trace-related error
            result = "expected_error"
        }
        result
    "#;

    let result = engine.eval_with_scope::<String>(&mut scope, &test_script)?;
    assert_eq!(
        result, "expected_error",
        "Should fail when tracing invalid PID"
    );
    Ok(())
}

/// Given: A Rhai engine with registered process management functions
/// When: A script is run to trace a process with the current pid but without cedar permissions to trace the process
/// Then: The script should fail with an appropriate error
#[test]
fn test_process_manager_trace_with_namespace_permission_denied() -> Result<(), Box<EvalAltResult>> {
    let principal = get_test_rex_principal();
    let policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action,
            resource
        );
        
        forbid(
            principal == User::"{principal}",
            action == {},
            resource
        );"#,
        ProcessAction::Trace
    );

    let auth = create_test_cedar_auth_with_policy(&policy);
    let engine = create_test_engine_with_auth(auth);

    let current_pid = process::id();
    let mut scope = Scope::new();
    scope.push("target_pid", current_pid as i64);

    let test_script = r#"
        let process_manager = ProcessManager();
        
        let result = ();
        try {
            process_manager.processes(ProcessOptions().load_namespace_info(true).build());
            let trace = process_manager.trace(target_pid, TraceOptions().ns_pid(target_pid).build());
            result = "unexpected_success"
        } catch(e) {
            // Expected: process not found or other trace-related error
            result = e.message;
        }
        result
    "#;

    let result = engine.eval_with_scope::<String>(&mut scope, &test_script)?;
    assert!(
        result.contains("Permission denied"),
        "expected 'Permission denied', got '{result}'"
    );
    Ok(())
}

fn should_skip_trace_tests() -> bool {
    // output == empty => gdb doesn't exist
    Command::new("command")
        .args(["-v", "pstack"])
        .output()
        .map(|output| String::from_utf8(output.stdout).unwrap_or("".to_string()) == "")
        .unwrap_or(false)
}

/// Given: A Rhai engine with registered process management functions and a MonitorProcessesCpuOptions builder
/// When: A MonitorProcessesCpuOptions object is built with valid parameters
/// Then: The build succeeds and returns a valid MonitorProcessesCpuOptions object
#[test]
fn test_top_options_builder_success() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let top_options = MonitorProcessesCpuOptions()
                .pids_to_monitor([1234, 5678])
                .batches(2)
                .delay_in_seconds(1)
                .include_threads(false)
                .build();
        "#,
    );

    assert!(
        result.is_ok(),
        "Failed to build MonitorProcessesCpuOptions: {:?}",
        result
    );
    Ok(())
}

/// Given: A Rhai engine with registered process management functions and a ProcessManager
/// When: A ProcessManager is created and top() method is called with valid options
/// Then: The method succeeds and returns batches of process information
#[test]
fn test_process_manager_top_success() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    let result = engine.eval_with_scope::<Array>(
        &mut scope,
        r#"
            let process_manager = ProcessManager();
            let processes = process_manager.processes();
            
            if len(processes) > 0 {
                let first_pid = processes[0].pid;
                let top_options = MonitorProcessesCpuOptions()
                    .pids_to_monitor([first_pid])
                    .batches(1)
                    .delay_in_seconds(0)
                    .build();
                
                process_manager.monitor_processes_cpu(top_options)
            } else {
                []
            }
        "#,
    );

    assert!(result.is_ok(), "Failed to call top method: {:?}", result);
    let batches = result?;

    if !batches.is_empty() {
        assert_eq!(batches.len(), 1, "Should return 1 batch");
    }

    Ok(())
}

/// Given: A Rhai engine with registered process management functions and a ProcessManager
/// When: A ProcessManager is created and top() method is called with invalid PID
/// Then: The method succeeds but returns empty batches
#[test]
fn test_process_manager_top_fail() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    let result = engine.eval_with_scope::<Array>(
        &mut scope,
        r#"
            let process_manager = ProcessManager();
            let top_options = MonitorProcessesCpuOptions()
                .pids_to_monitor([999999])
                .batches(1)
                .build();
            
            process_manager.monitor_processes_cpu(top_options)
        "#,
    );

    assert!(
        result.is_ok(),
        "Top method should succeed even with invalid PID"
    );
    let batches = result?;
    assert_eq!(batches.len(), 1, "Should return 1 batch");

    // The batch should be empty since PID doesn't exist
    let first_batch = batches[0].clone().cast::<Array>();
    assert!(
        first_batch.is_empty(),
        "Batch should be empty for non-existent PID"
    );

    Ok(())
}

/// Given: A Rhai engine with registered process management functions and a MonitorProcessesCpuOptions builder
/// When: A MonitorProcessesCpuOptions object is built with empty PID list
/// Then: The monitor_processes_cpu() call should fail with a validation error
#[test]
fn test_top_options_empty_pids() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    let result = engine.eval_with_scope::<Array>(
        &mut scope,
        r#"
            let process_manager = ProcessManager();
            let top_options = MonitorProcessesCpuOptions()
                .pids_to_monitor([])
                .batches(1)
                .build();
            
            process_manager.monitor_processes_cpu(top_options)
        "#,
    );

    assert!(
        result.is_err(),
        "monitor_processes_cpu should fail with empty PIDs"
    );
    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("PIDs array cannot be empty") || error_msg.contains("cannot be empty"),
        "Error should mention empty PIDs array: {}",
        error_msg
    );

    Ok(())
}

/// Given: A Rhai engine with registered process management functions
/// When: Calling processes() with ProcessOptions having load_namespace_info=false
/// Then: Should return processes without namespace info
#[test]
fn test_processes_with_options_namespace_info_disabled() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    let test_script = r#"
        let process_manager = ProcessManager();
        let options = ProcessOptions()
            .load_namespace_info(false)
            .build();
        let processes = process_manager.processes(options);
        
        if len(processes) > 0 {
            let process = processes[0];
            process.pid_namespace == ()
        } else {
            true
        }
    "#;

    let result = engine.eval_with_scope::<bool>(&mut scope, test_script)?;
    assert!(
        result,
        "pid_namespace should be None when load_namespace_info=false"
    );

    Ok(())
}

/// Given: A Rhai engine with registered process management functions
/// When: Calling processes() with ProcessOptions having load_namespace_info=true
/// Then: Should return processes with namespace info that matches /proc data
#[test]
fn test_processes_with_options_namespace_info_enabled() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    // Read current process namespace from /proc/self/ns/pid for validation
    let self_ns_link =
        std::fs::read_link("/proc/self/ns/pid").expect("Failed to read /proc/self/ns/pid");
    let self_ns_str = self_ns_link.to_string_lossy();
    let expected_ns_id: u64 = self_ns_str
        .strip_prefix("pid:[")
        .and_then(|s| s.strip_suffix(']'))
        .and_then(|s| s.parse().ok())
        .expect("Failed to parse self namespace ID");

    let current_pid = std::process::id();
    scope.push("expected_pid", current_pid as i64);
    scope.push("expected_ns_id", expected_ns_id as i64);

    let test_script = r#"
        let process_manager = ProcessManager();
        let options = ProcessOptions()
            .load_namespace_info(true)
            .build();
        let processes = process_manager.processes(options);
        
        // Find current process
        let current_process = ();
        for process in processes {
            if process.pid == expected_pid {
                current_process = process;
                break;
            }
        }
        
        if current_process == () {
            throw "Current process not found in results";
        }
        
        // Verify namespace info exists
        if current_process.pid_namespace == () {
            throw "pid_namespace should not be None";
        }
        
        let ns = current_process.pid_namespace;
        
        // Verify namespace_id matches /proc/self/ns/pid
        if ns.namespace_id != expected_ns_id {
            throw `namespace_id mismatch: expected ${expected_ns_id}, got ${ns.namespace_id}`;
        }
        
        // Verify child_pid equals current PID (for current process)
        if ns.child_ns_pid != expected_pid {
            throw `child_ns_pid mismatch: expected ${expected_pid}, got ${ns.child_ns_pid}`;
        }
        
        true
    "#;

    let result = engine.eval_with_scope::<bool>(&mut scope, test_script)?;
    assert!(result, "Namespace info should match /proc data");

    Ok(())
}

/// Spawns 3 threads on the current process. Returns handles that must be kept alive.
fn spawn_test_threads() -> Vec<std::thread::JoinHandle<()>> {
    (0..3)
        .map(|_| std::thread::spawn(|| sleep(Duration::from_secs(10))))
        .collect()
}

/// Runs a ps command and returns the count for the given pid
fn get_process_count_from_ps(ps_command: &str, pid: u32) -> i64 {
    let ps_output = std::process::Command::new("bash")
        .args(["-c", &format!("{} | awk '$2=={}' | wc -l", ps_command, pid)])
        .output()
        .expect("Failed to run ps command");
    String::from_utf8_lossy(&ps_output.stdout)
        .trim()
        .parse::<i64>()
        .expect("Failed to parse ps count")
}

/// Sets up test with spawned threads and returns (threads, pid, ps_count)
fn setup_thread_test(ps_command: &str) -> (Vec<std::thread::JoinHandle<()>>, u32, i64) {
    let threads = spawn_test_threads();
    let pid = std::process::id();
    let ps_count = get_process_count_from_ps(ps_command, pid);
    (threads, pid, ps_count)
}

/// Given: A Rhai engine with registered process management functions and spawned threads
/// When: Calling processes() with ProcessOptions having include_threads=false (default)
/// Then: Should match ps aux count for this process (1 entry)
#[test]
fn test_processes_with_options_include_threads_disabled() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    let (_threads, pid, ps_count) = setup_thread_test("ps aux");

    let test_script = format!(
        r#"
        let process_manager = ProcessManager();
        let options = ProcessOptions()
            .include_threads(false)
            .build();
        let processes = process_manager.processes(options);
        let count = 0;
        for process in processes {{
            if process.pid == {} {{
                count += 1;
            }}
        }}
        count
    "#,
        pid
    );

    let count = engine.eval_with_scope::<i64>(&mut scope, &test_script)?;

    assert_eq!(
        count, ps_count,
        "Process count {} should match ps aux {} for pid {}",
        count, ps_count, pid
    );

    Ok(())
}

/// Given: A Rhai engine with registered process management functions and spawned threads
/// When: Calling processes() with ProcessOptions having include_threads=true
/// Then: Should match ps -eLf count for this process (main + threads)
#[test]
fn test_processes_with_options_include_threads_enabled() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    let (_threads, pid, ps_count) = setup_thread_test("ps -eLf");

    let test_script = format!(
        r#"
        let process_manager = ProcessManager();
        let options = ProcessOptions()
            .include_threads(true)
            .build();
        let processes = process_manager.processes(options);
        let count = 0;
        for process in processes {{
            // Count main process (pid == pid) and its threads (ppid == pid)
            if process.pid == {} || process.ppid == {} {{
                count += 1;
            }}
        }}
        count
    "#,
        pid, pid
    );

    let count = engine.eval_with_scope::<i64>(&mut scope, &test_script)?;

    // Allow absolute tolerance for timing differences (threads starting/stopping between calls)
    let diff = (count - ps_count).abs();
    assert!(
        diff <= 5,
        "Process count {} differs from ps -eLf {} by more than 5 threads for pid {} (diff: {})",
        count,
        ps_count,
        pid,
        diff
    );

    Ok(())
}

/// Given: A ProcessInfo object from processes()
/// When: to_map is called on it
/// Then: The map matches the expected values from getters
#[test]
fn test_process_info_to_map() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();

    let result = engine.eval::<Map>(
        r#"
            let pm = ProcessManager();
            let processes = pm.processes();
            let p = processes[0];

            let expected = #{
                "pid": p.pid,
                "name": p.name,
                "ppid": p.ppid,
                "uid": p.uid,
                "username": p.username,
                "memory_usage": p.memory_usage,
                "memory_percent": p.memory_percent,
                "state": p.state,
                "command": p.command,
                "recent_cpu_usage": p.recent_cpu_usage,
                "historical_cpu_usage": p.historical_cpu_usage,
                "pid_namespace": p.pid_namespace,
            };

            #{
                "expected": expected.to_json(),
                "actual": p.to_map().to_json(),
            }
        "#,
    )?;

    let expected: String = result.get("expected").unwrap().clone().into_string()?;
    let actual: String = result.get("actual").unwrap().clone().into_string()?;
    assert_eq!(expected, actual);

    Ok(())
}

/// Given: A FuserInfo object from processes_using_inode()
/// When: to_map is called on it
/// Then: The map matches the expected values from getters
#[test]
fn test_fuser_info_to_map() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();

    let temp_dir = assert_fs::TempDir::new().unwrap();
    temp_dir.child("test.txt").write_str("hello").unwrap();
    let file_path = temp_dir
        .child("test.txt")
        .path()
        .to_string_lossy()
        .into_owned();
    let _held_file = std::fs::File::open(&file_path).unwrap();

    let mut scope = Scope::new();
    scope.push_constant("test_path", file_path);

    let result = engine.eval_with_scope::<Map>(
        &mut scope,
        r#"
            let pm = ProcessManager();
            let fuser_infos = pm.processes_using_inode(test_path);
            let f = fuser_infos[0];

            let expected = #{
                "user": f.user,
                "pid": f.pid,
                "access_types": f.to_map()["access_types"],
                "command": f.command,
            };

            #{
                "expected": expected.to_json(),
                "actual": f.to_map().to_json(),
            }
        "#,
    )?;

    let expected: String = result.get("expected").unwrap().clone().into_string()?;
    let actual: String = result.get("actual").unwrap().clone().into_string()?;
    assert_eq!(expected, actual);

    Ok(())
}

/// Given: An IpcsInfo object from ipcs_info()
/// When: to_map is called on it
/// Then: The map matches the expected values from getters
#[test]
fn test_ipcs_info_to_map() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();

    let result = engine.eval::<Map>(
        r#"
            let pm = ProcessManager();
            let ipcs = pm.ipcs_info();

            let expected = #{
                "shared_memory": ipcs.shared_memory,
                "semaphores": ipcs.semaphores,
                "queues": ipcs.queues,
            };

            #{
                "expected": expected.to_json(),
                "actual": ipcs.to_map().to_json(),
            }
        "#,
    )?;

    let expected: String = result.get("expected").unwrap().clone().into_string()?;
    let actual: String = result.get("actual").unwrap().clone().into_string()?;
    assert_eq!(expected, actual);

    Ok(())
}

/// Given: An OpenFileInfo object from list_open_files()
/// When: to_map is called on it
/// Then: The map matches the expected values from getters
#[test]
fn test_open_file_info_to_map() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();

    let temp_dir = assert_fs::TempDir::new().unwrap();
    temp_dir.child("test.txt").write_str("hello").unwrap();
    let _held_file = std::fs::File::open(temp_dir.child("test.txt").path()).unwrap();

    let mut scope = Scope::new();
    scope.push_constant("test_dir", temp_dir.path().to_string_lossy().into_owned());

    let result = engine.eval_with_scope::<Map>(
        &mut scope,
        r#"
            let pm = ProcessManager();
            let options = LsofOptions().path(test_dir).include_subdir(true).build();
            let open_files = pm.list_open_files(options);
            let f = open_files[0];

            let expected = #{
                "pid": f.pid,
                "process_name": f.process_name,
                "user": f.user,
                "command": f.command,
                "access_type": f.access,
                "file_type": f.file_type,
                "file_path": f.file_path,
            };

            #{
                "expected": expected.to_json(),
                "actual": f.to_map().to_json(),
            }
        "#,
    )?;

    let expected: String = result.get("expected").unwrap().clone().into_string()?;
    let actual: String = result.get("actual").unwrap().clone().into_string()?;
    assert_eq!(expected, actual);

    Ok(())
}
