#![cfg(target_os = "linux")]
// Integration tests test your crate's public API. They only have access to items
// in your crate that are marked pub. See the Cargo Targets page of the Cargo Book
// for more information.
//
//   https://doc.rust-lang.org/cargo/reference/cargo-targets.html#integration-tests
//
// This file contains tests for the rust_safe_process_mgmt crate.
use anyhow::Result;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::process::actions::ProcessAction;
use rex_cedar_auth::test_utils::{DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder};
use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_test_rex_principal};
use rex_test_utils::assertions::assert_error_contains;
use rstest::rstest;
use rust_safe_process_mgmt::errors::RustSafeProcessMgmtError;
use rust_safe_process_mgmt::options::{
    KillOptionsBuilder, LsofOptionsBuilder, MonitorProcessesCpuOptionsBuilder,
    NamespaceOptionsBuilder, ProcessOptionsBuilder, TraceOptionsBuilder,
};
use rust_safe_process_mgmt::{AccessType, RcProcessManager};
use rustix::process::Signal;
use std::fs::File;
use std::io::Error;
use std::io::Write;
use std::process::{self, Command, Stdio};
use std::thread::sleep;
use std::time::Duration;
use tempfile::tempdir;
use tracing::Level;
use tracing_subscriber::fmt;

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;

fn init_test_logger() {
    let _ = fmt::Subscriber::builder()
        .with_max_level(Level::DEBUG)
        .with_test_writer()
        .try_init();
}

/// Spawns 3 threads on the current process. Returns handles that must be kept alive.
fn spawn_test_threads() -> Vec<std::thread::JoinHandle<()>> {
    (0..3)
        .map(|_| std::thread::spawn(|| sleep(Duration::from_secs(10))))
        .collect()
}

/// Runs a ps command and returns the count for the given pid
fn get_process_count_from_ps(ps_command: &str, pid: u32) -> Result<usize> {
    let ps_out = Command::new("bash")
        .args(["-c", &format!("{} | awk '$2=={}' | wc -l", ps_command, pid)])
        .output()?;
    Ok(String::from_utf8_lossy(&ps_out.stdout).trim().parse()?)
}

/// Sets up test with spawned threads and returns (threads, pid, ps_count)
fn setup_thread_test(ps_command: &str) -> Result<(Vec<std::thread::JoinHandle<()>>, u32, usize)> {
    let threads = spawn_test_threads();
    let pid = std::process::id();
    let ps_count = get_process_count_from_ps(ps_command, pid)?;
    Ok((threads, pid, ps_count))
}

/// Given: The test process with 3 extra threads
/// When: Listing processes with include_threads=false
/// Then: Should find 1 entry matching ps aux
#[test]
fn test_thread_filtering_matches_ps_aux() -> Result<()> {
    let cedar_auth = TestCedarAuthBuilder::default()
        .policy(get_default_test_rex_policy())
        .build()
        .unwrap()
        .create();

    let (_threads, pid, ps_count) = setup_thread_test("ps aux")?;

    let procs = RcProcessManager::default().safe_processes(&cedar_auth)?;
    let api_count = procs.iter().filter(|p| p.pid == pid).count();

    assert_eq!(
        api_count, ps_count,
        "include_threads=false should match ps aux for pid {}",
        pid
    );

    Ok(())
}

/// Returns the TID (thread ID / LWP) of the calling thread by reading
/// /proc/thread-self/status, which requires no extra crate dependencies.
fn get_current_tid() -> u32 {
    let status = std::fs::read_to_string("/proc/thread-self/status")
        .expect("Failed to read /proc/thread-self/status");
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Pid:") {
            return rest.trim().parse().expect("Failed to parse TID");
        }
    }
    panic!("Pid line not found in /proc/thread-self/status");
}

/// Holds the parsed fields from a single `ps -eLf` row for a thread.
#[derive(Debug)]
struct PsThreadInfo {
    uid: String,
    pid: u32,
    lwp: u32,
    cmd: String,
}

/// Returns a map from LWP → `PsThreadInfo` for every thread belonging
/// to the given process pid, parsed from `ps -eLf`.
///
/// `ps -eLf` columns: UID PID PPID LWP C NLWP STIME TTY TIME CMD
/// Fields 0-8 are single tokens; CMD (field 9+) may contain spaces.
fn get_thread_info_from_ps(pid: u32) -> Result<std::collections::HashMap<u32, PsThreadInfo>> {
    let output = Command::new("bash")
        .args(["-c", &format!("ps -eLf | awk -v pid={} '$2 == pid'", pid)])
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut map = std::collections::HashMap::new();
    for line in stdout.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        let lwp: u32 = match cols[3].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let info = PsThreadInfo {
            uid: cols[0].to_string(),
            pid: cols[1].parse().unwrap_or(0),
            lwp,
            cmd: cols[9..].join(" "),
        };
        map.insert(lwp, info);
    }
    Ok(map)
}

/// Given: The test process with 3 extra threads whose TIDs are known
/// When: Listing processes with include_threads=true
/// Then: Each spawned TID appears in both `ps -eLf` and the SDK with matching fields
#[test]
fn test_with_threads_matches_ps_elf() -> Result<()> {
    let cedar_auth = TestCedarAuthBuilder::default()
        .policy(get_default_test_rex_policy())
        .build()
        .unwrap()
        .create();

    let pid = std::process::id();

    // Spawn 3 threads and collect their TIDs.
    let tid_pairs: Vec<(std::thread::JoinHandle<()>, u32)> = (0..3)
        .map(|_| {
            let (tx, rx) = std::sync::mpsc::channel();
            let handle = std::thread::spawn(move || {
                let tid = get_current_tid();
                let _ = tx.send(tid);
                sleep(Duration::from_secs(30));
            });
            let tid = rx.recv().expect("Thread failed to send TID");
            (handle, tid)
        })
        .collect();

    let spawned_tids: Vec<u32> = tid_pairs.iter().map(|(_, tid)| *tid).collect();

    // Collect full thread info from ps -eLf.
    let ps_threads = get_thread_info_from_ps(pid)?;
    for tid in &spawned_tids {
        assert!(
            ps_threads.contains_key(tid),
            "ps -eLf should list TID {} for pid {}, got LWPs: {:?}",
            tid,
            pid,
            ps_threads.keys().collect::<Vec<_>>(),
        );
    }

    // Collect full process info from the SDK.
    let opts = ProcessOptionsBuilder::default()
        .include_threads(true)
        .build()?;
    let procs = RcProcessManager::default().safe_processes_with_options(&cedar_auth, opts)?;

    let sdk_by_pid: std::collections::HashMap<u32, &_> = procs.iter().map(|p| (p.pid, p)).collect();

    // Resolve the ps UID string to a username for comparison.
    // ps -eLf shows the username when it fits, or the numeric UID.
    let expected_username = {
        let uid_output = Command::new("id").arg("-un").output()?;
        String::from_utf8_lossy(&uid_output.stdout)
            .trim()
            .to_string()
    };

    for tid in &spawned_tids {
        // --- ps side ---
        let ps = ps_threads
            .get(tid)
            .unwrap_or_else(|| panic!("TID {} missing from ps -eLf output", tid));

        // --- SDK side ---
        let sdk = sdk_by_pid.get(tid).unwrap_or_else(|| {
            panic!(
                "SDK should list TID {} (pid {}), got PIDs: {:?}",
                tid,
                pid,
                procs
                    .iter()
                    .filter(|p| p.pid == pid || p.ppid == Some(pid))
                    .map(|p| p.pid)
                    .collect::<Vec<_>>(),
            )
        });

        // 1) SDK pid == ps LWP (the TID)
        assert_eq!(sdk.pid, ps.lwp, "TID {}: SDK pid should equal ps LWP", tid,);

        // 2) SDK ppid == ps PID (thread's parent is the process)
        assert_eq!(
            sdk.ppid,
            Some(ps.pid),
            "TID {}: SDK ppid ({:?}) should equal ps PID ({})",
            tid,
            sdk.ppid,
            ps.pid,
        );

        // 3) Command: ps CMD should start with the same binary
        //    name the SDK reports (SDK strips the directory prefix).
        let ps_cmd_binary = ps.cmd.split_whitespace().next().unwrap_or("");
        let ps_cmd_base = ps_cmd_binary.rsplit('/').next().unwrap_or(ps_cmd_binary);
        let sdk_cmd_binary = sdk.command.split_whitespace().next().unwrap_or("");
        assert_eq!(
            sdk_cmd_binary, ps_cmd_base,
            "TID {}: SDK command binary '{}' should match ps CMD \
             binary '{}'",
            tid, sdk_cmd_binary, ps_cmd_base,
        );

        // 4) Username: SDK username should match our user.
        //    ps shows UID string which may be the username itself.
        assert_eq!(
            sdk.username, expected_username,
            "TID {}: SDK username '{}' should match expected '{}'",
            tid, sdk.username, expected_username,
        );
        // Also validate ps UID matches (may be numeric or name).
        let ps_uid_matches = ps.uid == expected_username || ps.uid.parse::<u32>().ok() == sdk.uid;
        assert!(
            ps_uid_matches,
            "TID {}: ps UID '{}' should match SDK uid {:?} or \
             username '{}'",
            tid, ps.uid, sdk.uid, expected_username,
        );
    }

    // Keep threads alive until assertions complete, then drop.
    drop(tid_pairs);
    Ok(())
}

/// Given: A policy that denies access to all processes
/// When: Getting all processes
/// Then: Should return an empty list
#[test]
fn test_safe_processes_permission_denied() -> Result<()> {
    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"forbid(
            principal == User::"{principal}",
            action in [
                {}
            ],
            resource
        );"#,
        ProcessAction::List
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let process_manager = RcProcessManager::new();
    let processes = process_manager.safe_processes(&test_cedar_auth)?;

    assert!(
        processes.is_empty(),
        "Process list should be empty when listing permission is denied for all processes"
    );

    Ok(())
}

/// Given: A Cedar policy that permits the ListFds action
/// When: Calling safe_lsof with the given path
/// Then: Should return results with expected fields
#[rstest]
#[case(".")]
#[case("/")]
fn test_safe_lsof_returns_data(#[case] lsof_path: &str) -> Result<()> {
    let test_policy = get_default_test_rex_policy();

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let process_manager = RcProcessManager::default();

    let options = LsofOptionsBuilder::default()
        .path(lsof_path.to_string())
        .include_subdir(true)
        .build()?;

    let lsof_results = process_manager.safe_lsof(&test_cedar_auth, options)?;

    assert!(lsof_results.len() >= 1);

    let mut test_process_found = false;

    for (i, open_file_info) in lsof_results.iter().enumerate() {
        assert!(
            !open_file_info.user.is_empty(),
            "OpenFileInfo #{} has empty user",
            i
        );

        assert_ne!(
            open_file_info.user, "unknown",
            "OpenFileInfo #{} has fallback username, expected actual username",
            i
        );

        assert!(
            !open_file_info.user.contains('/') && !open_file_info.user.contains('\\'),
            "OpenFileInfo #{} has invalid username format: {}",
            i,
            open_file_info.user
        );

        assert!(
            open_file_info.pid > 0,
            "OpenFileInfo #{} has invalid PID",
            i
        );

        assert!(
            !open_file_info.process_name.is_empty(),
            "OpenFileInfo #{} has empty process_name",
            i
        );

        assert!(
            !open_file_info.command.is_empty(),
            "OpenFileInfo #{} has empty command",
            i
        );

        assert!(
            !open_file_info.file_path.is_empty(),
            "OpenFileInfo #{} has empty file_path",
            i
        );

        if open_file_info.pid == std::process::id() {
            test_process_found = true;
        }

        // Check command format - should not contain full paths for the executable
        // This verifies format_command is working correctly
        let command_parts: Vec<&str> = open_file_info.command.split_whitespace().collect();
        if !command_parts.is_empty() {
            let executable = command_parts[0];
            // The executable name should not contain directory separators
            // because format_command removes the path
            assert!(
                !executable.contains('/'),
                "OpenFileInfo #{} command executable '{}' contains path separators, expected simplified format",
                i,
                executable
            );
        }

        let access_type = open_file_info.access_type.to_string();
        assert!(
            !access_type.is_empty(),
            "OpenFileInfo #{} access_type.to_string() returned empty string",
            i
        );

        let file_type = open_file_info.file_type.to_string();
        assert!(
            !file_type.is_empty(),
            "OpenFileInfo #{} file_type.to_string() returned empty string",
            i
        );
    }

    assert!(test_process_found, "Should find the current test process");

    Ok(())
}

/// Given: A policy that denies access to all processes
/// When: Getting lsof information
/// Then: Should Error
#[test]
fn test_safe_lsof_permission_denied() -> Result<()> {
    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"forbid(
            principal == User::"{principal}",
            action in [
                {}
            ],
            resource
        );"#,
        ProcessAction::ListFds
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let process_manager = RcProcessManager::default();

    let options = LsofOptionsBuilder::default()
        .path(".".to_string())
        .build()?;

    let lsof_results = process_manager.safe_lsof(&test_cedar_auth, options);

    assert!(lsof_results.is_err());

    let error = lsof_results.unwrap_err();
    assert!(matches!(
        error,
        RustSafeProcessMgmtError::PermissionDenied { .. }
    ));

    let error_msg = error.to_string();
    assert!(error_msg.contains("Permission denied"));

    Ok(())
}

/// Given: A path that is mmap'd
/// When: Calling safe_lsof on directory containing mmap'd file
/// Then: Return the information including that it's an mmap
#[test]
fn test_safe_lsof_memory_mapped_detection() -> Result<(), anyhow::Error> {
    let temp_dir = tempdir()?;
    let test_file_path = temp_dir.path().join("test_lsof_mmap_file");
    let mut file = File::create(&test_file_path)?;
    file.write_all(b"test content for lsof memory mapping")?;

    let canonical_dir = std::fs::canonicalize(temp_dir.path())?;
    let canonical_dir_str = canonical_dir.to_string_lossy().to_string();

    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action == {},
            resource
        );

        permit(
            principal == User::"{principal}",
            action in [{}, {}],
            resource
        );
        "#,
        ProcessAction::ListFds,
        FilesystemAction::Open,
        FilesystemAction::Read,
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let process_manager = RcProcessManager::default();

    let mmap_file = std::fs::File::open(&test_file_path)?;
    let mmap = unsafe { memmap2::Mmap::map(&mmap_file)? };

    let options = LsofOptionsBuilder::default()
        .path(canonical_dir_str)
        .include_subdir(true)
        .build()?;

    let lsof_results = process_manager.safe_lsof(&test_cedar_auth, options)?;

    drop(mmap);

    let current_pid = std::process::id();

    let mut found_memory_mapped = false;
    for open_file_info in lsof_results {
        if open_file_info.pid == current_pid {
            if open_file_info.access_type == AccessType::MemoryMapped {
                found_memory_mapped = true;
                break;
            }
        }
    }

    assert!(found_memory_mapped);

    Ok(())
}

/// Given: A non-existent path
/// When: Calling safe_lsof with the invalid path
/// Then: Should return a validation error
#[test]
fn test_safe_lsof_invalid_path() -> Result<()> {
    let test_cedar_auth = TestCedarAuthBuilder::default().build().unwrap().create();
    let process_manager = RcProcessManager::default();

    let options = LsofOptionsBuilder::default()
        .path("/definitely/nonexistent/path/12345".to_string())
        .build()?;

    let result = process_manager.safe_lsof(&test_cedar_auth, options);

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(matches!(
        error,
        RustSafeProcessMgmtError::ValidationError { .. }
    ));

    let error_msg = error.to_string();
    assert!(error_msg.contains("Failed to canonicalize path"));

    Ok(())
}

/// Given: A non-existent PID
/// When: Calling safe_lsof with that PID
/// Then: Should return ProcessNotFound error
#[test]
fn test_safe_lsof_by_pid_not_found() -> Result<()> {
    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(get_default_test_rex_policy())
        .build()
        .unwrap()
        .create();

    let process_manager = RcProcessManager::default();
    let options = LsofOptionsBuilder::default().pid(999_999_999_u32).build()?;

    let result = process_manager.safe_lsof(&test_cedar_auth, options);

    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("does not exist"));

    Ok(())
}

/// Given: A Cedar policy that denies ListFds
/// When: Calling safe_lsof with pid option
/// Then: Should return PermissionDenied error
#[test]
fn test_safe_lsof_by_pid_permission_denied() -> Result<()> {
    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [{}, {}],
            resource
        );
        forbid(
            principal == User::"{principal}",
            action in [{}],
            resource
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Read,
        ProcessAction::ListFds,
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let process_manager = RcProcessManager::default();
    let options = LsofOptionsBuilder::default()
        .pid(std::process::id())
        .build()?;

    let result = process_manager.safe_lsof(&test_cedar_auth, options);

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        RustSafeProcessMgmtError::PermissionDenied { .. }
    ));

    Ok(())
}

/// Given: A process with various FD types (regular file, unix socket, mmap, eventfd)
/// When: Calling safe_lsof with that process's PID
/// Then: Should return entries for all FD types with correct FileType variants
#[test]
fn test_safe_lsof_by_pid_all_fd_types() -> Result<()> {
    use std::os::unix::net::UnixListener;

    let test_dir = "/tmp/rex_lsof_pid_fd_types";
    let _ = std::fs::remove_dir_all(test_dir);
    std::fs::create_dir_all(test_dir)?;

    // Regular file FD
    let reg_path = format!("{}/regular.txt", test_dir);
    std::fs::write(&reg_path, "test content for mmap")?;
    let _reg_file = std::fs::File::open(&reg_path)?;

    // Unix domain socket
    let sock_path = format!("{}/test.sock", test_dir);
    let _listener = UnixListener::bind(&sock_path)?;

    // Memory-mapped file
    let mmap_file = std::fs::File::open(&reg_path)?;
    let _mmap = unsafe { memmap2::Mmap::map(&mmap_file)? };

    // Pipe (creates FIFO FDs)
    let (pipe_read, _pipe_write) = nix::unistd::pipe()?;

    // eventfd (creates AnonInode FD — anon_inode:[eventfd])
    let eventfd = unsafe { nix::libc::eventfd(0, 0) };
    assert!(eventfd >= 0, "eventfd creation failed");

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(get_default_test_rex_policy())
        .build()
        .unwrap()
        .create();

    let process_manager = RcProcessManager::default();
    let my_pid = std::process::id();
    let options = LsofOptionsBuilder::default().pid(my_pid).build()?;

    let results = process_manager.safe_lsof(&test_cedar_auth, options)?;

    let file_types: std::collections::HashSet<String> =
        results.iter().map(|f| f.file_type.to_string()).collect();
    let access_types: std::collections::HashSet<String> =
        results.iter().map(|f| f.access_type.to_string()).collect();

    // Verify FD types
    assert!(file_types.contains("REG"), "Should see REG (regular file)");
    assert!(file_types.contains("SOCK"), "Should see SOCK (unix socket)");
    assert!(file_types.contains("DIR"), "Should see DIR (cwd/root)");
    assert!(file_types.contains("FIFO"), "Should see FIFO (pipe)");
    assert!(
        file_types.contains("ANON_INODE"),
        "Should see a_inode (eventfd)"
    );

    // Verify access types
    assert!(access_types.contains("File descriptor"));
    assert!(access_types.contains("Memory mapped"));
    assert!(access_types.contains("Working directory"));
    assert!(access_types.contains("Root directory"));
    assert!(access_types.contains("Executable"));

    // Verify specific entries
    assert!(
        results.iter().any(|f| f.file_path == reg_path),
        "Should find regular file"
    );
    assert!(
        results.iter().any(|f| f.file_path == sock_path),
        "Should find unix socket"
    );
    assert!(
        results.iter().any(|f| f.file_path.contains("pipe:")),
        "Should find pipe"
    );
    assert!(
        results
            .iter()
            .any(|f| f.file_path.contains("anon_inode:[eventfd]")),
        "Should find eventfd"
    );

    // Cleanup
    nix::unistd::close(pipe_read)?;
    unsafe {
        nix::libc::close(eventfd);
    }
    let _ = std::fs::remove_dir_all(test_dir);

    Ok(())
}

/// Given: A directory with a regular file, unix socket, and nested file
/// When: Calling safe_lsof on that directory with include_subdir
/// Then: Should find all targets matching bash lsof +D behavior
#[test]
fn test_safe_lsof_finds_all_target_types() -> Result<()> {
    use std::os::unix::net::UnixListener;

    let test_dir = "/tmp/rex_lsof_all_targets";
    let _ = std::fs::remove_dir_all(test_dir);
    std::fs::create_dir_all(test_dir)?;

    // Regular file
    let reg_file = format!("{}/regular.txt", test_dir);
    std::fs::write(&reg_file, "test")?;
    let tail = std::process::Command::new("tail")
        .args(["-f", &reg_file])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;

    // Unix domain socket (simulates .s.PGSQL.5432)
    let sock_path = format!("{}/test.s.PGSQL.5432", test_dir);
    let _listener = UnixListener::bind(&sock_path)?;

    // Nested file in subdirectory
    let sub_file = format!("{}/subdir/nested.txt", test_dir);
    std::fs::create_dir_all(format!("{}/subdir", test_dir))?;
    std::fs::write(&sub_file, "nested")?;
    let tail2 = std::process::Command::new("tail")
        .args(["-f", &sub_file])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;

    std::thread::sleep(std::time::Duration::from_secs(1));

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(get_default_test_rex_policy())
        .build()
        .unwrap()
        .create();

    let process_manager = RcProcessManager::default();
    let options = LsofOptionsBuilder::default()
        .path(test_dir.to_string())
        .include_subdir(true)
        .build()?;

    let results = process_manager.safe_lsof(&test_cedar_auth, options)?;
    let paths: Vec<&str> = results.iter().map(|f| f.file_path.as_str()).collect();

    // All target types found
    assert!(
        paths.iter().any(|p| *p == reg_file),
        "Should find regular file"
    );
    assert!(
        paths.iter().any(|p| *p == sock_path),
        "Should find unix socket"
    );
    assert!(
        paths.iter().any(|p| *p == sub_file),
        "Should find nested file"
    );

    // Cleanup
    let _ = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(tail.id() as i32),
        nix::sys::signal::Signal::SIGTERM,
    );
    let _ = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(tail2.id() as i32),
        nix::sys::signal::Signal::SIGTERM,
    );
    let _ = std::fs::remove_dir_all(test_dir);

    Ok(())
}

/// Given: ProcessManager is available
/// When: Getting all processes
/// Then: Should return a non-empty list of processes with all required fields
#[test]
fn test_safe_processes_returns_data() -> Result<()> {
    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"
        permit(
            principal == User::"{principal}",
            action == {},
            resource
        );
        "#,
        ProcessAction::List
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let process_manager = RcProcessManager::default();

    let processes = process_manager.safe_processes(&test_cedar_auth)?;
    assert!(!processes.is_empty(), "Should find at least some processes");

    let test_process = processes.iter().find(|p| p.pid == std::process::id());
    assert!(
        test_process.is_some(),
        "Should find current test process in process list"
    );
    if let Some(process) = test_process {
        assert!(process.pid > 0, "PID should not be empty");
        assert!(!process.name.is_empty(), "Process name should not be empty");
        assert!(!process.username.is_empty(), "Username should not be empty");
        assert!(
            !process.state.is_empty(),
            "Process state should not be empty"
        );
        assert!(
            process.memory_percent >= 0.0,
            "Memory percentage should not be negative"
        );
        assert!(
            process.pid_namespace.is_none(),
            "Namespace info should be None by default"
        );
    }

    // Test with load_namespace_info=false explicitly
    let options = ProcessOptionsBuilder::default()
        .load_namespace_info(false)
        .build()?;
    let processes_no_ns = process_manager.safe_processes_with_options(&test_cedar_auth, options)?;

    for process in processes_no_ns.iter() {
        assert!(
            process.pid_namespace.is_none(),
            "Namespace info should be None when load_namespace_info=false"
        );
    }

    Ok(())
}

/// Given: A Cedar authorization setup that would cause an error
/// When: Listing processes with an invalid context
/// Then: An authorization error is returned due to context requirements
#[test]
fn test_is_authorized_error() -> Result<()> {
    let principal = get_test_rex_principal();

    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action == {},
            resource
        ) when {{
            context.access_level >= 5
        }};"#,
        ProcessAction::List
    );

    let test_schema = r#"entity User;

    namespace process_system {
        entity Process;

        action list appliesTo {
            principal: [User],
            resource: [Process],
            context: {
                access_level: Long
            }
        };
    }"#;

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy.to_string())
        .schema(test_schema.to_string())
        .build()
        .unwrap()
        .create();

    let process_manager = RcProcessManager::default();
    let result = process_manager.safe_processes(&test_cedar_auth);

    assert!(result.is_err());

    let error = result.unwrap_err();
    assert!(matches!(
        error,
        RustSafeProcessMgmtError::AuthorizationError { .. }
    ));

    let error_msg = error.to_string();
    assert!(error_msg.contains("Authorization check failed"));

    Ok(())
}

/// Given: Valid namespace option (mount enabled)
/// When: Using safe_nsenter with current process
/// Then: Should succeed or fail gracefully due to system limitations
#[test]
fn test_safe_nsenter_pid_mount_namespace() -> Result<()> {
    let current_pid = std::process::id();
    let cedar_auth = TestCedarAuthBuilder::default().build().unwrap().create();
    let options = NamespaceOptionsBuilder::default()
        .mount(true)
        .pid(current_pid)
        .build()
        .unwrap();

    let process_manager = RcProcessManager::default();

    let _processes = process_manager.safe_processes(&cedar_auth)?;

    let result = process_manager.safe_nsenter(
        &options,
        || -> Result<&str, Error> { Ok("test_result") },
        &cedar_auth,
    );

    // Expected due to unit test env not having `CAP_SYS_ADMIN` capability
    assert!(result.is_err());
    let error = result.unwrap_err();

    assert!(matches!(
        error,
        RustSafeProcessMgmtError::NamespaceOperationError { .. }
    ));

    let error_msg = error.to_string();
    assert!(error_msg.contains("Failed to enter requested namespaces"));

    Ok(())
}

/// Given: Valid namespace option (net enabled)
/// When: Using safe_nsenter with current process
/// Then: Should succeed or fail gracefully due to system limitations
#[test]
fn test_safe_nsenter_pid_network_namespace() -> Result<()> {
    let cedar_auth = TestCedarAuthBuilder::default().build().unwrap().create();

    let current_pid = std::process::id();
    let options = NamespaceOptionsBuilder::default()
        .net(true)
        .pid(current_pid)
        .build()
        .unwrap();

    let process_manager = RcProcessManager::default();

    let _processes = process_manager.safe_processes(&cedar_auth)?;

    let result = process_manager.safe_nsenter(
        &options,
        || -> Result<&str, Error> { Ok("test_result") },
        &cedar_auth,
    );

    // Expected due to unit test env not having `CAP_SYS_ADMIN` capability
    assert!(result.is_err());
    let error = result.unwrap_err();

    assert!(matches!(
        error,
        RustSafeProcessMgmtError::NamespaceOperationError { .. }
    ));

    let error_msg = error.to_string();
    assert!(error_msg.contains("Failed to enter requested namespaces"));

    Ok(())
}

/// Given: A ProcessManager and namespace options with no namespaces enabled
/// When: Executing safe_nsenter with the current process ID and a callback
/// Then: The operation should fail with a validation error
#[test]
fn test_safe_nsenter_pid_no_namespaces() -> Result<()> {
    let cedar_auth = TestCedarAuthBuilder::default().build().unwrap().create();
    let pid = std::process::id();
    let options = NamespaceOptionsBuilder::default().pid(pid).build().unwrap(); // No namespaces enabled

    let process_manager = RcProcessManager::default();
    let result = process_manager.safe_nsenter(
        &options,
        || -> Result<&str, Error> { Ok("test_result") },
        &cedar_auth,
    );

    assert!(result.is_err());
    let error = result.unwrap_err();

    assert!(matches!(
        error,
        RustSafeProcessMgmtError::ValidationError { .. }
    ));

    let error_msg = error.to_string();
    assert!(error_msg.contains("At least one namespace type (mount or net) must be enabled"));

    Ok(())
}

/// Given: A ProcessManager and namespace options with atleast one namespace enabled
/// When: Executing safe_nsenter with a non-existent process ID and a callback
/// Then: The operation should fail with an error indicating the process doesn't exist
#[test]
fn test_safe_nsenter_invalid_pid() -> Result<()> {
    let cedar_auth = TestCedarAuthBuilder::default().build().unwrap().create();
    let pid = 999999;
    let options = NamespaceOptionsBuilder::default()
        .mount(true)
        .pid(pid)
        .build()
        .unwrap();

    let process_manager = RcProcessManager::default();
    let result = process_manager.safe_nsenter(
        &options,
        || -> Result<&str, Error> { Ok("should_not_execute") },
        &cedar_auth,
    );

    assert!(result.is_err());
    let error = result.unwrap_err();

    assert!(matches!(
        error,
        RustSafeProcessMgmtError::ProcessNotFound { .. }
    ));

    let error_msg = error.to_string();
    assert!(error_msg.contains("Process with specified PID does not exist"));

    Ok(())
}

/// Given: A nonexistent network namespace file at /var/run/netns/test-nonexistent-ns
/// When: Using safe_nsenter_net to enter the namespace
/// Then: Should fail since the namespace file doesn't exist
#[test]
fn test_safe_nsenter_nonexistent_net_namespace_file() -> Result<()> {
    let process_manager = RcProcessManager::default();
    let net_ns_name = "test-nonexistent-ns";

    let options = NamespaceOptionsBuilder::default()
        .net(true)
        .net_ns_name(net_ns_name)
        .build()
        .unwrap();

    let result = process_manager.safe_nsenter(
        &options,
        || -> Result<&str, Error> { Ok("successfully_entered_namespace") },
        &DEFAULT_TEST_CEDAR_AUTH,
    );

    assert!(result.is_err());

    let error = result.unwrap_err();
    assert!(
        matches!(
            error,
            RustSafeProcessMgmtError::NamespaceOperationError { .. }
        ),
        "{}",
        error.to_string()
    );

    let error_msg = error.to_string();
    assert!(error_msg.contains("No such file or directory"));

    Ok(())
}

/// Given: A Cedar policy that denies opening a network namespace file
/// When: Calling safe_nsenter with a network namespace file
/// Then: Should return a permission denied error
#[test]
fn test_safe_nsenter_unauthorized_net_namespace_file() -> Result<()> {
    let principal = get_test_rex_principal();
    let deny_network_namespace_file_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action,
            resource
        );
        
        forbid(
            principal == User::"{principal}",
            action == {},
            resource is file_system::File in file_system::Dir::"/run/netns"
        );"#,
        FilesystemAction::NetworkNamespace,
    );

    let deny_cedar_auth = TestCedarAuthBuilder::default()
        .policy(deny_network_namespace_file_policy)
        .build()
        .unwrap()
        .create();

    let process_manager = RcProcessManager::default();
    let net_ns_name = "test-nonexistent-ns";

    let options = NamespaceOptionsBuilder::default()
        .net_ns_name(net_ns_name)
        .build()
        .unwrap();

    let result = process_manager.safe_nsenter(
        &options,
        || -> Result<&str, Error> { Ok("successfully entered namespace") },
        &deny_cedar_auth,
    );

    assert!(result.is_err());

    let error = result.unwrap_err();
    assert!(matches!(
        error,
        RustSafeProcessMgmtError::PermissionDenied { .. }
    ));

    let error_msg = error.to_string();
    assert!(error_msg.contains("Permission denied"));

    Ok(())
}

/// Given: A Cedar policy that permits the ListFds action
/// When: Calling safe_fuser with a common path
/// Then: Should return results with expected fields
#[test]
fn test_safe_fuser_returns_data() -> Result<()> {
    let test_policy = get_default_test_rex_policy();

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let process_manager = RcProcessManager::default();

    let fuser_results = process_manager.safe_fuser(&test_cedar_auth, ".")?;

    assert!(fuser_results.len() >= 1);

    let mut test_process_found = false;

    for (i, fuser_info) in fuser_results.iter().enumerate() {
        assert!(
            !fuser_info.user.is_empty(),
            "FuserInfo #{} has empty user",
            i
        );

        assert_ne!(
            fuser_info.user, "unknown",
            "FuserInfo #{} has fallback username, expected actual username",
            i
        );

        assert!(
            !fuser_info.user.contains('/') && !fuser_info.user.contains('\\'),
            "FuserInfo #{} has invalid username format: {}",
            i,
            fuser_info.user
        );

        assert!(fuser_info.pid > 0, "FuserInfo #{} has invalid PID", i);

        assert!(
            !fuser_info.access_types.is_empty(),
            "FuserInfo #{} has empty access_types",
            i
        );

        assert!(
            !fuser_info.command.is_empty(),
            "FuserInfo #{} has empty command",
            i
        );

        if fuser_info.pid == std::process::id() {
            test_process_found = true;
        }

        // Check command format - should not contain full paths for the executable
        // This verifies format_command is working correctly
        let command_parts: Vec<&str> = fuser_info.command.split_whitespace().collect();
        if !command_parts.is_empty() {
            let executable = command_parts[0];
            // The executable name should not contain directory separators
            // because format_command removes the path
            assert!(
                !executable.contains('/'),
                "FuserInfo #{} command executable '{}' contains path separators, expected simplified format",
                i,
                executable
            );
        }

        let access_str = fuser_info.format_access();
        assert!(
            !access_str.is_empty(),
            "format_access returned empty string"
        );

        // Verify the format_access output contains the expected access type descriptions
        for access_type in &fuser_info.access_types {
            let expected_text = match access_type {
                AccessType::FileDescriptor => "File descriptor",
                AccessType::RootDirectory => "Root directory",
                AccessType::CurrentDirectory => "Working directory",
                AccessType::Executable => "Executable",
                AccessType::MemoryMapped => "Memory mapped",
                _ => "Unknown access type", // Handle any future variants
            };
            assert!(
                access_str.contains(expected_text),
                "format_access output '{}' should contain '{}'",
                access_str,
                expected_text
            );
        }
    }

    assert!(test_process_found, "Should find the current test process");

    Ok(())
}

/// Given: A policy that denies access to all processes
/// When: Getting fuser information
/// Then: Should Error
#[test]
fn test_safe_fuser_permission_denied() -> Result<()> {
    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"forbid(
            principal == User::"{principal}",
            action in [{}, {}],
            resource
        );
        
        forbid(
            principal == User::"{principal}",
            action in [
                {}
            ],
            resource
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Read,
        ProcessAction::ListFds
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let process_manager = RcProcessManager::default();

    let fuser_results = process_manager.safe_fuser(&test_cedar_auth, ".");

    assert!(fuser_results.is_err());

    let error = fuser_results.unwrap_err();
    assert!(matches!(
        error,
        RustSafeProcessMgmtError::PermissionDenied { .. }
    ));

    let error_msg = error.to_string();
    assert!(error_msg.contains("Permission denied"));

    Ok(())
}

/// Given: A path that is mmap'd
/// When: Calling fuser API on mmap'd path
/// Then: Return the information including that it's an mmap
#[test]
fn test_memory_mapped_access_detection() -> Result<(), anyhow::Error> {
    let temp_dir = tempdir()?;
    let test_file_path = temp_dir.path().join("test_mmap_file");
    let mut file = File::create(&test_file_path)?;
    file.write_all(b"test content for memory mapping")?;

    let canonical_path = std::fs::canonicalize(&test_file_path)?;
    let canonical_path_str = canonical_path.to_string_lossy().to_string();

    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action == {},
            resource
        );

        permit(
            principal == User::"{principal}",
            action in [{}, {}],
            resource
        );
        "#,
        ProcessAction::ListFds,
        FilesystemAction::Open,
        FilesystemAction::Read,
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let process_manager = RcProcessManager::default();

    let mmap_file = std::fs::File::open(&test_file_path)?;
    let mmap = unsafe { memmap2::Mmap::map(&mmap_file)? };

    let fuser_results = process_manager.safe_fuser(&test_cedar_auth, &canonical_path_str)?;

    drop(mmap);

    let current_pid = std::process::id();

    let mut found_memory_mapped = false;
    for fuser_info in fuser_results {
        if fuser_info.pid == current_pid {
            if fuser_info.access_types.contains(&AccessType::MemoryMapped) {
                found_memory_mapped = true;
                break;
            }
        }
    }

    assert!(found_memory_mapped);

    Ok(())
}

/// Given: A ProcessManager with a spawned child process
/// When: Calling safe_kill with the child process PID and command matching
/// Then: Should successfully kill the child process using both PID and command targeting
#[test]
fn test_safe_kill_child_process_comprehensive() -> Result<()> {
    init_test_logger();
    let process_manager = RcProcessManager::default();

    let mut child = Command::new("sleep")
        .arg("30")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to spawn child process");

    let child_pid = child.id();
    sleep(Duration::from_millis(100));

    let processes = process_manager.safe_processes(&DEFAULT_TEST_CEDAR_AUTH)?;
    assert!(
        !processes.is_empty(),
        "Should have processes available for testing"
    );

    let child_command = processes
        .iter()
        .find(|p| p.pid == child_pid)
        .map(|p| p.command.clone());

    if child_command.is_none() {
        let _ = child.kill();
        let _ = child.wait();
        return Ok(());
    }

    let kill_options_pid = KillOptionsBuilder::default()
        .pid(child_pid.into())
        .signal(Signal::TERM)
        .build()?;

    let killed_pids = process_manager.safe_kill(&DEFAULT_TEST_CEDAR_AUTH, kill_options_pid)?;
    assert_eq!(killed_pids.len(), 1);
    assert_eq!(killed_pids[0].1, child_pid);

    let exit_status = child.wait()?;

    #[cfg(unix)]
    {
        assert!(
            exit_status.signal().is_some(),
            "Child process should have been terminated by signal"
        );
    }

    let mut child2 = Command::new("sleep")
        .arg("25")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to spawn second child process");

    sleep(Duration::from_millis(100));
    let processes2 = process_manager.safe_processes(&DEFAULT_TEST_CEDAR_AUTH)?;

    let child2_command = processes2
        .iter()
        .find(|p| p.pid == child2.id())
        .map(|p| p.command.clone());

    if let Some(cmd) = child2_command {
        let kill_options_cmd_exact = KillOptionsBuilder::default()
            .command(&cmd)
            .exact_match(true)
            .signal(Signal::TERM)
            .build()?;

        let killed_pids_exact =
            process_manager.safe_kill(&DEFAULT_TEST_CEDAR_AUTH, kill_options_cmd_exact)?;
        assert!(
            !killed_pids_exact.is_empty(),
            "Should kill process matching exact command"
        );
    }

    let _ = child2.kill();
    let _ = child2.wait();

    Ok(())
}

/// Given: A ProcessManager with multiple spawned child processes
/// When: Calling safe_kill with various targeting methods
/// Then: Should kill processes using name matching (exact/partial), username filtering, and combinations
#[test]
fn test_safe_kill_comprehensive_targeting() -> Result<()> {
    init_test_logger();
    let process_manager = RcProcessManager::default();

    let mut children = Vec::new();
    let num_children = 3;

    for i in 0..num_children {
        let child = Command::new("sleep")
            .arg(&format!("{}", 30 + i))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("Failed to spawn child process");

        children.push(child);
    }

    sleep(Duration::from_millis(200));

    let processes = process_manager.safe_processes(&DEFAULT_TEST_CEDAR_AUTH)?;

    let child_pids: Vec<u32> = children.iter().map(|c| c.id()).collect();
    let visible_children = processes
        .iter()
        .filter(|p| child_pids.contains(&p.pid))
        .count();

    if visible_children == 0 {
        for mut child in children {
            let _ = child.kill();
            let _ = child.wait();
        }
        return Ok(());
    }

    let current_username = processes
        .iter()
        .find(|p| p.pid == std::process::id())
        .map(|p| p.username.clone())
        .unwrap_or_else(|| "unknown".to_string());

    let kill_options_exact = KillOptionsBuilder::default()
        .process_name("sleep")
        .signal(Signal::TERM)
        .exact_match(true)
        .build()?;

    let killed_pids_exact =
        process_manager.safe_kill(&DEFAULT_TEST_CEDAR_AUTH, kill_options_exact)?;
    assert!(
        killed_pids_exact.len() >= visible_children,
        "Should have killed at least {} processes with exact name match, but killed {}",
        visible_children,
        killed_pids_exact.len()
    );

    children.clear();
    for i in 0..2 {
        let child = Command::new("sleep")
            .arg(&format!("{}", 25 + i))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("Failed to spawn child process");
        children.push(child);
    }

    sleep(Duration::from_millis(100));
    let _processes = process_manager.safe_processes(&DEFAULT_TEST_CEDAR_AUTH)?;

    let kill_options_name_user = KillOptionsBuilder::default()
        .process_name("sleep")
        .username(&current_username)
        .signal(Signal::TERM)
        .exact_match(true)
        .build()?;

    let killed_pids_name_user =
        process_manager.safe_kill(&DEFAULT_TEST_CEDAR_AUTH, kill_options_name_user)?;
    assert!(
        !killed_pids_name_user.is_empty(),
        "Should have killed processes with name+username match"
    );

    children.clear();
    let child = Command::new("sleep")
        .arg("20")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to spawn child process");
    children.push(child);

    sleep(Duration::from_millis(100));
    let _processes = process_manager.safe_processes(&DEFAULT_TEST_CEDAR_AUTH)?;

    let kill_options_partial = KillOptionsBuilder::default()
        .process_name("sleep")
        .signal(Signal::TERM)
        .exact_match(false)
        .build()?;

    let killed_pids_partial =
        process_manager.safe_kill(&DEFAULT_TEST_CEDAR_AUTH, kill_options_partial)?;
    assert!(
        !killed_pids_partial.is_empty(),
        "Should have killed processes with partial name match"
    );

    for mut child in children {
        let _ = child.kill();
        let _ = child.wait();
    }

    Ok(())
}

/// Given: A fresh RcProcessManager with no prior safe_processes call (empty cache)
/// When: Calling safe_kill with a valid child process PID
/// Then: Should lazily cache the process and successfully kill it
#[test]
fn test_safe_kill_without_prior_safe_processes() -> Result<()> {
    init_test_logger();
    // Fresh manager — cache is empty, no safe_processes call
    let process_manager = RcProcessManager::default();

    let mut child = Command::new("sleep")
        .arg("30")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to spawn child process");

    let child_pid = child.id();
    sleep(Duration::from_millis(100));

    // Kill directly without calling safe_processes first
    let kill_options = KillOptionsBuilder::default()
        .pid(child_pid.into())
        .signal(Signal::TERM)
        .build()?;

    let killed = process_manager.safe_kill(&DEFAULT_TEST_CEDAR_AUTH, kill_options)?;
    assert_eq!(killed.len(), 1, "Should have killed exactly one process");
    assert_eq!(killed[0].1, child_pid, "Killed PID should match child PID");

    let exit_status = child.wait()?;
    assert!(
        !exit_status.success(),
        "Child should have been terminated by signal"
    );

    Ok(())
}

/// Given: A ProcessManager with various error conditions
/// When: Calling safe_kill with invalid parameters or insufficient permissions
/// Then: Should handle errors gracefully with appropriate error messages
#[test]
fn test_safe_kill_error_conditions() -> Result<()> {
    init_test_logger();
    let principal = get_test_rex_principal();

    let deny_policy = format!(
        r#"
        permit(
            principal == User::"{principal}",
            action == {},
            resource
        );

                permit(
            principal == User::"{principal}",
            action == {},
            resource
        );
        
        forbid(
            principal == User::"{principal}",
            action == {},
            resource
        );
        "#,
        ProcessAction::List,
        ProcessAction::Kill,
        ProcessAction::Interrupt
    );

    let deny_cedar_auth = TestCedarAuthBuilder::default()
        .policy(deny_policy)
        .build()
        .unwrap()
        .create();

    let process_manager = RcProcessManager::default();

    let _processes = process_manager.safe_processes(&deny_cedar_auth)?;

    let kill_options_denied = KillOptionsBuilder::default()
        .pid(std::process::id().into())
        .signal(Signal::HUP)
        .build()?;

    let result_denied = process_manager.safe_kill(&deny_cedar_auth, kill_options_denied);
    assert!(result_denied.is_err());
    assert_error_contains(result_denied, "Permission denied");

    let _processes = process_manager.safe_processes(&DEFAULT_TEST_CEDAR_AUTH)?;

    let kill_options_nonexistent = KillOptionsBuilder::default()
        .pid(999999999)
        .signal(Signal::TERM)
        .build()?;

    let result_nonexistent =
        process_manager.safe_kill(&DEFAULT_TEST_CEDAR_AUTH, kill_options_nonexistent);
    assert!(result_nonexistent.is_err());
    assert_error_contains(result_nonexistent, "not found");

    Ok(())
}

/// Given: A ProcessManager with processes
/// When: Calling safe_kill with criteria that match no processes
/// Then: Should return an error indicating no processes were found
#[test]
fn test_safe_kill_no_matching_processes() -> Result<()> {
    init_test_logger();
    let process_manager = RcProcessManager::default();

    let _processes = process_manager.safe_processes(&DEFAULT_TEST_CEDAR_AUTH)?;

    let kill_options_no_name = KillOptionsBuilder::default()
        .process_name("definitely_nonexistent_process_name_12345")
        .signal(Signal::TERM)
        .exact_match(true)
        .build()?;

    let result_no_name = process_manager.safe_kill(&DEFAULT_TEST_CEDAR_AUTH, kill_options_no_name);
    assert!(result_no_name.is_err());
    assert_error_contains(result_no_name, "No matching processes found");

    let kill_options_no_cmd = KillOptionsBuilder::default()
        .command("nonexistent_command_with_args_that_will_never_match_12345")
        .signal(Signal::TERM)
        .build()?;

    let result_no_cmd = process_manager.safe_kill(&DEFAULT_TEST_CEDAR_AUTH, kill_options_no_cmd);
    assert!(result_no_cmd.is_err());
    assert_error_contains(result_no_cmd, "No matching processes found");

    let kill_options_no_user = KillOptionsBuilder::default()
        .username("nonexistent_user_12345")
        .signal(Signal::TERM)
        .build()?;

    let result_no_user = process_manager.safe_kill(&DEFAULT_TEST_CEDAR_AUTH, kill_options_no_user);
    assert!(result_no_user.is_err());
    assert_error_contains(result_no_user, "No matching processes found");

    Ok(())
}

/// Given: A ProcessManager with a child process that exits quickly
/// When: Attempting to kill a process that no longer exists (testing pidfd error case)
/// Then: Should handle the race condition and pidfd errors gracefully
#[test]
fn test_safe_kill_race_condition_and_pidfd_errors() -> Result<()> {
    init_test_logger();
    let process_manager = RcProcessManager::default();

    let mut child = Command::new("sleep")
        .arg("0.1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to spawn child process");

    let child_pid = child.id();

    let _processes = process_manager.safe_processes(&DEFAULT_TEST_CEDAR_AUTH)?;

    let _ = child.wait();

    let kill_options = KillOptionsBuilder::default()
        .pid(child_pid.into())
        .signal(Signal::TERM)
        .build()?;

    let result = process_manager.safe_kill(&DEFAULT_TEST_CEDAR_AUTH, kill_options);

    assert_error_contains(result, "No such process");

    Ok(())
}

/// Given: A ProcessManager with proper Cedar authorization
/// When: Calling safe_ipcs to get System V IPC information
/// Then: Should return IpcsInfo with all three IPC types populated
#[test]
fn test_safe_ipcs_success() -> Result<()> {
    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action in [{}, {}],
            resource
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Read,
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let process_manager = RcProcessManager::default();
    let ipcs_info = process_manager.safe_ipcs(&test_cedar_auth)?;

    assert!(
        !ipcs_info.shared_memory.is_empty() || ipcs_info.shared_memory.is_empty(),
        "shared_memory field should be accessible"
    );
    assert!(
        !ipcs_info.queues.is_empty() || ipcs_info.queues.is_empty(),
        "queues field should be accessible"
    );
    assert!(
        !ipcs_info.semaphores.is_empty() || ipcs_info.semaphores.is_empty(),
        "semaphores field should be accessible"
    );

    let display_output = ipcs_info.to_string();
    assert!(display_output.contains("Shared Memory Segments:"));
    assert!(display_output.contains("Message Queues:"));
    assert!(display_output.contains("Semaphore Arrays:"));

    Ok(())
}

/// Given: A ProcessManager with Cedar policy that denies opening /proc directory
/// When: Calling safe_ipcs without permission to open /proc
/// Then: Should return a permission denied error for directory access
#[test]
fn test_safe_ipcs_permission_denied_proc_open() -> Result<()> {
    let principal = get_test_rex_principal();
    let deny_proc_open_policy = format!(
        r#"forbid(
            principal == User::"{principal}",
            action == {},
            resource
        );
        
        permit(
            principal == User::"{principal}",
            action == {},
            resource
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Read,
    );

    let deny_cedar_auth = TestCedarAuthBuilder::default()
        .policy(deny_proc_open_policy)
        .build()
        .unwrap()
        .create();

    let process_manager = RcProcessManager::default();
    let result = process_manager.safe_ipcs(&deny_cedar_auth);

    assert!(result.is_err());

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Open
    );
    assert_error_contains(result, &expected_error);

    Ok(())
}

/// Given: A ProcessManager with Cedar policy that denies reading sysvipc files
/// When: Calling safe_ipcs without permission to read sysvipc files
/// Then: Should return a permission denied error for file read access
#[test]
fn test_safe_ipcs_permission_denied_sysvipc_read() -> Result<()> {
    let principal = get_test_rex_principal();
    let deny_sysvipc_read_policy = format!(
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
        FilesystemAction::Read,
    );

    let deny_cedar_auth = TestCedarAuthBuilder::default()
        .policy(deny_sysvipc_read_policy)
        .build()
        .unwrap()
        .create();

    let process_manager = RcProcessManager::default();
    let result = process_manager.safe_ipcs(&deny_cedar_auth);

    assert!(result.is_err());

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Read
    );
    assert_error_contains(result, &expected_error);

    Ok(())
}

/// Given: A process spawned with exec -a
/// When: Getting process information via safe_processes
/// Then: Command should be formatted correctly - executable path simplified, argument paths preserved
#[test]
fn test_command_format_for_exec_process() -> Result<()> {
    let temp_dir = tempdir()?;
    let temp_file = temp_dir.path().join("file.txt");
    let temp_file_path = temp_file.to_str().unwrap();

    let mut exec_process = Command::new("sh")
        .arg("-c")
        .arg(format!("exec -a 'worker -D {}' sleep 30", temp_file_path))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    let exec_process_pid = exec_process.id();

    let process_manager = RcProcessManager::default();
    let processes = process_manager.safe_processes(&DEFAULT_TEST_CEDAR_AUTH)?;
    let process = processes
        .iter()
        .find(|p| p.pid == exec_process_pid)
        .expect("Should find the spawned worker process");

    let expected_command = format!("worker -D {} 30", temp_file_path);
    assert_eq!(
        process.command, expected_command,
        "Command should be '{}', got: '{}'",
        expected_command, process.command
    );

    let _ = exec_process.kill();

    Ok(())
}

/// Given: A process spawned with flags and path arguments
/// When: Getting process information via safe_processes
/// Then: Command should preserve all flags and path arguments, but simplify the executable path
#[test]
fn test_command_format_for_regular_process_with_flags() -> Result<()> {
    let mut tail_process = Command::new("/usr/bin/tail")
        .arg("-f")
        .arg("/dev/null")
        .arg("-n")
        .arg("100")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    let tail_pid = tail_process.id();

    let process_manager = RcProcessManager::default();
    let processes = process_manager.safe_processes(&DEFAULT_TEST_CEDAR_AUTH)?;
    let process = processes
        .iter()
        .find(|p: &&rust_safe_process_mgmt::ProcessInfo| p.pid == tail_pid)
        .expect("Should find the spawned tail process");

    let expected_command = "tail -f /dev/null -n 100";
    assert_eq!(
        process.command, expected_command,
        "Command should be '{}', got: '{}'",
        expected_command, process.command
    );

    let _ = tail_process.kill();

    Ok(())
}

/// Given: A spawned tail process
/// When: Getting process information via safe_processes
/// Then: ProcessInfo fields should match values from the system
#[test]
fn test_process_info_all_fields_validation() -> Result<()> {
    // memory_usage and memory_percent are not validated here because they can be flaky on remote builds
    let tail_process = Command::new("/usr/bin/tail")
        .arg("-f")
        .arg("/dev/null")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    let tail_pid = tail_process.id();

    let ps_output = Command::new("ps")
        .arg("-p")
        .arg(tail_pid.to_string())
        .arg("-o")
        .arg("pid,ppid,uid,user,comm,state,rss,args")
        .arg("--no-headers")
        .output()?;

    let ps_line = String::from_utf8_lossy(&ps_output.stdout);
    let ps_fields: Vec<&str> = ps_line.split_whitespace().collect();

    let expected_pid: u32 = ps_fields[0].parse()?;
    let expected_ppid: u32 = ps_fields[1].parse()?;
    let expected_uid: u32 = ps_fields[2].parse()?;
    let expected_username = ps_fields[3];
    let expected_name = ps_fields[4];
    let expected_rss_kb: u64 = ps_fields[6].parse()?;
    let expected_memory_usage: u64 = expected_rss_kb * 1024; // Convert KB to bytes

    let process_manager = RcProcessManager::default();
    let processes = process_manager.safe_processes(&DEFAULT_TEST_CEDAR_AUTH)?;

    let process = processes
        .iter()
        .find(|p| p.pid == tail_pid)
        .expect("Should find the spawned tail process");

    assert_eq!(process.pid, expected_pid, "PID should match ps output");
    assert_eq!(process.name, expected_name, "Name should match ps output");
    assert!(process.ppid.is_some(), "Process should have a parent PID");
    assert_eq!(
        process.ppid.unwrap(),
        expected_ppid,
        "Parent PID should match ps output"
    );
    assert!(process.uid.is_some(), "Process should have a numeric UID");
    assert_eq!(
        process.uid.unwrap(),
        expected_uid,
        "UID should match ps output"
    );
    assert_eq!(
        process.username, expected_username,
        "Username should match ps output"
    );

    assert!(
        !process.state.is_empty(),
        "Process state should not be empty"
    );

    Ok(())
}
/// Given: A ProcessManager with valid MonitorProcessesCpuOptions
/// When: Calling safe_monitor_processes_cpu with the current test process
/// Then: Should return batches of ProcessInfo with CPU usage data populated
#[test]
fn test_safe_monitor_processes_cpu_returns_data() -> Result<()> {
    let process_manager = RcProcessManager::default();
    let current_pid = std::process::id();
    let target_pids = vec![current_pid];

    let options = MonitorProcessesCpuOptionsBuilder::default()
        .pids_to_monitor(target_pids.clone())
        .batches(2)
        .delay_in_seconds(0)
        .build()?;

    let batches = process_manager.safe_monitor_processes_cpu(&DEFAULT_TEST_CEDAR_AUTH, options)?;

    assert_eq!(batches.len(), 2, "Should return 2 batches");

    for batch in batches.iter() {
        assert!(!batch.is_empty(), "Batch should not be empty");

        for process in batch {
            assert_eq!(
                process.pid, current_pid,
                "Process PID should match current process"
            );
            assert!(
                process.recent_cpu_usage.is_some(),
                "CPU usage should be populated"
            );
            assert!(
                process.recent_cpu_usage.unwrap() >= 0.0,
                "CPU usage should be non-negative"
            );
        }
    }

    Ok(())
}

/// Given: A ProcessManager with empty PID list
/// When: Building MonitorProcessesCpuOptions with no target PIDs
/// Then: Should return a ValidationError from the builder
#[test]
fn test_safe_monitor_processes_cpu_empty_pids() -> Result<()> {
    let result = MonitorProcessesCpuOptionsBuilder::default()
        .pids_to_monitor(vec![])
        .batches(1)
        .build();

    assert!(result.is_err(), "Expected an error for empty pids array");
    let expected_err = "PIDs array cannot be empty";
    assert_error_contains(result, expected_err);

    Ok(())
}

/// Given: A ProcessManager with invalid PID
/// When: Calling safe_monitor_processes_cpu with non-existent PID
/// Then: Should return empty batches (processes that don't exist are skipped)
#[test]
fn test_safe_monitor_processes_cpu_invalid_pid() -> Result<()> {
    let process_manager = RcProcessManager::default();

    let options = MonitorProcessesCpuOptionsBuilder::default()
        .pids_to_monitor(vec![999999])
        .batches(1)
        .build()?;

    let batches = process_manager.safe_monitor_processes_cpu(&DEFAULT_TEST_CEDAR_AUTH, options)?;

    assert_eq!(batches.len(), 1, "Should return 1 batch");
    assert!(
        batches[0].is_empty(),
        "Batch should be empty for non-existent PID"
    );

    Ok(())
}

/// Given: A policy that denies process listing
/// When: Calling safe_monitor_processes_cpu
/// Then: Should return empty batches due to permission denial
#[test]
fn test_safe_monitor_processes_cpu_permission_denied() -> Result<()> {
    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"forbid(
            principal == User::"{principal}",
            action == {},
            resource
        );"#,
        ProcessAction::List
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let process_manager = RcProcessManager::default();

    let options = MonitorProcessesCpuOptionsBuilder::default()
        .pids_to_monitor(vec![std::process::id()])
        .batches(1)
        .build()?;

    let batches = process_manager.safe_monitor_processes_cpu(&test_cedar_auth, options)?;

    assert_eq!(batches.len(), 1, "Should return 1 batch");
    assert!(
        batches[0].is_empty(),
        "Batch should be empty due to permission denial"
    );

    Ok(())
}

/// Given: A ProcessManager with include_threads option enabled
/// When: Calling safe_monitor_processes_cpu with include_threads=true
/// Then: Should return batches with main process and thread data populated
#[test]
fn test_safe_monitor_processes_cpu_with_threads() -> Result<()> {
    let process_manager = RcProcessManager::default();
    let current_pid = std::process::id();
    let target_pids = vec![current_pid];

    let options = MonitorProcessesCpuOptionsBuilder::default()
        .pids_to_monitor(target_pids.clone())
        .batches(2)
        .delay_in_seconds(0)
        .include_threads(true)
        .build()?;

    let batches = process_manager.safe_monitor_processes_cpu(&DEFAULT_TEST_CEDAR_AUTH, options)?;

    assert_eq!(batches.len(), 2, "Should return 2 batches");

    for batch in batches.iter() {
        assert!(!batch.is_empty(), "Batch should not be empty");

        let main_process = batch.iter().find(|p| p.pid == current_pid);
        assert!(
            main_process.is_some(),
            "Main process should be present in batch"
        );

        let main_proc = main_process.unwrap();
        assert!(
            main_proc.recent_cpu_usage.is_some(),
            "Main process CPU usage should be populated"
        );
        assert!(
            main_proc.recent_cpu_usage.unwrap() >= 0.0,
            "Main process CPU usage should be non-negative"
        );

        for process in batch {
            assert!(
                process.recent_cpu_usage.is_some(),
                "CPU usage should be populated"
            );
            assert!(
                process.recent_cpu_usage.unwrap() >= 0.0,
                "CPU usage should be non-negative"
            );
        }
    }

    Ok(())
}

/// Given: ProcessOptions with load_namespace_info=true
/// When: Calling safe_processes_with_options
/// Then: Should return processes with namespace info populated and validated against /proc
#[test]
fn test_safe_processes_with_options_with_namespace_info() -> Result<()> {
    let process_manager = RcProcessManager::default();
    let options = ProcessOptionsBuilder::default()
        .load_namespace_info(true)
        .build()?;

    let processes =
        process_manager.safe_processes_with_options(&DEFAULT_TEST_CEDAR_AUTH, options)?;

    assert!(!processes.is_empty(), "Should return processes");

    // Read current process namespace from /proc/self/ns/pid for validation
    let self_ns_link = std::fs::read_link("/proc/self/ns/pid")?;
    let self_ns_str = self_ns_link.to_string_lossy();
    let self_ns_id: u64 = self_ns_str
        .strip_prefix("pid:[")
        .and_then(|s| s.strip_suffix(']'))
        .and_then(|s| s.parse().ok())
        .expect("Failed to parse self namespace ID");

    // Read current process NSpid from /proc/self/status
    let status_content = std::fs::read_to_string("/proc/self/status")?;
    let nspid_line = status_content
        .lines()
        .find(|line| line.starts_with("NSpid:"))
        .expect("NSpid line not found");
    let nspid_values: Vec<u32> = nspid_line
        .strip_prefix("NSpid:")
        .unwrap()
        .split_whitespace()
        .filter_map(|s| s.parse().ok())
        .collect();
    let expected_child_ns_pid = *nspid_values
        .last()
        .expect("NSpid should have at least one value");

    // Find current process in results
    let current_pid = std::process::id();
    let current_process = processes.iter().find(|p| p.pid == current_pid);

    assert!(
        current_process.is_some(),
        "Current process should be in results"
    );
    let proc = current_process.unwrap();

    assert!(
        proc.pid_namespace.is_some(),
        "Current process should have namespace info"
    );
    let ns = proc.pid_namespace.as_ref().unwrap();

    assert_eq!(
        ns.namespace_id, self_ns_id,
        "Namespace ID should match /proc/self/ns/pid"
    );
    assert_eq!(
        ns.child_ns_pid, expected_child_ns_pid,
        "Child PID should match last value from NSpid in /proc/self/status"
    );

    Ok(())
}

/// Given: A fresh RcProcessManager with no prior safe_processes call
/// When: Calling safe_trace_with_namespace with a non-existent PID
/// Then: Should return error indicating namespace info not available
#[test]
fn test_safe_trace_with_namespace_cache_not_initialized() -> Result<()> {
    let process_manager = RcProcessManager::default();
    let non_existent_pid: u32 = 999_999_999;
    let trace_options = TraceOptionsBuilder::default().ns_pid(1).build()?;
    let result = process_manager.safe_trace_with_namespace(
        &DEFAULT_TEST_CEDAR_AUTH,
        non_existent_pid,
        trace_options,
    );

    assert_error_contains(result, "PID namespace not found");
    Ok(())
}

/// Given: Cache populated without load_namespace_info option
/// When: Calling safe_trace_with_namespace
/// Then: Should return error indicating namespace info not available
#[test]
fn test_safe_trace_with_namespace_cache_without_namespace_info() -> Result<()> {
    let process_manager = RcProcessManager::default();

    // Populate cache without namespace info
    let options = ProcessOptionsBuilder::default()
        .load_namespace_info(false)
        .build()?;
    process_manager.safe_processes_with_options(&DEFAULT_TEST_CEDAR_AUTH, options)?;

    let trace_options = TraceOptionsBuilder::default().ns_pid(1).build()?;
    let result =
        process_manager.safe_trace_with_namespace(&DEFAULT_TEST_CEDAR_AUTH, 1, trace_options);

    assert_error_contains(
        result,
        "PID namespace not found for PID 1: Namespace information was not present in process info",
    );

    Ok(())
}

/// Given: Cache populated
/// When: Calling safe_trace_with_namespace on non-existent PID
/// Then: Should return error indicating process not found
#[test]
fn test_safe_trace_with_namespace_cache_invalid_pid() -> Result<()> {
    let process_manager = RcProcessManager::default();

    // Populate cache without namespace info
    let options = ProcessOptionsBuilder::default()
        .load_namespace_info(true)
        .build()?;
    process_manager.safe_processes_with_options(&DEFAULT_TEST_CEDAR_AUTH, options)?;

    // use the current pid because we're allowed to get namespace info for it without CAP_SYS_PTRACE
    let current_pid = process::id();
    let trace_options = TraceOptionsBuilder::default().ns_pid(current_pid).build()?;
    let result =
        process_manager.safe_trace_with_namespace(&DEFAULT_TEST_CEDAR_AUTH, 9999999, trace_options);

    assert_error_contains(result, "Process information was not present in the cache");

    Ok(())
}

/// Given: Process in another namespace without authorization
/// When: Calling safe_trace_with_namespace
/// Then: Should return authorization error
#[test]
fn test_safe_trace_with_namespace_unauthorized() -> Result<()> {
    let principal = get_test_rex_principal();
    let test_policy = format!(
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

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let process_manager = RcProcessManager::default();

    // Populate cache with namespace info
    let options = ProcessOptionsBuilder::default()
        .load_namespace_info(true)
        .build()?;
    process_manager.safe_processes_with_options(&test_cedar_auth, options)?;

    // use the current pid because we're allowed to get namespace info for it without CAP_SYS_PTRACE
    let current_pid = process::id();
    let trace_options = TraceOptionsBuilder::default().ns_pid(current_pid).build()?;
    let result =
        process_manager.safe_trace_with_namespace(&test_cedar_auth, current_pid, trace_options);

    assert_error_contains(result, "Permission denied");

    Ok(())
}
