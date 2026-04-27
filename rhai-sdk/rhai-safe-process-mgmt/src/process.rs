//! Process management functionality for Rhai scripts
//! The functions used here are declared in the rust-safe-process-mgmt crate.
#![deny(missing_docs)]
#![allow(
    unused_variables,
    unreachable_code,
    clippy::unreachable,
    unused_mut,
    clippy::needless_pass_by_value
)]
use anyhow::Result;
use rhai::{Dynamic, EvalAltResult, FnPtr, NativeCallContext};
use rust_safe_io::TracedProcess;
use rust_safe_process_mgmt::options::{
    KillOptions, LsofOptions, MonitorProcessesCpuOptions, NamespaceOptions,
};
use rust_safe_process_mgmt::{FuserInfo, IpcsInfo, ProcessInfo};

/// Manages process-related operations such as listing and killing processes, inspecting open files, ptrace, and more.
#[derive(Debug, Clone, Copy)]
pub struct ProcessManager;

impl ProcessManager {
    /// Gets all processes accessible to the current user
    ///
    /// This method retrieves information about all processes on the system, applying Cedar authorization
    /// checks to ensure the caller has permission to access this information.
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `process_system::Action::"list"` | [`process_system::Process`](rex_cedar_auth::process::entities::ProcessEntity) |
    ///
    /// # Linux Capabilities
    ///
    /// | Capability | Condition |
    /// |-----------|-----------|
    /// | `CAP_SYS_PTRACE` | When `load_namespace_info = true` |
    ///
    /// See <https://man7.org/linux/man-pages/man7/namespaces.7.html>
    ///
    /// # Overloads
    ///
    /// * `processes()`        - Returns processes without namespace information and without threads (default behavior)
    /// * `processes(options)` - Returns processes with optional namespace information and thread filtering based on `ProcessOptions`
    ///   * `load_namespace_info` - When true, loads PID namespace information for each process
    ///   * `include_threads`     - When false (default), excludes threads (like `ps aux`). When true, includes threads (like `ps -eLf`)
    ///
    /// # Available Process Information
    ///
    /// Each process object contains the following fields:
    ///
    /// * `pid` - Process ID. For thread entries (when `include_threads=true`) this is the
    ///   thread ID (TID / LWP), **not** the process PID.
    /// * `name` - Process name
    /// * `ppid` - Parent process ID (if available). For thread entries this is the PID of
    ///   the process that owns the thread.
    /// * `uid` - User ID
    /// * `username` - Username of the process owner
    /// * `memory_usage` - Memory usage in bytes
    /// * `memory_percent` - Memory usage as percentage of system total
    /// * `state` - Process state (e.g., "Running", "Sleeping")
    /// * `command` - Full command line used to launch the process
    /// * `historical_cpu_usage` - Accumulated CPU usage percentage since process start (can exceed 100.0 on multi-core systems)
    /// * `pid_namespace` - Optional PID namespace information (only present when `load_namespace_info` is enabled)
    ///   * `namespace_id` - The inode number of the PID namespace
    ///   * `child_ns_pid` - The PID in the innermost namespace
    ///
    /// # Thread behaviour (`include_threads = true`)
    ///
    /// When threads are included the result set also contains one entry per thread
    /// (similar to `ps -eLf`). For these thread entries:
    /// - `pid` is the thread ID (TID / LWP), **not** the process PID.
    /// - `ppid` is the PID of the process that owns the thread.
    /// - `command` and `username` match the owning process.
    ///
    /// # Examples
    ///
    /// Basic usage without namespace info (threads excluded by default):
    /// ```
    /// # use rex_test_utils::rhai::process_mgmt::create_test_env;
    /// # use rhai::Dynamic;
    /// # let (mut scope, engine) = create_test_env();
    /// # let result = engine.eval_with_scope::<Dynamic>(
    /// #     &mut scope,
    /// #     r#"
    /// let process_manager = ProcessManager();
    /// let processes = process_manager.processes();  // Threads not included
    ///
    /// for process in processes {
    ///     print(`pid: ${process.pid}`);
    ///     print(`ppid: ${process.ppid}`);
    ///     print(`name: ${process.name}`);
    ///     print(`username: ${process.username}`);
    ///     print(`uid: ${process.uid}`);
    ///     print(`state: ${process.state}`);
    ///     print(`command: ${process.command}`);
    ///     print(`memory_usage: ${process.memory_usage}`);
    ///     print(`memory_percent: ${process.memory_percent}`);
    ///     print(`historical_cpu_usage: ${process.historical_cpu_usage}`);
    ///     print(`recent_cpu_usage: ${process.recent_cpu_usage}`);
    /// }
    /// #     "#
    /// # );
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    ///
    /// With namespace information:
    /// ```
    /// # use rex_test_utils::rhai::process_mgmt::create_test_env;
    /// # use rhai::Dynamic;
    /// # let (mut scope, engine) = create_test_env();
    /// # let result = engine.eval_with_scope::<Dynamic>(
    /// #     &mut scope,
    /// #     r#"
    /// let process_manager = ProcessManager();
    /// let options = ProcessOptions()
    ///     .load_namespace_info(true)
    ///     .build();
    /// let processes = process_manager.processes(options);
    ///
    /// for process in processes {
    ///     print(`PID: ${process.pid}`);
    ///     if process.pid_namespace != () {
    ///         print(`  Namespace ID: ${process.pid_namespace.namespace_id}`);
    ///         print(`  Child PID: ${process.pid_namespace.child_ns_pid}`);
    ///     }
    /// }
    /// #     "#
    /// # );
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    ///
    /// With threads included:
    /// ```
    /// # use rex_test_utils::rhai::process_mgmt::create_test_env;
    /// # use rhai::Dynamic;
    /// # let (mut scope, engine) = create_test_env();
    /// # let result = engine.eval_with_scope::<Dynamic>(
    /// #     &mut scope,
    /// #     r#"
    /// let process_manager = ProcessManager();
    /// let options = ProcessOptions()
    ///     .include_threads(true)
    ///     .build();
    /// let processes = process_manager.processes(options);
    ///
    /// for process in processes {
    ///     print(`pid: ${process.pid}, name: ${process.name}`);
    ///     if process.ppid != () {
    ///         print(`  parent pid: ${process.ppid}`);
    ///     }
    /// }
    /// #     "#
    /// # );
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[doc(alias = "ps")]
    #[doc(alias = "pgrep")]
    #[doc(alias = "pidof")]
    pub fn processes(&self) -> Result<Vec<ProcessInfo>, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Enters the specified namespaces of a process and executes a Rhai callback
    ///
    /// This function allows Rhai scripts to execute code within the namespaces of another process.
    /// The callback function is executed within the target namespace context with access to the full
    /// Rhai engine context including all registered functions.
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource | Condition |
    /// |--------|----------|-----------|
    /// | `process_system::Action::"mount_namespace"` | [`process_system::Process`](rex_cedar_auth::process::entities::ProcessEntity) | When entering mount namespace by pid |
    /// | `process_system::Action::"network_namespace"` | [`process_system::Process`](rex_cedar_auth::process::entities::ProcessEntity) | When entering network namespace by pid |
    /// | `file_system::Action::"network_namespace"` | [`file_system::File`](rex_cedar_auth::fs::entities::FileEntity) | When entering network namespace by name |
    ///
    /// # Linux Capabilities
    ///
    /// | Capability | Condition |
    /// |-----------|-----------|
    /// | `CAP_SYS_ADMIN` | Always |
    /// | `CAP_SYS_PTRACE` | When target process is not owned by current user |
    /// | `CAP_SYS_CHROOT` | When entering mount namespace |
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::process_mgmt::create_test_env;
    /// # use rhai::Dynamic;
    /// # let (mut scope, engine) = create_test_env();
    /// # let result = engine.eval_with_scope::<Dynamic>(
    /// #     &mut scope,
    /// #     r#"
    ///
    /// let pm = ProcessManager();
    /// let processes = pm.processes();
    ///
    /// // Find the target process pid from processes array
    /// let target_pid = -1;
    ///
    /// for process in processes {
    ///     if process.command.contains("postgres") {
    ///         target_pid = process.pid;
    ///         break;
    ///     }
    /// }
    ///
    /// // Using pid
    /// let options = NamespaceOptions()
    ///     .mount(true)
    ///     .pid(target_pid)
    ///     .net(true)
    ///     .build();
    ///
    /// // Using network namespace file
    /// let net_ns_file_options = NamespaceOptions()
    ///     .net_ns_name("customer")
    ///     .build()
    ///
    /// let result = pm.nsenter(options, || {
    ///     // Rhai Callback Function to execute inside the namespace
    /// });
    /// #     "#
    /// # );
    /// # // Expected to error due to missing postgres process and capabilities.
    /// # assert!(result.is_err(), "err: {:?}", result.unwrap_err());
    /// ```
    #[doc(alias = "ip netns")]
    pub fn nsenter(
        &mut self,
        ctx: &NativeCallContext,
        options: NamespaceOptions,
        callback: FnPtr,
    ) -> Result<Dynamic, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Gets processes that are using a file or directory, similar to `fuser -v <path>`
    ///
    /// This method identifies processes that are using the specified path based on [`rust_safe_process_mgmt::AccessType`],
    /// providing objects with properties for each process's information.
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"open"` | [`file_system::Dir`](rex_cedar_auth::fs::entities::DirEntity) |
    /// | `file_system::Action::"read"` | [`file_system::Dir`](rex_cedar_auth::fs::entities::DirEntity) |
    /// | `process_system::Action::"list_fds"` | [`process_system::Process`](rex_cedar_auth::process::entities::ProcessEntity) |
    ///
    /// # Linux Capabilities
    ///
    /// | Capability | Condition |
    /// |-----------|-----------|
    /// | `CAP_SYS_PTRACE` | When reading file descriptors of processes owned by other users |
    ///
    /// # Available Process Information
    ///
    /// Each process object contains the following properties:
    ///
    /// * `user` - Username of the process owner
    /// * `pid` - Process ID
    /// * `access` - Human-readable description of the access type
    /// * `command` - Full command line used to launch the process
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::process_mgmt::create_test_env;
    /// # use rhai::Dynamic;
    /// # let (mut scope, engine) = create_test_env();
    /// # let result = engine.eval_with_scope::<Dynamic>(
    /// #     &mut scope,
    /// #     r#"
    /// let process_manager = ProcessManager();
    /// let processes = process_manager.processes_using_inode(".");
    ///
    /// for process in processes {
    ///     print(`USER: ${process.user}, PID: ${process.pid}, ACCESS: ${process.access}, COMMAND: ${process.command}`)
    /// }
    /// #     "#
    /// # );
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[doc(alias = "fuser")]
    pub fn processes_using_inode(&self, path: &str) -> Result<Vec<FuserInfo>, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Lists open files, similar to `lsof <path>` or `lsof -p <pid>`
    ///
    /// Supports two mutually exclusive modes:
    /// * **Path mode** — list open files within a directory (like `lsof +d` / `lsof +D`)
    /// * **PID mode** — list all open files for a specific process (like `lsof -p`)
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"open"` | [`file_system::Dir`](rex_cedar_auth::fs::entities::DirEntity) |
    /// | `file_system::Action::"read"` | [`file_system::Dir`](rex_cedar_auth::fs::entities::DirEntity) |
    /// | `process_system::Action::"list_fds"` | [`process_system::Process`](rex_cedar_auth::process::entities::ProcessEntity) |
    ///
    /// # Linux Capabilities
    ///
    /// | Capability | Condition |
    /// |-----------|-----------|
    /// | `CAP_SYS_PTRACE` | When reading memory maps of processes owned by other users |
    /// | `CAP_DAC_READ_SEARCH` | When reading file descriptors of processes owned by other users |
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::process_mgmt::create_test_env;
    /// # use rhai::Dynamic;
    /// # let (mut scope, engine) = create_test_env();
    /// # let result = engine.eval_with_scope::<Dynamic>(
    /// #     &mut scope,
    /// #     r#"
    /// let process_manager = ProcessManager();
    ///
    /// // Path mode: list open files in a directory
    /// let lsof_options = LsofOptions()
    ///     .path("/tmp")
    ///     .build();
    /// let open_files = process_manager.list_open_files(lsof_options);
    ///
    /// // PID mode: list all open files for a specific process
    /// let pid_options = LsofOptions()
    ///     .pid(1)
    ///     .build();
    /// let open_files = process_manager.list_open_files(pid_options);
    ///
    /// for file in open_files {
    ///     print(`PID: ${file.pid}, Process: ${file.process_name}, File: ${file.file_path}, Access: ${file.access}, File Type: ${file.file_type}`)
    /// }
    /// #     "#
    /// # );
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[doc(alias = "lsof")]
    pub fn list_open_files(
        &self,
        lsof_options: LsofOptions,
    ) -> Result<Dynamic, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Kills processes based on the provided options
    ///
    /// This method kills processes according to the targeting criteria specified in the `KillOptions`.
    /// It supports killing by PID, process name, username, or command line, with proper Cedar authorization.
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource | Condition |
    /// |--------|----------|-----------|
    /// | `process_system::Action::"kill"` | [`process_system::Process`](rex_cedar_auth::process::entities::ProcessEntity) | Default |
    /// | `process_system::Action::"interrupt"` | [`process_system::Process`](rex_cedar_auth::process::entities::ProcessEntity) | When signal is `SIGHUP` |
    ///
    /// # Linux Capabilities
    ///
    /// | Capability | Condition |
    /// |-----------|-----------|
    /// | `CAP_KILL` | When target process is owned by a different user |
    ///
    /// # Arguments
    ///
    /// * `kill_options` - The options specifying which processes to kill and how
    ///
    /// # Returns
    ///
    /// Returns an array of objects representing killed processes, each containing:
    /// * `name` - The process name
    /// * `pid` - The process ID
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::process_mgmt::create_test_env;
    /// # use rhai::Dynamic;
    /// # let (mut scope, engine) = create_test_env();
    /// // This example shows how to attempt to kill processes
    /// // Note: In practice, this may fail if no matching processes are found
    /// # let result = engine.eval_with_scope::<Dynamic>(
    /// #     &mut scope,
    /// #     r#"
    /// let process_manager = ProcessManager();
    /// let kill_options = KillOptions()
    ///     .process_name("nonexistent_process")
    ///     .signal(Signal::SIGTERM)
    ///     .build();
    ///
    /// try {
    ///     let killed_processes = process_manager.kill(kill_options);
    ///     killed_processes
    /// } catch(err) {
    ///     // Expected when no matching processes found
    ///     []
    /// }
    /// #     "#
    /// # );
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[doc(alias = "pkill")]
    pub fn kill(&self, kill_options: KillOptions) -> Result<Dynamic, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Gets System V IPC information similar to `ipcs` command
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"open"` | [`file_system::Dir`](rex_cedar_auth::fs::entities::DirEntity) |
    /// | `file_system::Action::"open"` | [`file_system::File`](rex_cedar_auth::fs::entities::FileEntity) |
    /// | `file_system::Action::"read"` | [`file_system::File`](rex_cedar_auth::fs::entities::FileEntity) |
    ///
    /// NB: Opens `/proc/sysvipc/` directory, then opens and reads `shm`, `msg`, and `sem` files within it.
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::process_mgmt::create_test_env;
    /// # use rhai::Dynamic;
    /// # let (mut scope, engine) = create_test_env();
    /// # let result = engine.eval_with_scope::<Dynamic>(
    /// #     &mut scope,
    /// #     r#"
    /// let pm = ProcessManager();
    /// let ipcs_info = pm.ipcs_info();
    ///
    /// let sem = ipcs_info.semaphores;   // ipcs -s equivalent
    /// let msg = ipcs_info.queues;       // ipcs -q equivalent  
    /// let shm = ipcs_info.shared_memory; // ipcs -m equivalent
    ///
    /// print(`Semaphores: ${sem}`);
    /// print(`Message Queues: ${msg}`);
    /// print(`Shared Memory: ${shm}`);
    ///
    /// print(`${ipcs_info}`);
    /// #     "#
    /// # );
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[doc(alias = "ipcs")]
    pub fn ipcs_info(&self) -> Result<IpcsInfo, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Traces a running process to get stack trace information
    ///
    /// This method provides stack trace functionality similar to the `pstack` utility,
    /// allowing Rhai scripts to obtain detailed stack information for running processes.
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `process_system::Action::"trace"` | [`process_system::Process`](rex_cedar_auth::process::entities::ProcessEntity) |
    ///
    ///
    /// # Overloads
    ///
    /// * `trace(pid)`            - Returns a trace for the target pid in the default namespace
    /// * `trace(pid, options)`   - Returns a trace with optional namespace information.
    ///   * `ns_pid`              - The target PID namespace to enter (typically this should be the pid of whatever sandbox process hosts the target pid). When this option
    ///     is set, the `pid` parameter is the target PID as seen from within the sandbox's PID namespace instead of its global namespace PID. This
    ///     option will also enter the sandbox's mount namespace to execute the trace operation. Note that `processes()` with
    ///     `load_namespace_info` option must be run first for this operation to succeed.
    ///
    /// # Linux Capabilities
    ///
    /// | Capability | Condition |
    /// |-----------|-----------|
    /// | `CAP_SYS_PTRACE` | When target process is owned by a different user |
    /// | `CAP_SYS_ADMIN` | When using the `ns_pid` option to enter another PID namespace |
    /// | `CAP_SYS_CHROOT` | When using the `ns_pid` option to enter another PID namespace |
    /// | `CAP_DAC_OVERRIDE` | When using the `ns_pid` option to enter another PID namespace and the target process is owned by a different user |
    ///
    /// # Example
    /// ```no_run
    /// # use rex_test_utils::rhai::process_mgmt::create_test_env;
    /// # use rhai::Dynamic;
    /// # let (mut scope, engine) = create_test_env();
    /// # let result = engine.eval_with_scope::<Dynamic>(
    /// #     &mut scope,
    /// #     r#"
    /// let pm = ProcessManager();
    /// let processes = pm.processes();
    /// let target_pid = processes[0].pid;
    ///
    /// let trace = pm.trace(target_pid);
    /// print(`Process PID: ${trace.pid}`);
    ///
    /// for t in trace.threads {
    ///     print(`Thread ${t.tid}:`);
    /// }
    ///
    /// // Tracing a process in another namespace
    /// # let sandbox_pid = 12345;
    /// let pm = ProcessManager();
    /// let processes = pm.processes(ProcessOptions().load_namespace_info(true).build());
    /// let trace = pm.trace(target_pid, TraceOptions().ns_pid(sandbox_pid).build());   
    /// #     "#
    /// # );
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[doc(alias = "ptrace")]
    pub fn trace(&self, pid: i64) -> Result<TracedProcess, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Gets top-like process information with CPU usage monitoring
    ///
    /// This method provides a way to monitor specific processes over time, similar to the `top` command.
    /// It returns multiple batches of process snapshots, with each snapshot containing CPU usage information
    /// calculated between refreshes.
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `process_system::Action::"list"` | [`process_system::Process`](rex_cedar_auth::process::entities::ProcessEntity) |
    ///
    /// # Options
    /// * `pids_to_monitor`: array of pids to monitor CPU usage and other process info
    /// * `batches`: how many times to monitor the input processes
    /// * `include_threads`: whether to monitor the worker threads of the input pids as well
    /// * `delay_in_seconds`: how long between each batch to query process stats
    ///
    /// # Returns
    ///
    /// Returns a 2D array where:
    /// * Each outer element is a batch (snapshot) taken at a specific time
    /// * Each inner element is a process object with all standard fields plus:
    ///   - `recent_cpu_usage` - CPU usage percentage calculated since the last refresh
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::process_mgmt::create_test_env;
    /// # use rhai::Dynamic;
    /// # let (mut scope, engine) = create_test_env();
    /// # let result = engine.eval_with_scope::<Dynamic>(
    /// #     &mut scope,
    /// #     r#"
    /// let process_manager = ProcessManager();
    /// let processes = process_manager.processes();
    ///
    /// if len(processes) > 0 {
    ///     let first_pid = processes[0].pid;
    ///     
    ///     let top_options = MonitorProcessesCpuOptions()
    ///         .pids_to_monitor([first_pid])
    ///         .batches(2)
    ///         .include_threads(false)
    ///         .build();
    ///     
    ///     let batches = process_manager.monitor_processes_cpu(top_options);
    ///     
    ///     for batch in batches {
    ///         for process in batch {
    ///             print(`PID: ${process.pid}, Name: ${process.name}, CPU: ${process.recent_cpu_usage}%`);
    ///         }
    ///     }
    /// }
    /// #     "#
    /// # );
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[doc(alias = "top")]
    pub fn monitor_processes_cpu(
        &self,
        monitor_processes_cpu_options: MonitorProcessesCpuOptions,
    ) -> Result<Dynamic, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }
}
