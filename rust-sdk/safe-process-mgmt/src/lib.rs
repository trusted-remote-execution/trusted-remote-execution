#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]
// Allow std::fs::File because we use it to open /proc/ns/pid symlinks, which can't be opened through cap-std.
#![allow(clippy::disallowed_types)]

//! # Rust Safe Process Management
//!
//! This crate provides secure wrappers for process enumeration operations.
//! All APIs operate on system process information via [`RcProcessManager`].
//!
//! The implementations rely on the [sysinfo](https://docs.rs/sysinfo/) crate
//! for cross-platform system information retrieval.
//!
//! Since this crate has not been tested on Windows, we currently only
//! support Linux and guard this crate as such.

pub mod auth;
pub mod constants;
pub mod errors;
pub mod options;
pub mod systemctl;

use crate::auth::is_authorized;
use crate::constants::error_constants::{
    CURRENT_NAMESPACE_ACCESS_FAILED, NAMESPACE_ENTER_FAILED, NAMESPACE_RESTORE_FAILED,
    PROCESS_NOT_FOUND,
};
use crate::errors::RustSafeProcessMgmtError;
use crate::options::{NamespaceOptionsBuilder, ProcessOptions, TraceOptions};
use caps::{CapSet, Capability};
use derive_getters::Getters;
use nix::sched::{CloneFlags, setns};
use nix::sys::stat::{SFlag, stat};
use options::{KillOptions, LsofOptions, MonitorProcessesCpuOptions, NamespaceOptions};
use procfs::process::{FDTarget, MMapPath::Path as ProcfsPath, Process as ProcfsProcess};
use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::fs::constants::PROC;
use rex_cedar_auth::fs::entities::{DirEntity, FileEntity};
use rex_cedar_auth::process::actions::ProcessAction;
use rex_cedar_auth::process::entities::ProcessEntity;
use rex_logger::{debug, error, warn};
use rust_safe_io::RcDirHandle;
use rust_safe_io::execute::{ChildNamespaceOptionsBuilder, ExecuteResult};
use rust_safe_io::{
    DirConfigBuilder, RcFileHandle, TracedProcess, execute::ExecuteOptionsBuilder,
    options::OpenDirOptionsBuilder, options::OpenFileOptionsBuilder, parse_backtrace_output,
};
use rustix::fd::OwnedFd;
use rustix::process::{Pid as RustixPid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};
use serde::Serialize;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;
#[allow(clippy::disallowed_types)]
use std::fs::File;
use std::path::Path;
use std::rc::Rc;
use std::thread::sleep;
use std::time::Duration;
use sysinfo::Process as SysinfoProcess;
use sysinfo::{
    MINIMUM_CPU_UPDATE_INTERVAL, Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind,
    Users,
};

const SYSVIPC_PATH: &str = "/proc/sysvipc";
const UNKNOWN_STATE: &str = "unknown";
const NET_NS_PARENT_DIR: &str = "/run/netns"; // network namespace paths may also be located in /var/run which is a symlink to /run
const REMOVE_DEAD_PROCESSES: bool = true; // Clean up terminated processes during refresh

#[derive(Debug)]
struct ProcessHandle {
    pid: Pid,
    pidfd: Option<OwnedFd>,
    process_info: ProcessInfo,
}

impl ProcessHandle {
    #[allow(clippy::cast_possible_wrap)]
    fn new(pid: Pid, process_info: ProcessInfo) -> Self {
        let pidfd = RustixPid::from_raw(pid.as_u32() as i32)
            .and_then(|rustix_pid| pidfd_open(rustix_pid, PidfdFlags::empty()).ok());

        ProcessHandle {
            pid,
            pidfd,
            process_info,
        }
    }

    const fn process_info(&self) -> &ProcessInfo {
        &self.process_info
    }

    fn kill_process(
        &self,
        cedar_auth: &CedarAuth,
        signal: Signal,
    ) -> Result<(), RustSafeProcessMgmtError> {
        let process_entity = ProcessEntity::new(
            self.pid.to_string(),
            self.process_info.name.clone(),
            self.process_info.username.clone(),
            self.process_info.command.clone(),
        );

        let action = if signal == Signal::HUP {
            &ProcessAction::Interrupt
        } else {
            &ProcessAction::Kill
        };

        is_authorized(cedar_auth, action, &process_entity)?;
        self.send_signal(signal)
    }

    fn send_signal(&self, signal: Signal) -> Result<(), RustSafeProcessMgmtError> {
        match &self.pidfd {
            Some(fd) => {
                pidfd_send_signal(fd, signal)
                    .map_err(|e| RustSafeProcessMgmtError::Other(e.into()))?;
                Ok(())
            }
            None => Err(RustSafeProcessMgmtError::ProcessNotFound {
                reason: "Cannot send signal to process - no valid pidfd".to_string(),
                pid: self.pid.as_u32(),
            }),
        }
    }
}

/// Field names for fuser information
pub mod fuser_fields {
    pub const USER: &str = "user";
    pub const PID: &str = "pid";
    pub const ACCESS: &str = "access";
    pub const COMMAND: &str = "command";
}

/// Represents different types of file descriptors based on filesystem stat information
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
pub enum FileType {
    #[serde(rename = "DIR")]
    Dir, // Directory
    #[serde(rename = "REG")]
    Reg, // Regular file
    #[serde(rename = "LNK")]
    Link, // Symbolic link
    #[serde(rename = "SOCK")]
    Sock, // Socket
    #[serde(rename = "CHR")]
    Chr, // Character device
    #[serde(rename = "BLK")]
    Blk, // Block device
    #[serde(rename = "FIFO")]
    Fifo, // FIFO/Named pipe
    #[serde(rename = "ANON_INODE")]
    AnonInode, // Anonymous inode (eventpoll, eventfd, bpf-*, perf_event, etc.)
    #[serde(rename = "UNK")]
    Unknown, // Unknown or unsupported type
}

impl fmt::Display for FileType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let file_type = match self {
            FileType::Dir => "DIR",
            FileType::Reg => "REG",
            FileType::Link => "LNK",
            FileType::Sock => "SOCK",
            FileType::Chr => "CHR",
            FileType::Blk => "BLK",
            FileType::Fifo => "FIFO",
            FileType::AnonInode => "ANON_INODE",
            FileType::Unknown => "UNK",
        };
        write!(f, "{file_type}")
    }
}

impl FileType {
    const fn from_mode(st_mode: u32) -> Self {
        match st_mode & SFlag::S_IFMT.bits() {
            mode if mode == SFlag::S_IFDIR.bits() => FileType::Dir,
            mode if mode == SFlag::S_IFREG.bits() => FileType::Reg,
            mode if mode == SFlag::S_IFLNK.bits() => FileType::Link,
            mode if mode == SFlag::S_IFSOCK.bits() => FileType::Sock,
            mode if mode == SFlag::S_IFCHR.bits() => FileType::Chr,
            mode if mode == SFlag::S_IFBLK.bits() => FileType::Blk,
            mode if mode == SFlag::S_IFIFO.bits() => FileType::Fifo,
            _ => FileType::Unknown,
        }
    }
}

/// Represents different types of access that a process can have to a file or directory
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
pub enum AccessType {
    #[serde(rename = "File descriptor")]
    FileDescriptor,
    #[serde(rename = "Root directory")]
    RootDirectory,
    #[serde(rename = "Working directory")]
    CurrentDirectory,
    #[serde(rename = "Executable")]
    Executable,
    #[serde(rename = "Memory mapped")]
    MemoryMapped,
}

impl fmt::Display for AccessType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let access_type = match self {
            AccessType::FileDescriptor => "File descriptor",
            AccessType::RootDirectory => "Root directory",
            AccessType::CurrentDirectory => "Working directory",
            AccessType::Executable => "Executable",
            AccessType::MemoryMapped => "Memory mapped",
        };
        write!(f, "{access_type}")
    }
}

/// Information about a process using a file or directory, similar to fuser output
#[derive(Debug, Clone, PartialEq, Eq, Getters, Serialize)]
pub struct FuserInfo {
    pub user: String,
    pub pid: u32,
    pub access_types: Vec<AccessType>,
    pub command: String,
}

impl FuserInfo {
    pub const fn new(
        user: String,
        pid: u32,
        access_types: Vec<AccessType>,
        command: String,
    ) -> Self {
        Self {
            user,
            pid,
            access_types,
            command,
        }
    }

    pub fn format_access(&self) -> String {
        if self.access_types.is_empty() {
            return "No access".to_string();
        }

        let descriptions: Vec<String> = self.access_types.iter().map(ToString::to_string).collect();

        descriptions.join(", ")
    }
}

/// Information about an open file, similar to lsof output
#[derive(Debug, Clone, PartialEq, Eq, Getters, Serialize)]
pub struct OpenFileInfo {
    pub pid: u32,
    pub process_name: String,
    pub user: String,
    pub command: String,
    pub access_type: AccessType,
    pub file_type: FileType,
    pub file_path: String,
}

impl OpenFileInfo {
    pub const fn new(
        pid: u32,
        process_name: String,
        user: String,
        command: String,
        access_type: AccessType,
        file_type: FileType,
        file_path: String,
    ) -> Self {
        Self {
            pid,
            process_name,
            user,
            command,
            access_type,
            file_type,
            file_path,
        }
    }
}

/// Information about System V IPC facilities
#[derive(Debug, Clone, PartialEq, Eq, Getters, Serialize)]
pub struct IpcsInfo {
    pub shared_memory: String,
    pub semaphores: String,
    pub queues: String,
}

impl IpcsInfo {
    pub const fn new(shared_memory: String, semaphores: String, queues: String) -> Self {
        Self {
            shared_memory,
            semaphores,
            queues,
        }
    }
}

impl fmt::Display for IpcsInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Shared Memory Segments:")?;
        writeln!(f, "{}", self.shared_memory)?;
        writeln!(f, "\nMessage Queues:")?;
        writeln!(f, "{}", self.queues)?;
        writeln!(f, "\nSemaphore Arrays:")?;
        write!(f, "{}", self.semaphores)
    }
}

/// Information about a process's PID namespace.
///
/// If a process is in the default namespace, its `child_ns_pid` will be the same as its PID. Otherwise, its `child_ns_pid` will be its PID in the child namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Getters, Serialize)]
pub struct PidNamespace {
    pub namespace_id: u64,
    pub child_ns_pid: u32,
}

/// Information about a running process or thread.
///
/// When `include_threads` is enabled in [`ProcessOptions`], thread entries are also
/// returned. For thread entries the field semantics differ from process entries:
///
/// | Field      | Process entry           | Thread entry (include_threads=true)     |
/// |------------|-------------------------|-----------------------------------------|
/// | `pid`      | Process PID             | Thread ID (TID / LWP)                   |
/// | `ppid`     | Parent process PID      | Owning process PID                      |
/// | `command`  | Process command line     | Same as owning process                  |
/// | `username` | Process owner            | Same as owning process                  |
#[derive(Debug, Clone, PartialEq, Getters, Serialize)]
pub struct ProcessInfo {
    /// Process ID. For thread entries (when `include_threads=true`), this is
    /// the thread ID (TID / LWP), not the process PID.
    pub pid: u32,
    pub name: String,
    /// Parent process ID. For thread entries (when `include_threads=true`),
    /// this is the PID of the process that owns the thread.
    pub ppid: Option<u32>,
    pub uid: Option<u32>,
    pub username: String,
    pub memory_usage: u64,
    pub memory_percent: f64,
    pub state: String,
    pub command: String,
    pub recent_cpu_usage: Option<f32>,
    pub historical_cpu_usage: f32,
    pub pid_namespace: Option<PidNamespace>,
}

impl ProcessInfo {
    #[allow(clippy::similar_names)]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        pid: u32,
        name: String,
        ppid: Option<u32>,
        uid: Option<u32>,
        username: String,
        memory_usage: u64,
        memory_percent: f64,
        state: String,
        command: String,
        recent_cpu_usage: Option<f32>,
        historical_cpu_usage: f32,
        pid_namespace: Option<PidNamespace>,
    ) -> Self {
        Self {
            pid,
            name,
            ppid,
            uid,
            username,
            memory_usage,
            memory_percent,
            state,
            command,
            recent_cpu_usage,
            historical_cpu_usage,
            pid_namespace,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NamespaceType {
    Mount,
    Network,
}

impl NamespaceType {
    fn namespace_path(self, pid: u32) -> String {
        match self {
            NamespaceType::Mount => format!("/proc/{pid}/ns/mnt"),
            NamespaceType::Network => format!("/proc/{pid}/ns/net"),
        }
    }

    const fn clone_flag(self) -> CloneFlags {
        match self {
            NamespaceType::Mount => CloneFlags::CLONE_NEWNS,
            NamespaceType::Network => CloneFlags::CLONE_NEWNET,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            NamespaceType::Mount => "mount",
            NamespaceType::Network => "network",
        }
    }

    const fn action(self) -> ProcessAction {
        match self {
            NamespaceType::Mount => ProcessAction::MountNamespace,
            NamespaceType::Network => ProcessAction::NetworkNamespace,
        }
    }

    // Opens the target namespace file from /run/netns/ and saves the current namespace for restoration.
    fn prepare_entry_by_fd(
        self,
        name: &str,
        cedar_auth: &CedarAuth,
        current_process_pid: u32,
    ) -> Result<(RcFileHandle, NamespaceContext), RustSafeProcessMgmtError> {
        match self {
            NamespaceType::Network => {
                let mut context = NamespaceContext::new();

                let current_ns_path = self.namespace_path(current_process_pid);

                let original_ns_file = save_current_namespace(&current_ns_path)?;
                context.add_namespace(self.clone_flag(), original_ns_file);

                let entity = &FileEntity::new(Path::new(&format!("{NET_NS_PARENT_DIR}/{name}")))?;
                is_authorized(cedar_auth, &FilesystemAction::NetworkNamespace, entity)?;

                let target_file_handle =
                    open_fd(cedar_auth, NET_NS_PARENT_DIR, name).map_err(|e| {
                        RustSafeProcessMgmtError::NamespaceOperationError {
                            reason: format!(
                                "Failed to open {} namespace at {}",
                                self.name(),
                                NET_NS_PARENT_DIR
                            ),
                            error: e.to_string(),
                        }
                    })?;

                Ok((target_file_handle, context))
            }
            NamespaceType::Mount => Err(RustSafeProcessMgmtError::NamespaceOperationError {
                reason: "Operation not supported".to_string(),
                error: format!(
                    "Entering {} namespace by file descriptor is not supported",
                    self.name()
                ),
            }),
        }
    }

    fn prepare_entry_by_pid(
        self,
        process_entity: &ProcessEntity,
        cedar_auth: &CedarAuth,
        current_process_pid: u32,
    ) -> Result<NamespaceContext, RustSafeProcessMgmtError> {
        let action = self.action();
        is_authorized(cedar_auth, &action, process_entity)?;

        // Opening a file descriptor to `/proc/{current_process_pid}/ns/<namespace>` creates a handle that
        // represents the current namespace.
        let ns_path = self.namespace_path(current_process_pid);
        let name = self.name();

        match save_current_namespace(&ns_path) {
            Ok(file) => {
                let mut context = NamespaceContext::new();
                context.add_namespace(self.clone_flag(), file);
                Ok(context)
            }
            Err(e) => {
                warn!(
                    "Failed to open file descriptor to current process {name} namespace with pid: {current_process_pid}. Hint: try running with CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_SYS_CHROOT capabilities"
                );
                Err(e)
            }
        }
    }
}

/// Context for managing namespace entry and restoration
///
/// This struct encapsulates the common pattern of saving current namespaces
/// and tracking clone flags needed for namespace operations.
#[derive(Debug)]
struct NamespaceContext {
    clone_flags: CloneFlags,
    #[allow(clippy::disallowed_types)]
    saved_namespaces: Vec<File>,
}

impl NamespaceContext {
    const fn new() -> Self {
        Self {
            clone_flags: CloneFlags::empty(),
            saved_namespaces: Vec::new(),
        }
    }

    fn add_namespace(&mut self, flag: CloneFlags, saved_ns: File) {
        self.clone_flags |= flag;
        self.saved_namespaces.push(saved_ns);
    }

    const fn clone_flags(&self) -> CloneFlags {
        self.clone_flags
    }

    /// Restore original namespaces to ensure the calling process returns to its initial state.
    fn restore_all(&self, current_pid: u32) -> Result<(), RustSafeProcessMgmtError> {
        for fd in &self.saved_namespaces {
            setns(fd, CloneFlags::empty()).map_err(|e| {
                RustSafeProcessMgmtError::PidNamespaceOperationError {
                    reason: NAMESPACE_RESTORE_FAILED.to_string(),
                    error: e.to_string(),
                    pid: current_pid,
                }
            })?;
        }
        Ok(())
    }
}

/// Internal process management state
///
/// This struct contains the core system information, user mappings, and process handle cache.
/// It is an implementation detail and should not be used directly by consumers.
/// Use [`RcProcessManager`] instead, which provides shared ownership semantics and
/// efficient cache sharing across clones.
#[derive(Debug, Default)]
struct ProcessManager {
    system: System,
    users: Users,
    process_handles: HashMap<u32, ProcessHandle>,
    namespace_mapping: HashMap<(u64, u32), u32>,
}

/// Reads the PID namespace ID given the relevant /proc/pid directory
fn read_namespace_id(
    proc_pid_dir: &RcDirHandle,
    cedar_auth: &CedarAuth,
) -> Result<u64, RustSafeProcessMgmtError> {
    let link_target = proc_pid_dir
        .safe_open_subdir(cedar_auth, "ns")
        .and_then(|dir_handle| dir_handle.safe_read_link_target(cedar_auth, "pid"))
        .map_err(|e| RustSafeProcessMgmtError::ProcessEnumerationError {
            message: format!("Failed to read namespace info from {proc_pid_dir}/ns: {e}"),
        })?;

    // Parse "pid:[4026532752]" format
    let namespace_id = link_target
        .strip_prefix("pid:[")
        .and_then(|s| s.strip_suffix(']'))
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| RustSafeProcessMgmtError::ProcessEnumerationError {
            message: format!("Failed to parse namespace ID from: {link_target}"),
        })?;

    Ok(namespace_id)
}

/// Reads the `NSpid` values for a given process from `/proc/<PID>/status`
fn read_nspid(
    proc_pid_dir: &RcDirHandle,
    cedar_auth: &CedarAuth,
) -> Result<Vec<u32>, RustSafeProcessMgmtError> {
    let content = proc_pid_dir
        .safe_open_file(
            cedar_auth,
            "status",
            OpenFileOptionsBuilder::default().read(true).build()?,
        )
        .and_then(|status_file| status_file.safe_read(cedar_auth))
        .map_err(|e| RustSafeProcessMgmtError::ProcessEnumerationError {
            message: format!("Failed to read {proc_pid_dir}/status: {e}"),
        })?;

    // Find the NSpid line
    for line in content.lines() {
        if let Some(nspid_str) = line.strip_prefix("NSpid:") {
            let pids: Vec<u32> = nspid_str
                .split_whitespace()
                .filter_map(|s| s.parse::<u32>().ok())
                .collect();
            return Ok(pids);
        }
    }

    Err(RustSafeProcessMgmtError::ProcessEnumerationError {
        message: format!("Unable to read the NSpid entry from {proc_pid_dir}/status"),
    })
}

/// Builds `PidNamespace` information for a given process
fn build_pid_namespace(
    pid: u32,
    cedar_auth: &CedarAuth,
) -> Result<PidNamespace, RustSafeProcessMgmtError> {
    let proc_pid_dir_path = format!("{PROC}/{pid}");
    let proc_pid_dir = DirConfigBuilder::default()
        .path(proc_pid_dir_path.clone())
        .build()
        .and_then(|dir_config| {
            dir_config.safe_open(cedar_auth, OpenDirOptionsBuilder::default().build()?)
        })
        .map_err(|e| RustSafeProcessMgmtError::ProcessEnumerationError {
            message: format!("Failed to open {proc_pid_dir_path}: {e}"),
        })?;

    let namespace_id = read_namespace_id(&proc_pid_dir, cedar_auth)?;
    let nspids = read_nspid(&proc_pid_dir, cedar_auth)?;

    let child_pid =
        *nspids
            .last()
            .ok_or_else(|| RustSafeProcessMgmtError::ProcessEnumerationError {
                message: format!("The namespace pid list is empty for PID {pid}"),
            })?;

    Ok(PidNamespace {
        namespace_id,
        child_ns_pid: child_pid,
    })
}

impl ProcessManager {
    /// Ensures a specific process is in the cache. If the PID is not found,
    /// refreshes just that process from the OS and caches it. This avoids
    /// populating the entire process list without authorization.
    fn ensure_process_cached(&mut self, pid: u32) {
        if self.process_handles.contains_key(&pid) {
            return;
        }
        let sysinfo_pid = Pid::from_u32(pid);
        self.system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[sysinfo_pid]),
            REMOVE_DEAD_PROCESSES,
            ProcessRefreshKind::nothing()
                .with_memory()
                .with_cpu()
                .with_user(UpdateKind::OnlyIfNotSet)
                .with_cmd(UpdateKind::OnlyIfNotSet),
        );
        self.users = Users::new_with_refreshed_list();
        if let Some(process) = self.system.process(sysinfo_pid) {
            let process_info =
                Self::build_process_info(sysinfo_pid, process, &self.users, &self.system);
            let handle = ProcessHandle::new(sysinfo_pid, process_info);
            self.process_handles.insert(pid, handle);
        }
    }

    /// Gets a process handle by PID, lazily caching it if not already present.
    /// All access to `process_handles` for a specific PID should go through this
    /// method to ensure the cache is transparently populated.
    fn get_process_handle(&mut self, pid: u32) -> Option<&ProcessHandle> {
        self.ensure_process_cached(pid);
        self.process_handles.get(&pid)
    }

    fn refresh_process_info(&mut self) {
        self.system.refresh_memory();
        self.system.refresh_processes_specifics(
            ProcessesToUpdate::All,
            REMOVE_DEAD_PROCESSES,
            ProcessRefreshKind::nothing()
                .with_memory()
                .with_cpu()
                .with_user(UpdateKind::OnlyIfNotSet)
                .with_cmd(UpdateKind::OnlyIfNotSet),
        );
        self.users = Users::new_with_refreshed_list();
    }

    #[allow(clippy::similar_names)]
    fn build_process_info(
        pid: Pid,
        process: &SysinfoProcess,
        users: &Users,
        system: &System,
    ) -> ProcessInfo {
        let pid_u32 = pid.as_u32();
        let name = process.name().to_string_lossy().to_string();
        let ppid = process.parent().map(Pid::as_u32);
        let uid = process
            .user_id()
            .and_then(|uid| uid.to_string().parse::<u32>().ok());
        let username = Self::resolve_username(process.user_id(), users).unwrap_or_default();
        let memory_usage = process.memory();
        let memory_percent =
            Self::calculate_memory_percentage(process.memory(), system.total_memory());
        let state = format!("{:?}", process.status());
        let command = Self::format_command(process.cmd());
        let historical_cpu_usage = Self::calculate_historical_cpu_usage(process);

        ProcessInfo::new(
            pid_u32,
            name,
            ppid,
            uid,
            username,
            memory_usage,
            memory_percent,
            state,
            command,
            None,
            historical_cpu_usage,
            None,
        )
    }

    /// Resolves a user ID to a username using sysinfo
    ///
    /// # Arguments
    ///
    /// * `uid` - Optional reference to a user ID
    /// * `users` - Reference to the sysinfo Users object
    ///
    /// # Returns
    ///
    /// * `Option<String>` - The username if found, None otherwise
    fn resolve_username(uid: Option<&sysinfo::Uid>, users: &Users) -> Option<String> {
        uid.and_then(|user_id| {
            users
                .get_user_by_id(user_id)
                .map(|user| user.name().to_string())
        })
    }

    /// This removes the directory path from the first argument (the executable),
    /// while preserving all other arguments unchanged.
    fn format_command(cmd_args: &[std::ffi::OsString]) -> String {
        let full_command: String = cmd_args
            .iter()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect::<Vec<String>>()
            .join(" ");

        let mut parts: Vec<&str> = full_command.split(' ').collect();

        if let Some(first) = parts.first_mut() {
            if let Some(pos) = first.rfind('/') {
                *first = &first[pos + 1..];
            }
        }

        parts.join(" ")
    }

    /// Calculates memory usage percentage with 2 decimal places precision
    ///
    /// Uses integer arithmetic to avoid floating-point precision loss when dealing
    /// with large memory values.
    ///
    /// # Arguments
    ///
    /// * `process_memory` - Memory used by the process in bytes
    /// * `total_memory` - Total system memory in bytes
    ///
    /// # Returns
    ///
    /// A float representing the percentage of system memory used by the process,
    /// rounded to 2 decimal places. Returns 0.0 if `total_memory` is 0.
    #[allow(clippy::cast_precision_loss)]
    fn calculate_memory_percentage(process_memory: u64, total_memory: u64) -> f64 {
        if total_memory == 0 {
            return 0.0;
        }
        let scaled_percentage = (process_memory * 10000) / total_memory;
        (scaled_percentage as f64) / 100.0
    }

    /// Calculates historical CPU usage as `accumulated_cpu_time` / `run_time` * 100
    ///
    /// This calculation matches the %CPU metric from the Linux `ps` command,
    /// representing total CPU utilization since process start as a percentage.
    /// On multi-core systems, this value can exceed 100.0 - for example, a process
    /// using 4 cores fully will show approximately 400.0.
    ///
    /// # Arguments
    ///
    /// * `process` - Reference to the sysinfo Process
    ///
    /// # Returns
    ///
    /// A float representing the historical CPU usage percentage. Returns 0.0 if
    /// `run_time` is zero.
    #[allow(clippy::cast_precision_loss)]
    fn calculate_historical_cpu_usage(process: &SysinfoProcess) -> f32 {
        let run_time_secs = process.run_time();
        if run_time_secs > 0 {
            let accumulated_cpu_ms = process.accumulated_cpu_time() as f32;
            let run_time_ms = (run_time_secs * 1000) as f32;
            (accumulated_cpu_ms / run_time_ms) * 100.0
        } else {
            0.0
        }
    }

    #[allow(clippy::cast_sign_loss)]
    fn cache_process_handle(&mut self, pid: i32, name: &str, username: &str, command: &str) {
        let pid_u32 = pid.max(0) as u32;
        let process_info = ProcessInfo {
            pid: pid_u32,
            name: name.to_string(),
            ppid: None,
            uid: None,
            username: username.to_string(),
            memory_usage: 0,
            memory_percent: 0.0,
            state: UNKNOWN_STATE.to_string(),
            command: command.to_string(),
            recent_cpu_usage: None,
            historical_cpu_usage: 0.0,
            pid_namespace: None,
        };
        let process_handle = ProcessHandle::new(Pid::from_u32(pid_u32), process_info);
        self.process_handles.insert(pid_u32, process_handle);
    }

    /// gets the username mapping from uid as well as the full command
    /// using sysinfo
    #[allow(clippy::cast_sign_loss)]
    fn get_process_info(&self, proc: &ProcfsProcess, pid: i32) -> (String, String, String) {
        let sysinfo_process = self.system.process(Pid::from_u32(pid.max(0) as u32));

        sysinfo_process.map_or_else(
            || {
                // Fallback to procfs data if sysinfo doesn't have the process
                let username = proc
                    .uid()
                    .map_or_else(|_| UNKNOWN_STATE.to_string(), |uid| format!("uid_{uid}"));
                let command = proc
                    .stat()
                    .map_or_else(|_| UNKNOWN_STATE.to_string(), |stat| stat.comm);
                (username, command, UNKNOWN_STATE.to_string())
            },
            |sys_proc| {
                let username = Self::resolve_username(sys_proc.user_id(), &self.users)
                    .unwrap_or_else(|| {
                        sys_proc
                            .user_id()
                            .map_or_else(|| UNKNOWN_STATE.to_string(), |uid| uid.to_string())
                    });
                let command = Self::format_command(sys_proc.cmd());
                (
                    username,
                    command,
                    sys_proc.name().to_string_lossy().to_string(),
                )
            },
        )
    }

    /// Gets process info and caches the process handle in one operation
    ///
    /// This combines `get_process_info` and `cache_process_handle` to avoid
    /// borrow checker conflicts when both operations are needed.
    #[allow(clippy::cast_sign_loss)]
    fn get_process_info_and_cache(
        &mut self,
        proc: &ProcfsProcess,
        pid: i32,
    ) -> (String, String, String) {
        let (username, command, name) = self.get_process_info(proc, pid);
        self.cache_process_handle(pid, &name, &username, &command);
        (username, command, name)
    }
}

/// A wrapper around [`ProcessManager`]
///
/// `RcProcessManager` wraps the internal [`ProcessManager`] state in `Rc<RefCell<>>` to enable shared caching
/// and memory efficient cloning. This ensures that the `System`, `Users` instances and cached `process_handles`
/// persist across all clones.
#[derive(Debug, Clone, Default)]
pub struct RcProcessManager {
    process_manager: Rc<RefCell<ProcessManager>>,
}

impl RcProcessManager {
    pub fn new() -> Self {
        Self {
            process_manager: Rc::new(RefCell::new(ProcessManager::default())),
        }
    }

    /// Gets all processes with process information
    ///
    /// This method retrieves information about all processes on the system, applying Cedar authorization
    /// checks to ensure the caller has permission to access this information.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rust_safe_process_mgmt::RcProcessManager;
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    ///
    /// let process_manager = RcProcessManager::default();
    ///
    /// match process_manager.safe_processes(&cedar_auth) {
    ///     Ok(processes) => {
    ///         for process in processes.iter().take(5) {
    ///             println!("PID: {}, Name: {}, User: {}", process.pid, process.name, process.username);
    ///         }
    ///     },
    ///     Err(e) => println!("Error: {}", e),
    /// }
    /// ```
    pub fn safe_processes(
        &self,
        cedar_auth: &CedarAuth,
    ) -> Result<Vec<ProcessInfo>, RustSafeProcessMgmtError> {
        self.safe_processes_with_options(
            cedar_auth,
            options::ProcessOptionsBuilder::default().build()?,
        )
    }

    /// Gets all processes with process information and optional namespace caching
    ///
    /// This method retrieves information about all processes on the system, applying Cedar authorization
    /// checks to ensure the caller has permission to access this information. By default, threads are
    /// excluded (matching `ps aux` behavior). When `load_namespace_info` is enabled in the options,
    /// it also collects PID namespace information for each process.
    ///
    /// # Thread behaviour (`include_threads = true`)
    ///
    /// When threads are included the result set also contains one [`ProcessInfo`] per
    /// thread (similar to `ps -eLf`). For these thread entries:
    /// - `pid` is the thread ID (TID / LWP), **not** the process PID.
    /// - `ppid` is the PID of the process that owns the thread.
    /// - `command` and `username` match the owning process.
    ///
    /// NB: `CAP_SYS_PTRACE` capability is required to load namespace information. See <https://man7.org/linux/man-pages/man7/namespaces.7.html>
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rust_safe_process_mgmt::RcProcessManager;
    /// # use rust_safe_process_mgmt::options::ProcessOptionsBuilder;
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// # let (cedar_auth, _) = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     &get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap();
    ///
    /// let process_manager = RcProcessManager::default();
    ///
    /// // Get processes without threads (default)
    /// let options = ProcessOptionsBuilder::default()
    ///     .load_namespace_info(true)
    ///     .build()
    ///     .unwrap();
    ///
    /// match process_manager.safe_processes_with_options(&cedar_auth, options) {
    ///     Ok(processes) => {
    ///         for process in processes.iter().take(5) {
    ///             println!("PID: {}, Name: {}", process.pid, process.name);
    ///             if let Some(ns) = &process.pid_namespace {
    ///                 println!("  Namespace ID: {}, Child PID: {}", ns.namespace_id, ns.child_ns_pid);
    ///             }
    ///         }
    ///     },
    ///     Err(e) => println!("Error: {}", e),
    /// }
    ///
    /// // Get processes with threads included
    /// let options_with_threads = ProcessOptionsBuilder::default()
    ///     .include_threads(true)
    ///     .build()
    ///     .unwrap();
    ///
    /// match process_manager.safe_processes_with_options(&cedar_auth, options_with_threads) {
    ///     Ok(processes) => {
    ///         println!("Total processes and threads: {}", processes.len());
    ///     },
    ///     Err(e) => println!("Error: {}", e),
    /// }
    /// ```
    pub fn safe_processes_with_options(
        &self,
        cedar_auth: &CedarAuth,
        options: ProcessOptions,
    ) -> Result<Vec<ProcessInfo>, RustSafeProcessMgmtError> {
        let mut process_manager = self.process_manager.borrow_mut();
        process_manager.refresh_process_info();

        let mut processes: Vec<ProcessInfo> = Vec::new();
        let mut process_handles_to_cache: Vec<(Pid, ProcessInfo)> = Vec::new();
        let mut namespace_mappings_to_cache: Vec<((u64, u32), u32)> = Vec::new();
        let mut processes_skipped = false;

        for (pid, process) in process_manager.system.processes() {
            // Filter out threads if include_threads is false
            if !options.include_threads && process.tasks().is_none() {
                continue;
            }

            let mut process_info: ProcessInfo = ProcessManager::build_process_info(
                *pid,
                process,
                &process_manager.users,
                &process_manager.system,
            );

            // Load namespace info if requested
            if options.load_namespace_info {
                match build_pid_namespace(pid.as_u32(), cedar_auth) {
                    Ok(pid_namespace) => {
                        process_info.pid_namespace = Some(pid_namespace);
                        // Collect namespace mapping for later insertion
                        namespace_mappings_to_cache.push((
                            (pid_namespace.namespace_id, pid_namespace.child_ns_pid),
                            pid.as_u32(),
                        ));
                    }
                    Err(e) => {
                        // Log but don't fail
                        warn!(
                            "Failed to load namespace info for PID {}. Hint: try running with CAP_SYS_PTRACE capability and open/read permissions on `/proc`. {}",
                            pid, e
                        );
                    }
                }
            }

            let process_entity = ProcessEntity::new(
                pid.to_string(),
                process_info.name.clone(),
                process_info.username.clone(),
                process_info.command.clone(),
            );

            match is_authorized(cedar_auth, &ProcessAction::List, &process_entity) {
                Ok(()) => {
                    process_handles_to_cache.push((*pid, process_info.clone()));
                    processes.push(process_info);
                }
                Err(RustSafeProcessMgmtError::PermissionDenied {
                    principal, action, ..
                }) => {
                    // Skip this process - normal filtering behavior as the author does not have permission to get the process
                    if !processes_skipped {
                        warn!(
                            "Some processes have been skipped due to enforced cedar policy: {principal} unauthorized to perform {action}"
                        );
                        processes_skipped = true;
                    }
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }

        // Cache process handles after iteration completes
        for (pid, process_info) in process_handles_to_cache {
            let pid_fd = ProcessHandle::new(pid, process_info);
            process_manager.process_handles.insert(pid.as_u32(), pid_fd);
        }

        // Cache namespace mappings after iteration completes
        for (key, value) in namespace_mappings_to_cache {
            process_manager.namespace_mapping.insert(key, value);
        }

        Ok(processes)
    }

    /// Enters a namespace by pid or path and executes a callback
    ///
    // Limitations - https://man7.org/linux/man-pages/man2/setns.2.html
    // User and PID namespaces have fundamental Linux kernel restrictions:
    // - PID namespaces only affect child processes created after setns()
    // - User namespaces cause capability loss, preventing restoration
    /// Required capabilities:
    /// * `CAP_SYS_ADMIN`
    /// * `CAP_SYS_CHROOT`
    /// * `CAP_SYS_PTRACE`
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rust_safe_process_mgmt::RcProcessManager;
    /// # use rust_safe_process_mgmt::options::NamespaceOptionsBuilder;
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// # use std::io::Error;
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    ///
    /// # let (cedar_auth, _) = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap();
    ///
    /// let options = NamespaceOptionsBuilder::default()
    ///     .pid(1234)
    ///     .mount(true)
    ///     .net(true)
    ///     .build()
    ///     .unwrap();
    ///
    /// let process_manager = RcProcessManager::default();
    /// let result = process_manager.safe_nsenter(&options, || {
    ///     // Execute code in target namespace
    ///     Ok::<&str, Error>("Success")
    /// }, &cedar_auth)
    /// .unwrap();
    /// Ok::<(), Error>(())
    /// ```
    pub fn safe_nsenter<F, R, E>(
        &self,
        options: &NamespaceOptions,
        callback: F,
        cedar_auth: &CedarAuth,
    ) -> Result<R, RustSafeProcessMgmtError>
    where
        F: FnOnce() -> Result<R, E>,
        E: Error,
    {
        options.validate()?;

        let current_process_pid = std::process::id();
        let context = if let Some(pid) = options.pid {
            let (target_fd, context) = prepare_multi_namespace_entry_by_pid(
                pid,
                options,
                cedar_auth,
                &self.process_manager,
                current_process_pid,
            )?;

            setns(target_fd, context.clone_flags).map_err(|e| {
                warn!(
                "Failed to set namespace. Hint: try running with CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_SYS_CHROOT capabilities"
            );
                RustSafeProcessMgmtError::NamespaceOperationError {
                    reason: NAMESPACE_ENTER_FAILED.to_string(),
                    error: e.to_string(),
                }
            })?;

            context
        } else if let Some(name) = &options.net_ns_name {
            // Use file-based namespace entry
            // NamespaceOptions validation ensure that if no pid is set, net_ns_name must be
            let (target_file_handle, context) = NamespaceType::Network.prepare_entry_by_fd(
                name,
                cedar_auth,
                current_process_pid,
            )?;

            setns(&target_file_handle, context.clone_flags).map_err(|e| {
                warn!(
                "Failed to set namespace. Hint: try running with CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_SYS_CHROOT capabilities"
            );
                RustSafeProcessMgmtError::NamespaceOperationError {
                    reason: NAMESPACE_ENTER_FAILED.to_string(),
                    error: e.to_string(),
                }
            })?;

            context
        } else {
            return Err(RustSafeProcessMgmtError::ValidationError {
                reason: "Either pid or net_ns_name must be specified".to_string(),
            });
        };

        let callback_result =
            callback().map_err(|e| RustSafeProcessMgmtError::CallbackExecutionError {
                message: e.to_string(),
            });

        context.restore_all(current_process_pid)?;
        callback_result
    }

    /// Safely kills processes based on the provided targeting criteria
    ///
    /// This method kills processes according to the targeting criteria specified in the `KillOptions`.
    /// It operates on cached process data and pidfds from the most recent `safe_processes()` call,
    /// which must be called first to populate the process cache.
    /// This caching approach prevents race conditions by using the same authorized pidfds that were opened during process enumeration.
    ///
    /// # Process Targeting
    ///
    /// The method supports two mutually exclusive targeting modes:
    /// * **PID targeting** - Kill a specific process by its process ID
    /// * **Pattern targeting** - Kill processes matching name, command, and/or username criteria
    ///
    /// Required capabilities:
    /// * `CAP_KILL`
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rust_safe_process_mgmt::{RcProcessManager, options::KillOptionsBuilder};
    /// # use rustix::process::Signal;
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    ///
    /// let process_manager = RcProcessManager::default();
    ///
    /// // Kill by specific PID
    /// let kill_by_pid = KillOptionsBuilder::default()
    ///     .pid(1234)
    ///     .signal(Signal::TERM)
    ///     .build()
    ///     .unwrap();
    ///
    /// match process_manager.safe_kill(&cedar_auth, kill_by_pid) {
    ///     Ok(killed_processes) => {
    ///         for (name, pid) in killed_processes {
    ///             println!("Killed process: {} (PID: {})", name, pid);
    ///         }
    ///     },
    ///     Err(e) => println!("Failed to kill process: {}", e),
    /// }
    ///
    /// // Kill by user and process name with exact matching
    /// let kill_by_name = KillOptionsBuilder::default()
    ///     .process_name("firefox")
    ///     .username("testuser")
    ///     .exact_match(true)
    ///     .signal(Signal::TERM)
    ///     .build()
    ///     .unwrap();
    ///
    /// match process_manager.safe_kill(&cedar_auth, kill_by_name) {
    ///     Ok(killed_processes) => {
    ///         println!("Killed {} firefox processes", killed_processes.len());
    ///     },
    ///     Err(e) => println!("No firefox processes found or permission denied: {}", e),
    /// }
    /// ```
    #[allow(clippy::needless_pass_by_value)]
    pub fn safe_kill(
        &self,
        cedar_auth: &CedarAuth,
        kill_options: KillOptions,
    ) -> Result<Vec<(String, u32)>, RustSafeProcessMgmtError> {
        let mut process_manager = self.process_manager.borrow_mut();
        let mut killed_processes: Vec<(String, u32)> = Vec::new();
        let signal = kill_options.signal;

        // Kill by pid
        if let Some(pid) = kill_options.pid {
            let u32_pid =
                u32::try_from(pid).map_err(|e| RustSafeProcessMgmtError::ValidationError {
                    reason: format!("Invalid PID value {pid}: {e}"),
                })?;
            let process_handle = process_manager.get_process_handle(u32_pid).ok_or_else(|| {
                RustSafeProcessMgmtError::ProcessNotFound {
                    reason: "Process not found".to_string(),
                    pid: u32_pid,
                }
            })?;

            let name = &process_handle.process_info().name;

            process_handle.kill_process(cedar_auth, signal)?;
            killed_processes.push((name.clone(), u32_pid));
        } else {
            for handle in process_manager.process_handles.values() {
                let name = &handle.process_info().name;
                let user = &handle.process_info().username;
                let cmd = &handle.process_info().command;

                let mut matches = true;
                let mut killed_process = name.clone();

                // Check process name if specified
                if let Some(target_name) = &kill_options.process_name {
                    let name_matches = if kill_options.exact_match {
                        name == target_name
                    } else {
                        name.contains(target_name)
                    };
                    if !name_matches {
                        matches = false;
                    }
                }

                // Check username if specified
                if let Some(target_user) = &kill_options.username {
                    if user != target_user {
                        matches = false;
                    }
                }

                // Check command if specified
                if let Some(target_cmd) = &kill_options.command {
                    let cmd_matches = if kill_options.exact_match {
                        cmd == target_cmd
                    } else {
                        cmd.contains(target_cmd)
                    };
                    if !cmd_matches {
                        matches = false;
                    }
                    killed_process.clone_from(cmd);
                }

                if matches {
                    match handle.kill_process(cedar_auth, signal) {
                        Ok(()) => {
                            let pidu32 = handle.pid.as_u32();
                            killed_processes.push((killed_process, pidu32));
                            debug!("killed {}({pidu32})", name);
                        }
                        Err(e) => {
                            error!("Failed to send signal to process {}: {}", handle.pid, e);
                        }
                    }
                }
            }

            if killed_processes.is_empty() {
                return Err(RustSafeProcessMgmtError::ProcessNotFound {
                    reason: "No matching processes found".to_string(),
                    pid: 0,
                });
            }
        }

        Ok(killed_processes)
    }

    /// Gets processes that are using a file, or directory, similar to `fuser -v <path>`
    ///
    /// This method identifies processes that are using the specified path based on [`AccessType`]
    /// providing a human readable version of `fuser -v` output. Note that this follows symlinks and
    /// works with relative paths. We consider this safe as it's used for informational purposes in Dynamic
    /// Actions today.
    ///
    /// **n.b.** Note that sockets and mount points are currently not supported.
    ///
    /// # Arguments
    ///
    /// * `path` - The absolute path to check for process usage
    /// * `cedar_auth` - The Cedar authorization instance for permission checks
    ///
    /// # Returns
    ///
    /// * `Result<Vec<FuserInfo>>` - Vector of processes using the path with access flags
    ///
    /// # Errors
    ///
    /// * Returns an error if the path does not exist
    /// * Returns an error if Cedar authorization fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rust_safe_process_mgmt::RcProcessManager;
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    ///
    /// let process_manager = RcProcessManager::default();
    ///
    /// match process_manager.safe_fuser(&cedar_auth, "/tmp") {
    ///     Ok(fuser_infos) => {
    ///         for info in fuser_infos {
    ///             println!("USER: {}, PID: {}, ACCESS: {}, COMMAND: {}",
    ///                      info.user, info.pid, info.format_access(), info.command);
    ///         }
    ///     },
    ///     Err(e) => println!("Error: {}", e),
    /// }
    /// ```
    pub fn safe_fuser(
        &self,
        cedar_auth: &CedarAuth,
        path: &str,
    ) -> Result<Vec<FuserInfo>, RustSafeProcessMgmtError> {
        // Validate and canonicalize path
        let canonical_path_str = canonicalize_path(path)?;

        // Refresh system information. This is to provide accurate information about
        // each process as well as username mappings.
        let mut process_manager = self.process_manager.borrow_mut();
        process_manager.refresh_process_info();

        let mut fuser_results = Vec::new();
        let mut processes_skipped = false;

        // Ensure we can open and walk /proc
        let entity = &DirEntity::new(Path::new(PROC))?;
        is_authorized(cedar_auth, &FilesystemAction::Open, entity)?;
        is_authorized(cedar_auth, &FilesystemAction::Read, entity)?;

        for proc_result in procfs::process::all_processes().map_err(|e| {
            RustSafeProcessMgmtError::ProcessEnumerationError {
                message: format!("Failed to enumerate processes: {e}"),
            }
        })? {
            match proc_result {
                Ok(process) => {
                    let (username, command, name) =
                        process_manager.get_process_info_and_cache(&process, process.pid);

                    let process_entity = ProcessEntity::new(
                        process.pid.to_string(),
                        name.clone(),
                        username.clone(),
                        command.clone(),
                    );

                    match is_authorized(cedar_auth, &ProcessAction::ListFds, &process_entity) {
                        Ok(()) => {
                            let access_types =
                                detect_process_access_types(&process, &canonical_path_str);

                            if access_types.is_empty() {
                                continue;
                            }

                            #[allow(clippy::cast_sign_loss)]
                            let pid_u32 = process.pid.max(0) as u32;
                            let fuser_info = FuserInfo::new(
                                username.clone(),
                                pid_u32,
                                access_types,
                                command.clone(),
                            );

                            fuser_results.push(fuser_info);
                        }
                        Err(RustSafeProcessMgmtError::PermissionDenied {
                            principal,
                            action,
                            ..
                        }) => {
                            // Skip this process - normal filtering behavior as the user does not have permission to list file descriptors for this process
                            if !processes_skipped {
                                warn!(
                                    "Some processes have been skipped due to enforced cedar policy: {principal} unauthorized to perform {action}"
                                );
                                processes_skipped = true;
                            }
                        }
                        Err(e) => {
                            return Err(e);
                        }
                    }
                }
                // rather than mock procfs for the sake of erroring, we'll ignore
                // coverage here
                Err(e) => match e {
                    procfs::ProcError::NotFound(_) | procfs::ProcError::Io(_, _) => {}
                    x => {
                        error!("Can't read process due to error {x:?}");
                    }
                },
            }
        }

        Ok(fuser_results)
    }

    /// Lists open files within a directory, similar to `lsof <path>`
    ///
    /// This method returns individual entries for each file access that matches the target directory.
    /// Each file descriptor, memory mapping, and other access type gets its own separate entry.
    /// Each entry contains the exact file path that matched, not just the target directory.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rust_safe_process_mgmt::{RcProcessManager, options::LsofOptionsBuilder};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    ///
    /// let process_manager = RcProcessManager::default();
    /// let options = LsofOptionsBuilder::default()
    ///     .path("/tmp".to_string())
    ///     .build()
    ///     .unwrap();
    ///
    /// match process_manager.safe_lsof(&cedar_auth, options) {
    ///     Ok(open_files) => {
    ///         for file in open_files {
    ///             println!("PID: {}, Process: {}, File: {}, Access: {}, Command: {}, File Type: {}",
    ///                      file.pid, file.process_name, file.file_path, file.access_type.to_string(), file.command, file.file_type.to_string());
    ///         }
    ///     },
    ///     Err(e) => println!("Error: {}", e),
    /// }
    /// ```
    #[allow(clippy::needless_pass_by_value)]
    pub fn safe_lsof(
        &self,
        cedar_auth: &CedarAuth,
        options: LsofOptions,
    ) -> Result<Vec<OpenFileInfo>, RustSafeProcessMgmtError> {
        let entity = &DirEntity::new(Path::new(PROC))?;
        is_authorized(cedar_auth, &FilesystemAction::Open, entity)?;
        is_authorized(cedar_auth, &FilesystemAction::Read, entity)?;

        let unix_socket_paths = build_unix_socket_path_map();

        if let Some(pid) = options.pid {
            self.lsof_by_pid(cedar_auth, pid, &unix_socket_paths)
        } else {
            let path = options.path.unwrap_or_default();
            let target_dir = canonicalize_path(&path)?;
            self.lsof_by_path(
                cedar_auth,
                &target_dir,
                options.include_subdir,
                &unix_socket_paths,
            )
        }
    }

    fn lsof_by_pid(
        &self,
        cedar_auth: &CedarAuth,
        pid: u32,
        unix_socket_paths: &HashMap<u64, String>,
    ) -> Result<Vec<OpenFileInfo>, RustSafeProcessMgmtError> {
        let mut process_manager = self.process_manager.borrow_mut();
        process_manager.refresh_process_info();

        #[allow(clippy::cast_possible_wrap)]
        let process = ProcfsProcess::new(pid as i32).map_err(|_| {
            RustSafeProcessMgmtError::ProcessNotFound {
                reason: format!("Process with PID {pid} does not exist"),
                pid,
            }
        })?;

        let (username, command, name) =
            process_manager.get_process_info_and_cache(&process, process.pid);

        let process_entity = ProcessEntity::new(
            process.pid.to_string(),
            name.clone(),
            username.clone(),
            command.clone(),
        );
        is_authorized(cedar_auth, &ProcessAction::ListFds, &process_entity)?;

        Ok(get_all_open_files_for_process(&process, unix_socket_paths)
            .into_iter()
            .map(|(file_path, file_type, access_type)| {
                OpenFileInfo::new(
                    pid,
                    name.clone(),
                    username.clone(),
                    command.clone(),
                    access_type,
                    file_type,
                    file_path,
                )
            })
            .collect())
    }

    fn lsof_by_path(
        &self,
        cedar_auth: &CedarAuth,
        target_dir: &str,
        include_subdirectories: bool,
        unix_socket_paths: &HashMap<u64, String>,
    ) -> Result<Vec<OpenFileInfo>, RustSafeProcessMgmtError> {
        let mut process_manager = self.process_manager.borrow_mut();
        process_manager.refresh_process_info();

        let mut lsof_results = Vec::new();
        let mut processes_skipped = false;

        for proc_result in procfs::process::all_processes().map_err(|e| {
            RustSafeProcessMgmtError::ProcessEnumerationError {
                message: format!("Failed to enumerate processes: {e}"),
            }
        })? {
            match proc_result {
                Ok(process) => {
                    let (username, command, name) =
                        process_manager.get_process_info_and_cache(&process, process.pid);

                    let process_entity = ProcessEntity::new(
                        process.pid.to_string(),
                        name.clone(),
                        username.clone(),
                        command.clone(),
                    );

                    match is_authorized(cedar_auth, &ProcessAction::ListFds, &process_entity) {
                        Ok(()) => {
                            let all_files =
                                get_all_open_files_for_process(&process, unix_socket_paths);

                            #[allow(clippy::cast_sign_loss)]
                            let pid_u32 = process.pid.max(0) as u32;

                            for (file_path, file_type, access_type) in all_files {
                                if path_matches(&file_path, target_dir, include_subdirectories) {
                                    lsof_results.push(OpenFileInfo::new(
                                        pid_u32,
                                        name.clone(),
                                        username.clone(),
                                        command.clone(),
                                        access_type,
                                        file_type,
                                        file_path,
                                    ));
                                }
                            }
                        }
                        Err(RustSafeProcessMgmtError::PermissionDenied {
                            principal,
                            action,
                            ..
                        }) => {
                            if !processes_skipped {
                                warn!(
                                    "Some processes have been skipped due to enforced cedar policy: {principal} unauthorized to perform {action}"
                                );
                                processes_skipped = true;
                            }
                        }
                        Err(e) => {
                            return Err(e);
                        }
                    }
                }
                Err(e) => match e {
                    procfs::ProcError::NotFound(_) | procfs::ProcError::Io(_, _) => {}
                    x => {
                        error!("Can't read process due to error {x:?}");
                    }
                },
            }
        }

        Ok(lsof_results)
    }

    /// Gets System V IPC information similar to `ipcs` command
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rust_safe_process_mgmt::RcProcessManager;
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    ///
    /// let process_manager = RcProcessManager::default();
    ///
    /// match process_manager.safe_ipcs(&cedar_auth) {
    ///     Ok(ipcs_info) => {
    ///         println!("Shared Memory: {}", ipcs_info.shared_memory);
    ///         println!("Message Queues: {}", ipcs_info.queues);
    ///         println!("Semaphores: {}", ipcs_info.semaphores);
    ///     },
    ///     Err(e) => println!("Error: {}", e),
    /// }
    /// ```
    pub fn safe_ipcs(&self, cedar_auth: &CedarAuth) -> Result<IpcsInfo, RustSafeProcessMgmtError> {
        let shared_memory_file = open_fd(cedar_auth, SYSVIPC_PATH, "shm")?;
        let semaphores_file = open_fd(cedar_auth, SYSVIPC_PATH, "sem")?;
        let message_queues_file = open_fd(cedar_auth, SYSVIPC_PATH, "msg")?;

        let shared_memory = shared_memory_file.safe_read(cedar_auth)?;
        let semaphores = semaphores_file.safe_read(cedar_auth)?;
        let queues = message_queues_file.safe_read(cedar_auth)?;

        Ok(IpcsInfo::new(shared_memory, semaphores, queues))
    }

    /// Traces a running process to get stack trace information, similar to `pstack <pid>`
    ///
    /// This method executes the pstack utility on the specified process ID and parses the output
    /// into a structured `TracedProcess` containing thread and stack frame information.
    /// Requires appropriate permissions (`CAP_SYS_PTRACE` or process ownership).
    ///
    /// This will trace the process using its pid in the default PID namespace. If you want to trace a PID in another PID namespace,
    /// use the [`RcProcessManager::safe_trace_with_namespace`] function instead.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rust_safe_process_mgmt::RcProcessManager;
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    /// let process_manager = RcProcessManager::default();
    ///
    /// // First get processes to populate cache
    /// let processes = process_manager.safe_processes(&cedar_auth).unwrap();
    /// let target_pid = processes[0].pid;
    ///
    /// match process_manager.safe_trace(&cedar_auth, target_pid) {
    ///     Ok(traced_process) => {
    ///         if let Some(pid) = traced_process.pid() {
    ///             println!("Traced process PID: {}", pid);
    ///         }
    ///         for thread in traced_process.threads() {
    ///             println!("Thread {}: {} frames", thread.id(), thread.frames().len());
    ///         }
    ///     },
    ///     Err(e) => println!("Error: {}", e),
    /// }
    /// ```
    pub fn safe_trace(
        &self,
        cedar_auth: &CedarAuth,
        pid: u32,
    ) -> Result<TracedProcess, RustSafeProcessMgmtError> {
        self.safe_trace_impl(cedar_auth, pid, None)
    }

    /// Traces a running process to get stack trace information, similar to `pstack <pid>`, but inside the PID namespace provided in [`TraceOptions`].
    ///
    /// This method executes the pstack utility on the specified process ID and parses the output
    /// into a structured `TracedProcess` containing thread and stack frame information.
    /// Requires appropriate permissions (`CAP_SYS_PTRACE` or process ownership).
    ///
    /// This will trace the process using its pid in the child PID namespace. If you want to trace a PID in the default PID namespace,
    /// use the [`RcProcessManager::safe_trace`] function instead.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rust_safe_process_mgmt::RcProcessManager;
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    /// let process_manager = RcProcessManager::default();
    ///
    /// // First get processes to populate cache
    /// let processes = process_manager.safe_processes(&cedar_auth).unwrap();
    /// let target_pid = processes[0].pid;
    ///
    /// match process_manager.safe_trace(&cedar_auth, target_pid) {
    ///     Ok(traced_process) => {
    ///         if let Some(pid) = traced_process.pid() {
    ///             println!("Traced process PID: {}", pid);
    ///         }
    ///         for thread in traced_process.threads() {
    ///             println!("Thread {}: {} frames", thread.id(), thread.frames().len());
    ///         }
    ///     },
    ///     Err(e) => println!("Error: {}", e),
    /// }
    /// ```
    pub fn safe_trace_with_namespace(
        &self,
        cedar_auth: &CedarAuth,
        pid: u32,
        options: TraceOptions,
    ) -> Result<TracedProcess, RustSafeProcessMgmtError> {
        self.safe_trace_impl(cedar_auth, pid, Some(options))
    }

    fn safe_trace_impl(
        &self,
        cedar_auth: &CedarAuth,
        pid: u32,
        options: Option<TraceOptions>,
    ) -> Result<TracedProcess, RustSafeProcessMgmtError> {
        // If `TraceOptions.ns_pid` is provided, the first step is to map the PID in the child namespace to its PID in the default namespace.
        // This allows us to look up the process attributes in the process cache and authorize it accordingly.
        let pid_in_default_ns: u32 = options
            .as_ref()
            .map(|opts| opts.ns_pid)
            .map(|ns_pid| self.get_default_ns_pid_for_child_ns_pid(ns_pid, pid))
            .unwrap_or(Ok(pid))?;

        // Get process info from cache for authorization
        let process_info = self.get_cached_process_info(pid_in_default_ns)?;
        let process_entity = ProcessEntity::new(
            pid_in_default_ns.to_string(),
            process_info.name.clone(),
            process_info.username.clone(),
            process_info.command,
        );
        is_authorized(cedar_auth, &ProcessAction::Trace, &process_entity)?;

        // 2 reasons to stop coverage:
        // * pstack doesn't work on the Amazon build fleet for a newly spawned process, although (for now) pstack-ing PID 1 works.
        // * pstack isn't even installed on AL2023, so we couldn't run this test on that platform in any case.
        // To avoid future flaky tests, we just rely on integration tests to cover this.
        let pstack_file = open_pstack_executable(cedar_auth)?;

        let mut execute_options = ExecuteOptionsBuilder::default();
        execute_options.args(vec![(pid.to_string(), None)]);

        let mut caps: Vec<Capability> = vec![];
        // Only pass in CAP_SYS_PTRACE if the runner has it (i.e. it was present in capabilities metadata)
        // CAP_DAC_OVERRIDE can also be required if the owning user of the target process doesn't match the current user.
        for cap in [Capability::CAP_SYS_PTRACE, Capability::CAP_DAC_OVERRIDE] {
            if caps::has_cap(None, CapSet::Effective, cap)? {
                caps.push(cap);
            }
        }

        if !caps.is_empty() {
            execute_options.capabilities(caps);
        }

        let exec_result = match options.map(|opts| opts.ns_pid) {
            // Execute pstack inside the pid namespace of the ns_pid
            Some(ns_pid) => self.execute_pstack_in_pid_namespace(
                &pstack_file,
                ns_pid,
                cedar_auth,
                execute_options,
            )?,
            // Just execute pstack in the default namespace.
            None => execute_pstack(&pstack_file, &execute_options)?,
        };

        if *exec_result.exit_code() != 0 {
            if exec_result.stderr().contains("Operation not permitted") {
                return Err(RustSafeProcessMgmtError::TracePermissionError { pid });
            }
            return Err(RustSafeProcessMgmtError::TracingError {
                pid,
                reason: format!(
                    "pstack exited with code {}. Stdout: {}, Stderr: {}",
                    *exec_result.exit_code(),
                    exec_result.stdout().clone(),
                    exec_result.stderr().clone()
                ),
            });
        }

        if exec_result.stdout().trim().is_empty() {
            return Err(RustSafeProcessMgmtError::TraceEmptyError { pid });
        }

        let traced_process = parse_backtrace_output(exec_result.stdout())
            .map_err(RustSafeProcessMgmtError::SafeIoError)?;

        traced_process.map_or_else(
            || {
                Err(RustSafeProcessMgmtError::TracingError {
                    pid,
                    reason: format!(
                        "pstack returned unparseable output: {}",
                        exec_result.stdout()
                    ),
                })
            },
            |mut process| {
                // set the pid if it's not set
                if process.pid().is_none() {
                    process.set_pid(pid);
                }
                Ok(process)
            },
        )
    }

    /// Retrieve process info from cache, fetching the specific process if not cached.
    fn get_cached_process_info(&self, pid: u32) -> Result<ProcessInfo, RustSafeProcessMgmtError> {
        let mut process_manager = self.process_manager.borrow_mut();
        let process_handle = process_manager.get_process_handle(pid).ok_or_else(|| {
            RustSafeProcessMgmtError::ProcessNotFound {
                reason: "Process not found".to_string(),
                pid,
            }
        })?;

        Ok(process_handle.process_info.clone())
    }

    /// For a process in `ns_pid`'s PID namespace, map its `child_ns_pid` to its corresponding PID in the default PID namespace.
    /// Example: the first process in the PID namespace will have PID 1 as its `child_ns_pid`, but in the default PID namespace it may have for example PID 3057.
    fn get_default_ns_pid_for_child_ns_pid(
        &self,
        ns_pid: u32,
        child_ns_pid: u32,
    ) -> Result<u32, RustSafeProcessMgmtError> {
        let namespace_id = self
            .get_cached_process_info(ns_pid)?
            .pid_namespace
            .map(|ns| ns.namespace_id)
            .ok_or_else(|| RustSafeProcessMgmtError::PidNamespaceNotFound {
                reason: "Namespace information was not present in process info. Hint: use safe_processes method with the load_namespace_info option to populate namespace info first.".to_string(),
                pid: child_ns_pid,
            })?;

        let process_manager = self.process_manager.borrow();
        process_manager
            .namespace_mapping
            .get(&(namespace_id, child_ns_pid))
            .copied()
            .ok_or_else(|| RustSafeProcessMgmtError::ProcessNotFound {
                reason: format!("Process information was not present in the cache for namespace {namespace_id} and pid {child_ns_pid}. Hint: use safe_processes method with the load_namespace_info option to populate the cache first."),
                pid: child_ns_pid,
            })
    }

    fn execute_pstack_in_pid_namespace(
        &self,
        pstack_file: &RcFileHandle,
        ns_pid: u32,
        cedar_auth: &CedarAuth,
        mut execute_options: ExecuteOptionsBuilder,
    ) -> Result<ExecuteResult, RustSafeProcessMgmtError> {
        let execute_namespace_options = ChildNamespaceOptionsBuilder::default()
            .target_process(ns_pid)
            .build()
            .map_err(RustSafeProcessMgmtError::SafeIoError)?;
        execute_options.namespace(execute_namespace_options);

        // We need to enter the mount namespace because otherwise symbols are not loaded, and we end up with output like "#0  0x00007f7e671f9c01 in ?? ()"
        let opts = NamespaceOptionsBuilder::default()
            .mount(true)
            .pid(ns_pid)
            .build()?;

        self.safe_nsenter(
            &opts,
            || execute_pstack(pstack_file, &execute_options),
            cedar_auth,
        )
    }

    /// Monitors CPU usage for specific processes over time
    ///
    /// This method provides CPU monitoring for specific processes, similar to the `top` command.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rust_safe_process_mgmt::{RcProcessManager, options::MonitorProcessesCpuOptionsBuilder};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    ///
    /// let process_manager = RcProcessManager::default();
    /// let options = MonitorProcessesCpuOptionsBuilder::default()
    ///     .pids_to_monitor(vec![1234, 5678])
    ///     .batches(3)
    ///     .delay_in_seconds(1)
    ///     .build()
    ///     .unwrap();
    ///
    /// match process_manager.safe_monitor_processes_cpu(&cedar_auth, options) {
    ///     Ok(batches) => {
    ///         for (batch_num, batch) in batches.iter().enumerate() {
    ///             println!("Batch {}: {} processes", batch_num + 1, batch.len());
    ///             for process in batch {
    ///                 println!("  PID: {}, Name: {}, CPU: {:?}%",
    ///                          process.pid, process.name, process.recent_cpu_usage);
    ///             }
    ///         }
    ///     },
    ///     Err(e) => println!("Error: {}", e),
    /// }
    /// ```
    #[allow(clippy::needless_pass_by_value)]
    pub fn safe_monitor_processes_cpu(
        &self,
        cedar_auth: &CedarAuth,
        options: MonitorProcessesCpuOptions,
    ) -> Result<Vec<Vec<ProcessInfo>>, RustSafeProcessMgmtError> {
        let mut all_batches: Vec<Vec<ProcessInfo>> = Vec::new();
        let mut process_manager = self.process_manager.borrow_mut();

        let mut target_pids: Vec<Pid> = options
            .pids_to_monitor
            .iter()
            .map(|&pid| Pid::from_u32(pid))
            .collect();

        let mut refresh_kind = ProcessRefreshKind::nothing()
            .with_cpu()
            .with_memory()
            .with_user(UpdateKind::OnlyIfNotSet)
            .with_cmd(UpdateKind::OnlyIfNotSet);

        if options.include_threads {
            refresh_kind = refresh_kind.with_tasks();
        }

        // Recent CPU Usage calculation requires a small delay (200ms default) between 2 refreshes to calculate.
        // This refresh is the refresh before the first iteration's refresh
        process_manager.system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&target_pids),
            REMOVE_DEAD_PROCESSES,
            refresh_kind,
        );

        if options.include_threads {
            let thread_pids: Vec<Pid> = target_pids
                .iter()
                .filter_map(|&pid| process_manager.system.process(pid))
                .filter_map(|process| process.tasks())
                .flat_map(|tasks| tasks.iter().copied())
                .collect();

            target_pids.extend(thread_pids);
        }

        sleep(MINIMUM_CPU_UPDATE_INTERVAL);

        for batch_num in 0..options.batches {
            process_manager.system.refresh_processes_specifics(
                ProcessesToUpdate::Some(&target_pids),
                REMOVE_DEAD_PROCESSES,
                ProcessRefreshKind::nothing().with_cpu().with_memory(),
            );

            let mut batch_processes: Vec<ProcessInfo> = Vec::new();

            for &pid in &target_pids {
                if let Some(process) = process_manager.system.process(pid) {
                    match authorize_and_build_process_info(
                        cedar_auth,
                        pid,
                        process,
                        &process_manager.users,
                        &process_manager.system,
                    ) {
                        Some(Ok(mut process_info)) => {
                            let cpu_usage = calculate_cpu_usage_for_monitoring(
                                process,
                                pid.as_u32(),
                                &options,
                                &process_manager.system,
                            );
                            process_info.recent_cpu_usage = Some(cpu_usage);
                            batch_processes.push(process_info);
                        }
                        Some(Err(e)) => return Err(e),
                        None => {
                            // Warning instead of throwing an error because it's possible that a process is unauthorized
                            // and we still want to keep the data for processes that are authorized
                            warn!(
                                "Process with PID {} has been skipped due to being unauthorized to perform List action",
                                pid.as_u32()
                            );
                        }
                    }
                } else {
                    // Warning instead of throwing an error because it's possible that a process can be stopped within the monitoring window
                    // and we still want to keep the data for processes that didn't stop
                    warn!("Process with PID {} does not exist", pid.as_u32());
                }
            }

            all_batches.push(batch_processes);

            // This sleep is for the -d flag from top command. Users can specify the delay between each batch,
            // If no delay is specified, it uses the MINIMUM_CPU_UPDATE_INTERVAL by default
            // Don't sleep after the last batch
            if batch_num < options.batches - 1 {
                let sleep_duration = if options.delay_in_seconds == 0 {
                    MINIMUM_CPU_UPDATE_INTERVAL
                } else {
                    Duration::from_secs(options.delay_in_seconds)
                };
                sleep(sleep_duration);
            }
        }

        Ok(all_batches)
    }
}

fn calculate_cpu_usage_for_monitoring(
    process: &SysinfoProcess,
    pid_u32: u32,
    options: &MonitorProcessesCpuOptions,
    system: &System,
) -> f32 {
    if options.include_threads && options.pids_to_monitor.contains(&pid_u32) {
        // cpu_usage() can return >100% if process has multiple threads
        // so we have to subtract the worker threads' CPU usage so that we get
        // an accurate CPU Usage for the main thread
        let aggregate = process.cpu_usage();
        let workers_sum: f32 = process
            .tasks()
            .iter()
            .flat_map(|tasks| tasks.iter())
            .filter_map(|task_pid| system.process(*task_pid))
            .map(SysinfoProcess::cpu_usage)
            .sum();
        (aggregate - workers_sum).max(0.0)
    } else {
        process.cpu_usage()
    }
}

fn authorize_and_build_process_info(
    cedar_auth: &CedarAuth,
    pid: Pid,
    process: &SysinfoProcess,
    users: &Users,
    system: &System,
) -> Option<Result<ProcessInfo, RustSafeProcessMgmtError>> {
    // First, extract minimal info needed for authorization
    let name = process.name().to_string_lossy().to_string();
    let username = ProcessManager::resolve_username(process.user_id(), users).unwrap_or_default();
    let command = ProcessManager::format_command(process.cmd());

    // Check authorization BEFORE building full ProcessInfo
    let process_entity = ProcessEntity::new(pid.to_string(), name, username, command);

    match is_authorized(cedar_auth, &ProcessAction::List, &process_entity) {
        Ok(()) => {
            // Only build full ProcessInfo if authorized
            let process_info = ProcessManager::build_process_info(pid, process, users, system);
            Some(Ok(process_info))
        }
        Err(RustSafeProcessMgmtError::PermissionDenied { .. }) => None,
        Err(e) => Some(Err(e)),
    }
}

// Save the current namespace as an RcFileHandle before we switch to the target process namespace.
// As long as this FD remains open, we can use setns() to return to this exact namespace later, even if
// the process switches to different namespaces in the meantime.
fn save_current_namespace(full_path: &String) -> Result<File, RustSafeProcessMgmtError> {
    // We use File::open() directly because namespace files in /proc/<pid>/ns/ are special kernel symlinks
    // that don't follow normal filesystem paths, and therefore cannot be opened through RustSafeIO.
    File::open(full_path).map_err(|e| RustSafeProcessMgmtError::NamespaceOperationError {
        reason: CURRENT_NAMESPACE_ACCESS_FAILED.to_string(),
        error: e.to_string(),
    })
}

// Orchestrates entry into one or more namespaces of a target process.
// Retrieves the cached pidfd, authorizes access, saves current namespaces, and combines clone flags.
fn prepare_multi_namespace_entry_by_pid(
    pid: u32,
    options: &NamespaceOptions,
    cedar_auth: &CedarAuth,
    process_manager: &RefCell<ProcessManager>,
    current_process_pid: u32,
) -> Result<(OwnedFd, NamespaceContext), RustSafeProcessMgmtError> {
    let mut context = NamespaceContext::new();

    // Get process_info and target process file descriptor from Process Manager cache
    let (process_info, target_process_pidfd) = {
        let mut process_manager = process_manager.borrow_mut();
        match process_manager.get_process_handle(pid) {
            Some(process_handle) => {
                let process_info = process_handle.process_info().clone(); // Clone to avoid borrow issues
                match process_handle.pidfd.as_ref() {
                    Some(pidfd) => (
                        process_info,
                        pidfd.try_clone().map_err(|e| {
                            RustSafeProcessMgmtError::FileDescriptorError {
                                message: format!(
                                    "Failed to clone cached file descriptor for process {pid}: {e}"
                                ),
                            }
                        })?,
                    ),
                    None => {
                        // Cached ProcessHandle should contain a valid pidfd from last `processes` call. Missing pidfd can occur due to:
                        // - FD limit exceeded
                        // - Process terminated during pidfd_open
                        return Err(RustSafeProcessMgmtError::FileDescriptorError {
                            message: format!(
                                "Failed to retrieve cached file descriptor for process {pid}."
                            ),
                        });
                    }
                }
            }
            None => {
                return Err(RustSafeProcessMgmtError::ProcessNotFound {
                    reason: format!(
                        "{PROCESS_NOT_FOUND}. Hint: use safe_processes method to get the target process pid first."
                    ),
                    pid,
                });
            }
        }
    };

    let process_entity = ProcessEntity::new(
        pid.to_string(),
        process_info.name.clone(),
        process_info.username.clone(),
        process_info.command,
    );

    if options.mount {
        let ns_context = NamespaceType::Mount.prepare_entry_by_pid(
            &process_entity,
            cedar_auth,
            current_process_pid,
        )?;
        context.clone_flags |= ns_context.clone_flags();
        context.saved_namespaces.extend(ns_context.saved_namespaces);
    }

    if options.net {
        let ns_context = NamespaceType::Network.prepare_entry_by_pid(
            &process_entity,
            cedar_auth,
            current_process_pid,
        )?;
        context.clone_flags |= ns_context.clone_flags();
        context.saved_namespaces.extend(ns_context.saved_namespaces);
    }

    Ok((target_process_pidfd, context))
}

pub fn open_fd(
    cedar_auth: &CedarAuth,
    dir_path: &str,
    file_name: &str,
) -> Result<RcFileHandle, RustSafeProcessMgmtError> {
    let dir_handle = DirConfigBuilder::default()
        .path(dir_path.to_string())
        .build()?
        .safe_open(cedar_auth, OpenDirOptionsBuilder::default().build()?)?;

    let file_handle = dir_handle.safe_open_file(
        cedar_auth,
        file_name,
        OpenFileOptionsBuilder::default().read(true).build()?,
    )?;

    Ok(file_handle)
}

fn open_pstack_executable(
    cedar_auth: &CedarAuth,
) -> Result<RcFileHandle, RustSafeProcessMgmtError> {
    // on Amazon Linux 2, installation of gdb results in pstack being symlinked to gstack.
    // we open the symlink target directly so we don't have to follow symlinks when opening an executable.
    // AL2023 doesn't have pstack installed by default, in that case we'll assume vendors install it as part of AMI build.
    open_fd(cedar_auth, "/usr/bin", "gstack")
}

fn execute_pstack(
    pstack_file: &RcFileHandle,
    execute_options: &ExecuteOptionsBuilder,
) -> Result<ExecuteResult, RustSafeProcessMgmtError> {
    pstack_file
        .safe_execute_util(
            &execute_options
                .build()
                .map_err(RustSafeProcessMgmtError::SafeIoError)?,
        )
        .map_err(RustSafeProcessMgmtError::SafeIoError)
}

fn path_matches(check_path: &str, target_path: &str, include_subdirectories: bool) -> bool {
    let check = Path::new(check_path);
    let target = Path::new(target_path);
    if include_subdirectories {
        check.starts_with(target)
    } else {
        check == target
    }
}

fn check_file_descriptors(
    proc: &ProcfsProcess,
    canonical_path_str: &str,
    access_types: &mut Vec<AccessType>,
) {
    if let Ok(fds) = proc.fd() {
        for fd_info in fds.flatten() {
            if let FDTarget::Path(fd_path) = &fd_info.target {
                if path_matches(&fd_path.to_string_lossy(), canonical_path_str, false) {
                    access_types.push(AccessType::FileDescriptor);
                    break; // Once we find one file descriptor, we can stop checking
                }
            }
        }
    }
}

fn check_memory_mappings(
    proc: &ProcfsProcess,
    canonical_path_str: &str,
    access_types: &mut Vec<AccessType>,
) {
    match proc.smaps() {
        Ok(maps) => {
            for map in maps {
                if let ProcfsPath(map_path) = &map.pathname {
                    let map_path_str = map_path.to_string_lossy();

                    if path_matches(&map_path_str, canonical_path_str, false) {
                        // For memory-mapped files, we consider any type of mapping as valid access
                        // This ensures we catch both read-only and read-write mappings
                        access_types.push(AccessType::MemoryMapped);
                        break;
                    }
                }
            }
        }
        Err(e) => {
            if e.to_string().to_lowercase().contains("permission denied") {
                warn!(
                    "Process {} failed to read smaps: {} - Hint: try running with CAP_SYS_PTRACE capability",
                    proc.pid, e
                );
            } else {
                warn!("Process {} failed to read smaps: {}", proc.pid, e);
            }
        }
    }
}

fn canonicalize_path(path: &str) -> Result<String, RustSafeProcessMgmtError> {
    let target_path = Path::new(path);

    // Canonicalize the path to resolve symlinks/relative paths and get the real path
    let canonical_path =
        target_path
            .canonicalize()
            .map_err(|e| RustSafeProcessMgmtError::ValidationError {
                reason: format!("Failed to canonicalize path {path}: {e}"),
            })?;

    if target_path.is_relative() {
        warn!(
            "path: '{path}' is a relative path. using '{}' for lookup",
            canonical_path.display()
        );
    }

    if target_path.is_symlink() {
        warn!(
            "path: '{path}' is a symlink. using '{}' for lookup",
            canonical_path.display()
        );
    }

    Ok(canonical_path.to_string_lossy().to_string())
}

fn check_simple_path<P: AsRef<Path>>(
    path_result: Result<P, procfs::ProcError>,
    canonical_path_str: &str,
    access_type: AccessType,
    access_types: &mut Vec<AccessType>,
) {
    if let Ok(path) = path_result {
        if path_matches(&path.as_ref().to_string_lossy(), canonical_path_str, false) {
            access_types.push(access_type);
        }
    }
}

fn detect_process_access_types(proc: &ProcfsProcess, canonical_path_str: &str) -> Vec<AccessType> {
    let mut access_types = Vec::new();

    // Handle special cases (fd and memory mappings) separately
    check_file_descriptors(proc, canonical_path_str, &mut access_types);
    check_memory_mappings(proc, canonical_path_str, &mut access_types);

    check_simple_path(
        proc.cwd(),
        canonical_path_str,
        AccessType::CurrentDirectory,
        &mut access_types,
    );
    check_simple_path(
        proc.exe(),
        canonical_path_str,
        AccessType::Executable,
        &mut access_types,
    );
    check_simple_path(
        proc.root(),
        canonical_path_str,
        AccessType::RootDirectory,
        &mut access_types,
    );

    access_types
}

/// Builds a lookup table mapping Unix domain socket inodes to their filesystem paths.
fn build_unix_socket_path_map() -> HashMap<u64, String> {
    let mut map = HashMap::new();
    if let Ok(entries) = procfs::net::unix() {
        for entry in entries {
            if let Some(path) = entry.path {
                map.insert(entry.inode, path.to_string_lossy().to_string());
            }
        }
    }
    map
}

// Returns all open files for a given process.
fn get_all_open_files_for_process(
    process: &ProcfsProcess,
    unix_socket_paths: &HashMap<u64, String>,
) -> Vec<(String, FileType, AccessType)> {
    let mut open_files = Vec::new();

    if let Ok(cwd) = process.cwd() {
        open_files.push((
            cwd.to_string_lossy().to_string(),
            FileType::Dir,
            AccessType::CurrentDirectory,
        ));
    }
    if let Ok(root) = process.root() {
        open_files.push((
            root.to_string_lossy().to_string(),
            FileType::Dir,
            AccessType::RootDirectory,
        ));
    }
    if let Ok(exe) = process.exe() {
        open_files.push((
            exe.to_string_lossy().to_string(),
            FileType::Reg,
            AccessType::Executable,
        ));
    }

    scan_memory_mappings(process, &mut open_files);
    scan_open_file_descriptors(process, unix_socket_paths, &mut open_files);

    open_files
}

fn scan_open_file_descriptors(
    process: &ProcfsProcess,
    unix_socket_paths: &HashMap<u64, String>,
    open_files: &mut Vec<(String, FileType, AccessType)>,
) {
    if let Ok(fds) = process.fd() {
        for fd_info in fds.flatten() {
            let (fd_path_str, file_type) = match &fd_info.target {
                FDTarget::Path(fd_path) => {
                    // File descriptor numbers are per-process: fd_info.fd is a number (e.g., 3) from the target process's
                    // fd table, but that same number in our process refers to a completely different file. Using fstat()
                    // on fd_info.fd would incorrectly stat our own fd 3 instead of the target process's fd 3.
                    //
                    // We use stat() on `/proc/<pid>/fd/<fd>` symlink, which the kernel resolves to the target process's
                    // actual file, reporting the correct file_type
                    let proc_fd_path = format!("/proc/{}/fd/{}", process.pid, fd_info.fd);
                    let file_type = stat(proc_fd_path.as_str())
                        .map(|stat_result| FileType::from_mode(stat_result.st_mode))
                        .unwrap_or(FileType::Unknown);
                    (fd_path.to_string_lossy().to_string(), file_type)
                }
                FDTarget::Socket(inode) => unix_socket_paths.get(inode).map_or_else(
                    || (format!("socket:[{inode}]"), FileType::Sock),
                    |path| (path.clone(), FileType::Sock),
                ),
                FDTarget::Net(inode) => (format!("net:[{inode}]"), FileType::Sock),
                FDTarget::Pipe(inode) => (format!("pipe:[{inode}]"), FileType::Fifo),
                FDTarget::AnonInode(name) => (format!("anon_inode:{name}"), FileType::AnonInode),
                FDTarget::MemFD(name) => (format!("/memfd:{name}"), FileType::Reg),
                FDTarget::Other(typ, inode) => (format!("{typ}:[{inode}]"), FileType::Unknown),
            };

            open_files.push((fd_path_str, file_type, AccessType::FileDescriptor));
        }
    }
}

fn scan_memory_mappings(
    process: &ProcfsProcess,
    open_files: &mut Vec<(String, FileType, AccessType)>,
) {
    // Get exe's (dev, inode) to skip — already reported as Executable.
    // Matches real lsof's process_proc_map() which skips maps matching the txt entry.
    let exe_key: Option<(i32, i32, u64)> = process.maps().ok().and_then(|maps| {
        let exe_path = process.exe().ok()?;
        maps.0
            .iter()
            .find(|m| matches!(&m.pathname, ProcfsPath(p) if p == &exe_path))
            .map(|m| (m.dev.0, m.dev.1, m.inode))
    });

    match process.maps() {
        Ok(maps) => {
            // Deduplicate by (dev, inode) — same approach as real lsof's saved_map.
            // /proc/<pid>/maps reports one entry per mapping region; a single file can
            // have multiple regions (text, rodata, data). We collapse them into one.
            let mut seen: HashSet<(i32, i32, u64)> = HashSet::new();
            for map in &maps.0 {
                if let ProcfsPath(map_path) = &map.pathname {
                    if map.dev == (0, 0) && map.inode == 0 {
                        continue;
                    }
                    let key = (map.dev.0, map.dev.1, map.inode);
                    if exe_key == Some(key) {
                        continue;
                    }
                    if !seen.insert(key) {
                        continue;
                    }
                    open_files.push((
                        map_path.to_string_lossy().to_string(),
                        FileType::Reg,
                        AccessType::MemoryMapped,
                    ));
                }
            }
        }
        Err(e) => {
            if e.to_string().to_lowercase().contains("permission denied") {
                warn!(
                    "Process {} failed to read maps: {} - Hint: try running with CAP_SYS_PTRACE capability",
                    process.pid, e
                );
            } else {
                warn!("Process {} failed to read maps: {}", process.pid, e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use rex_cedar_auth::test_utils::{
        DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_default_test_rex_policy,
        get_default_test_rex_schema, get_test_rex_principal,
    };
    use rex_test_utils::assertions::assert_error_contains;
    use rstest::rstest;
    use std::ffi::OsString;

    /// Given: Command line arguments with different path formats
    /// When: Formatting them with format_command
    /// Then: Should simplify the executable path while preserving arguments
    #[rstest]
    #[case(
        vec!["/usr/bin/perl", "-w", "/apollo/sbin/update-rpm", "--sleep", "84600"],
        "perl -w /apollo/sbin/update-rpm --sleep 84600"
    )]
    #[case(
        vec!["perl", "-w", "/path/to/script"],
        "perl -w /path/to/script"
    )]
    #[case(
        vec!["/usr/bin/postgres", "-D", "/rdsdbdata/db", "-f", "/dev/null"],
        "postgres -D /rdsdbdata/db -f /dev/null"
    )]
    #[case(
        vec!["postgres", "-D", "/rdsdbdata/db", "-f", "/dev/null"],
        "postgres -D /rdsdbdata/db -f /dev/null"
    )]
    #[case(vec!["perl"], "perl")]
    #[case(vec![], "")]
    fn test_format_command(#[case] input: Vec<&str>, #[case] expected: &str) {
        let cmd: Vec<OsString> = input.iter().map(|s| OsString::from(s)).collect();
        let result = ProcessManager::format_command(&cmd);
        assert_eq!(result, expected);
    }

    /// Given: Various process memory usage scenarios
    /// When: Calculating memory percentage using calculate_memory_percentage
    /// Then: Should return correctly rounded percentages with 2 decimal places
    #[rstest]
    #[case(5000, 0, 0.0)]
    #[case(5000, 10000, 50.0)]
    fn test_calculate_memory_percentage(
        #[case] process_memory: u64,
        #[case] total_memory: u64,
        #[case] expected: f64,
    ) {
        let result = ProcessManager::calculate_memory_percentage(process_memory, total_memory);
        assert_eq!(result, expected);
    }

    /// Given: A FuserInfo instance access types
    /// When: Calling format_access
    /// Then: Should return expected access type
    #[rstest]
    #[case(vec![], "No access")]
    #[case(vec![AccessType::FileDescriptor], "File descriptor")]
    #[case(vec![AccessType::RootDirectory], "Root directory")]
    #[case(vec![AccessType::CurrentDirectory], "Working directory")]
    #[case(vec![AccessType::Executable], "Executable")]
    #[case(vec![AccessType::MemoryMapped], "Memory mapped")]
    #[case(vec![AccessType::FileDescriptor, AccessType::MemoryMapped], "File descriptor, Memory mapped")]
    fn test_format_access_empty(
        #[case] access_types: Vec<AccessType>,
        #[case] expected_str: String,
    ) {
        let fuser_info = FuserInfo::new(
            "testuser".to_string(),
            12345,
            access_types,
            "test-command".to_string(),
        );

        let result = fuser_info.format_access();
        assert_eq!(result, expected_str);
    }

    /// Given: FuserInfo instances with various access type combinations
    /// When: Calling format_access
    /// Then: Should return correct string representation for each combination
    #[rstest]
    // All access types in a specific order
    #[case(
        vec![
            AccessType::FileDescriptor,
            AccessType::RootDirectory,
            AccessType::CurrentDirectory,
            AccessType::Executable,
            AccessType::MemoryMapped,
        ],
        "File descriptor, Root directory, Working directory, Executable, Memory mapped"
    )]
    // Various combinations
    #[case(
        vec![AccessType::FileDescriptor, AccessType::Executable],
        "File descriptor, Executable"
    )]
    #[case(
        vec![AccessType::RootDirectory, AccessType::MemoryMapped],
        "Root directory, Memory mapped"
    )]
    #[case(
        vec![
            AccessType::CurrentDirectory,
            AccessType::FileDescriptor,
            AccessType::MemoryMapped,
        ],
        "Working directory, File descriptor, Memory mapped"
    )]
    // Different orders of the same access types
    #[case(
        vec![
            AccessType::FileDescriptor,
            AccessType::Executable,
            AccessType::MemoryMapped,
        ],
        "File descriptor, Executable, Memory mapped"
    )]
    #[case(
        vec![
            AccessType::MemoryMapped,
            AccessType::FileDescriptor,
            AccessType::Executable,
        ],
        "Memory mapped, File descriptor, Executable"
    )]
    #[case(
        vec![
            AccessType::Executable,
            AccessType::MemoryMapped,
            AccessType::FileDescriptor,
        ],
        "Executable, Memory mapped, File descriptor"
    )]
    fn test_format_access_comprehensive(
        #[case] access_types: Vec<AccessType>,
        #[case] expected_str: String,
    ) {
        let fuser_info = FuserInfo::new(
            "testuser".to_string(),
            12345,
            access_types,
            "test-command".to_string(),
        );

        let result = fuser_info.format_access();
        assert_eq!(result, expected_str);
    }

    /// Given: Various path string pairs for both exact and subdirectory matching
    /// When: Calling path_matches with different include_subdirectories settings
    /// Then: Should return correct results for exact matches and subdirectory contains
    #[rstest]
    // Exact matching (include_subdirectories = false)
    #[case("/usr/bin/bash", "/usr/bin/bash", false, true)]
    #[case("/usr/bin/bash", "/usr/bin/sh", false, false)]
    #[case("/tmp", "/tmp/", false, true)]
    // Subdirectory matching (include_subdirectories = true)
    #[case("/tmp/file.txt", "/tmp", true, true)]
    #[case("/tmp/subdir/file.txt", "/tmp", true, true)]
    #[case("/usr/lib", "/tmp", true, false)]
    #[case("/tmp", "/tmp/file.txt", true, false)]
    // Root directory matching
    #[case("/tmp/file.txt", "/", true, true)]
    #[case("/", "/", false, true)]
    fn test_path_matches(
        #[case] path1: &str,
        #[case] path2: &str,
        #[case] include_subdirs: bool,
        #[case] expected: bool,
    ) {
        let result = path_matches(path1, path2, include_subdirs);
        assert_eq!(
            result, expected,
            "path_matches({:?}, {:?}, {}) should be {}",
            path1, path2, include_subdirs, expected
        );
    }

    /// Given: A ProcessHandle created with a non-existent PID that causes pidfd creation to fail
    /// When: Calling send_signal on the ProcessHandle with no valid pidfd
    /// Then: Should return error from the None branch
    #[test]
    fn test_kill_process_no_pidfd() -> Result<()> {
        let process_info = ProcessInfo::new(
            999999,
            "test".to_string(),
            None,
            None,
            "test".to_string(),
            0,
            0.0,
            UNKNOWN_STATE.to_string(),
            "test".to_string(),
            None,
            0.0,
            None,
        );

        let bad_process_handle = ProcessHandle::new(Pid::from(999999), process_info);
        let result = bad_process_handle.send_signal(Signal::TERM);

        assert!(result.is_err());
        let expected_err = "Cannot send signal to process - no valid pidfd";
        assert_error_contains(result, expected_err);

        Ok(())
    }

    /// Given: All AccessType variants
    /// When: Converting to string using Display trait
    /// Then: Should return correct string representations
    #[rstest]
    #[case(AccessType::FileDescriptor, "File descriptor")]
    #[case(AccessType::RootDirectory, "Root directory")]
    #[case(AccessType::CurrentDirectory, "Working directory")]
    #[case(AccessType::Executable, "Executable")]
    #[case(AccessType::MemoryMapped, "Memory mapped")]
    fn test_access_type_display(#[case] access_type: AccessType, #[case] expected: &str) {
        let result = access_type.to_string();
        assert_eq!(result, expected);
    }

    /// Given: All FileType variants
    /// When: Calling description on each
    /// Then: Should return correct string representations
    #[rstest]
    #[case(FileType::Dir, "DIR")]
    #[case(FileType::Reg, "REG")]
    #[case(FileType::Link, "LNK")]
    #[case(FileType::Sock, "SOCK")]
    #[case(FileType::Chr, "CHR")]
    #[case(FileType::Blk, "BLK")]
    #[case(FileType::Fifo, "FIFO")]
    #[case(FileType::AnonInode, "ANON_INODE")]
    #[case(FileType::Unknown, "UNK")]
    fn test_file_type_description(#[case] file_type: FileType, #[case] expected: &str) {
        let result = file_type.to_string();
        assert_eq!(result, expected);
    }

    /// Given: Various st_mode values with different file type flags
    /// When: Calling FileType::from_mode
    /// Then: Should return correct FileType based on mode flags
    #[rstest]
    #[case(0o100644, FileType::Reg)] // S_IFREG | 0644 (regular file)
    #[case(0o040755, FileType::Dir)] // S_IFDIR | 0755 (directory)
    #[case(0o120777, FileType::Link)] // S_IFLNK | 0777 (symbolic link)
    #[case(0o140666, FileType::Sock)] // S_IFSOCK | 0666 (socket)
    #[case(0o020666, FileType::Chr)] // S_IFCHR | 0666 (character device)
    #[case(0o060666, FileType::Blk)] // S_IFBLK | 0666 (block device)
    #[case(0o010666, FileType::Fifo)] // S_IFIFO | 0666 (FIFO/named pipe)
    #[case(0o000644, FileType::Unknown)] // No file type bits set
    #[case(0o170000, FileType::Unknown)] // Invalid/unknown file type bits
    fn test_file_type_from_mode(#[case] st_mode: u32, #[case] expected: FileType) {
        let result = FileType::from_mode(st_mode);
        assert_eq!(
            result, expected,
            "st_mode: 0o{:o} should map to {:?}",
            st_mode, expected
        );
    }

    /// Given: An RcProcessManager with populated process cache
    /// When: Cloning the RcProcessManager
    /// Then: The cloned RcProcessManager should share the same underlying state via Rc
    #[test]
    fn test_rc_process_manager_clone_shares_state() -> Result<()> {
        let (cedar_auth, _) = CedarAuth::new(
            &get_default_test_rex_policy(),
            get_default_test_rex_schema(),
            "[]",
        )?;

        let original_manager = RcProcessManager::default();
        let processes = original_manager.safe_processes(&cedar_auth)?;

        assert!(!processes.is_empty(), "Should have at least one process");

        let cloned_manager = original_manager.clone();

        // Verify both managers share the same Rc pointer
        assert!(
            Rc::ptr_eq(
                &original_manager.process_manager,
                &cloned_manager.process_manager
            ),
            "Cloned manager should share the same Rc pointer as original"
        );

        // Verify cloned manager can access the same cache
        let cloned_processes = cloned_manager.safe_processes(&cedar_auth)?;
        assert!(
            !cloned_processes.is_empty(),
            "Cloned manager should have access to processes"
        );

        Ok(())
    }

    /// Given: A process ID that doesn't exist in the cache
    /// When: Calling safe_trace
    /// Then: Should return ProcessNotFound error
    #[test]
    fn test_safe_trace_process_not_found() -> Result<()> {
        // This test works even on AL2023 (where pstack isn't installed) because we never get to the pstack call -
        // as soon as the process isn't found in the process list, we return an ProcessNotFound error.

        let (cedar_auth, _) = CedarAuth::new(
            &get_default_test_rex_policy(),
            get_default_test_rex_schema(),
            "[]",
        )?;

        let process_manager = RcProcessManager::default();
        let non_existent_pid = 999999;

        let result = process_manager.safe_trace(&cedar_auth, non_existent_pid);

        assert!(result.is_err());
        match result.unwrap_err() {
            RustSafeProcessMgmtError::ProcessNotFound { pid, .. } => {
                assert_eq!(pid, non_existent_pid);
            }
            other => panic!("Expected ProcessNotFound error, got: {:?}", other),
        }

        Ok(())
    }

    /// Given: A TracePermissionError with a specific PID
    /// When: Converting the error to a string
    /// Then: Should produce the expected error message
    #[test]
    fn test_trace_permission_error_message() {
        let pid = 12345;
        let error = RustSafeProcessMgmtError::TracePermissionError { pid };
        assert_eq!(
            error.to_string(),
            "Unable to trace process 12345. Likely you need to set the CAP_SYS_PTRACE linux capability."
        );
    }

    /// Given: A Cedar policy that denies Trace action
    /// When: Calling safe_trace
    /// Then: Should return PermissionDenied error
    #[test]
    fn test_safe_trace_permission_denied() -> Result<()> {
        let principal = get_test_rex_principal();
        // Create a restrictive policy that denies trace operations
        let deny_trace_policy = format!(
            r#"
            permit(
                principal == User::"{principal}",
                action,
                resource
            );
            forbid(
                principal == User::"{principal}", 
                action == process_system::Action::"trace",
                resource
            );
        "#
        );

        let (cedar_auth, _) =
            CedarAuth::new(&deny_trace_policy, get_default_test_rex_schema(), "[]")?;

        let process_manager = RcProcessManager::default();

        // First populate the cache (this should work with List permission)
        let processes = process_manager.safe_processes(&cedar_auth)?;
        assert!(!processes.is_empty(), "Should have at least one process");

        let target_pid = processes[0].pid;

        // This should fail due to permission denied for Trace action
        let result = process_manager.safe_trace(&cedar_auth, target_pid);

        assert!(result.is_err());
        match result.unwrap_err() {
            RustSafeProcessMgmtError::PermissionDenied { action, .. } => {
                assert_eq!(action, "process_system::Action::\"trace\"");
            }
            other => panic!("Expected PermissionDenied error, got: {:?}", other),
        }

        Ok(())
    }

    /// Given: A non-existent PID
    /// When: Calling build_pid_namespace
    /// Then: Should return ProcessEnumerationError propagated from read_namespace_id
    #[test]
    fn test_build_pid_namespace_nonexistent_pid() -> Result<()> {
        let nonexistent_pid = 999999;
        let result = build_pid_namespace(nonexistent_pid, &DEFAULT_TEST_CEDAR_AUTH);

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(matches!(
            error,
            RustSafeProcessMgmtError::ProcessEnumerationError { .. }
        ));

        Ok(())
    }

    /// Given: A Cedar policy that denies reading /proc/pid/status
    /// When: Calling read_nspid
    /// Then: Should return ProcessEnumerationError for permission denied
    #[test]
    fn test_read_nspid_permission_denied() -> Result<()> {
        let principal = get_test_rex_principal();
        let current_pid = std::process::id();
        let deny_read_policy = format!(
            r#"permit(
                principal == User::"{principal}",
                action in [{}, {}],
                resource
            );
            
            forbid(
                principal == User::"{principal}",
                action == {},
                resource == file_system::File::"/proc/{}/status"
            );"#,
            FilesystemAction::Open,
            FilesystemAction::Read,
            FilesystemAction::Read,
            current_pid.to_string()
        );

        let deny_cedar_auth = TestCedarAuthBuilder::default()
            .policy(deny_read_policy)
            .build()
            .unwrap()
            .create();

        let result = build_pid_namespace(current_pid, &deny_cedar_auth);

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(matches!(
            error,
            RustSafeProcessMgmtError::ProcessEnumerationError { .. }
        ));

        let error_msg = error.to_string();
        assert!(
            error_msg.contains(&format!("/proc/{}/status", current_pid)),
            "Expected error to contain /proc/{}/status, actual error: {}",
            current_pid,
            error_msg
        );

        Ok(())
    }
}
