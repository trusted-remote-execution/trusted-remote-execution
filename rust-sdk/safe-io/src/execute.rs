#![cfg(target_os = "linux")]

use crate::RcFileHandle;
use crate::auth::is_authorized_with_context_entities;
use crate::constants::error_constants::{NO_GROUP_MAPPING_ERR, NO_USER_MAPPING_ERR};
use crate::constants::{EXECUTE_API_CHILD_MONITORING_INTERNVAL_MSEC, SIGTERM_TIMEOUT_SECONDS};
use crate::errors::RustSafeIoError;
use caps::{CapSet, Capability};
use rex_cedar_auth::cedar_auth::{CedarAuth, CedarRexEntity, Entity};
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::fs::entities::FileEntity;
use rex_cedar_auth::fs::entities::{ArgumentsEntity, EnvironmentEntity};
use rex_logger::{RUNNER_AND_SYSLOG_TARGET, error};
use rust_sdk_common_utils::signal_handling::SigtermHandler;

use derive_builder::Builder;
use derive_getters::Getters;
use nix::sched::{CloneFlags, setns};
use nix::sys::signal::{Signal, kill};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{
    ForkResult, Gid, Pid, Uid, dup, dup2, fexecve, fork, getgid, getuid, pipe, setgid, setgroups,
    setuid,
};
use rustix::process::{Pid as RustixPid, PidfdFlags, pidfd_open};
use serde::Serialize;
use serde_json::{Map, Value, json};
use std::collections::HashSet;
use std::ffi::CString;
use std::fmt::Display;
#[allow(clippy::disallowed_types)]
use std::fs::File;
use std::io::Read;
use std::mem::forget;
use std::os::fd::{OwnedFd, RawFd};
use std::os::unix::io::FromRawFd;
use std::process::{exit, id};
use std::thread;
use std::time::Duration;
use sysinfo::{Groups, Users};

/// Exit code for child processes
const EXIT_FAILURE: i32 = 1;

/// Standard file descriptors
const STDOUT_FILENO: RawFd = 1;
const STDERR_FILENO: RawFd = 2;

/// Represents the result of command execution containing output and exit information
///
/// # Fields
///
/// * `exit_code` - Exit code returned by the executed command
/// * `stdout` - Standard output captured from the command
/// * `stderr` - Standard error output captured from the command
#[derive(Debug, Clone, Getters, Serialize)]
pub struct ExecuteResult {
    exit_code: i32,
    stdout: String,
    stderr: String,
}

/// Namespace configuration for child process execution
/// Currently supports PID namespace, designed for future expansion
///
/// # Examples
///
/// ```no_run
/// # use rust_safe_io::execute::ChildNamespaceOptionsBuilder;
/// let container_pid: u32 = 1234;
/// let child_namespace_options = ChildNamespaceOptionsBuilder::default()
///     .target_process(container_pid)
///     .build()
///     .unwrap();
/// ```
#[derive(Builder, Debug, Clone, Copy)]
#[builder(derive(Debug), build_fn(error = "RustSafeIoError"))]
pub struct ChildNamespaceOptions {
    pub target_process: u32,
}

/// Configuration options for command execution
///
/// This struct specifies how a safe execute should be executed, including
/// arguments, environment variables, capabilities, and user id using the builder pattern.
///
/// # Examples
///
/// ```no_run
/// use rust_safe_io::execute::{ExecuteOptionsBuilder};
/// use caps::Capability;
///
/// // Arguments as ordered key-value pairs
/// // Use Some(value) for arguments with values, None for flags
/// let args = vec![
///     ("-A".to_string(), Some("INPUT".to_string())),
///     ("-p".to_string(), Some("tcp".to_string())),
///     ("--dport".to_string(), Some("8000".to_string())),
///     ("-j".to_string(), Some("ACCEPT".to_string())),
///     ("--verbose".to_string(), None),
///     ("/home/user".to_string(), None),
/// ];
///
/// let env = vec![
///     ("PATH".to_string(), "/usr/bin:/bin".to_string()),
/// ];
///
/// let options = ExecuteOptionsBuilder::default()
///     .args(args)
///     .env(env)
///     .capabilities(vec![Capability::CAP_NET_ADMIN])
///     .user("nginx")
///     .build()
///     .unwrap();
/// ```
#[derive(Builder, Debug, Clone)]
#[builder(
    derive(Debug),
    build_fn(error = "RustSafeIoError", validate = "Self::validate")
)]
pub struct ExecuteOptions {
    #[builder(default)]
    pub args: Vec<(String, Option<String>)>,
    #[builder(default)]
    pub env: Vec<(String, String)>,
    #[builder(default)]
    pub capabilities: Vec<Capability>,
    #[builder(setter(into, strip_option), default)]
    pub user: Option<String>,
    #[builder(setter(into, strip_option), default)]
    pub group: Option<String>,
    #[builder(setter(into, strip_option), default)]
    pub namespace: Option<ChildNamespaceOptions>,
}

impl ExecuteOptionsBuilder {
    fn validate(&self) -> Result<(), RustSafeIoError> {
        if let Some(args) = &self.args {
            Self::validate_args(args)?;
        }

        if let Some(env) = &self.env {
            Self::validate_env(env)?;
        }

        Ok(())
    }

    /// Validates that argument keys and values are not empty
    fn validate_args(args: &[(String, Option<String>)]) -> Result<(), RustSafeIoError> {
        if let Some((i, _key)) = args
            .iter()
            .enumerate()
            .find_map(|(i, (key, _))| if key.is_empty() { Some((i, key)) } else { None })
        {
            return Err(RustSafeIoError::ValidationError {
                reason: format!("Argument key at index {i} cannot be empty"),
            });
        }

        if let Some((i, key, _)) = args.iter().enumerate().find_map(|(i, (key, val))| {
            val.as_ref().and_then(|v| {
                if v.is_empty() {
                    Some((i, key, v))
                } else {
                    None
                }
            })
        }) {
            return Err(RustSafeIoError::ValidationError {
                reason: format!("Argument value for key '{key}' at index {i} cannot be empty"),
            });
        }

        Ok(())
    }

    /// Validates that environment variable keys and values are not empty
    fn validate_env(env: &[(String, String)]) -> Result<(), RustSafeIoError> {
        if let Some((i, _)) = env
            .iter()
            .enumerate()
            .find(|(_, (key, value))| key.is_empty() || value.is_empty())
        {
            return Err(RustSafeIoError::ValidationError {
                reason: format!(
                    "Environment variable at index {i} should have non-empty key and value"
                ),
            });
        }
        Ok(())
    }
}

impl RcFileHandle {
    /// Executes a command using the file handle with secure command execution via `fexecve()`.
    ///
    /// This method performs secure command execution by creating pipes for stdout/stderr capture,
    /// forking the current process, and then executing the file through its file descriptor.
    /// In the child process, output is redirected to the pipes before calling `fexecve()`.
    /// The parent process captures the output from the pipes and waits for the child to complete.
    /// The file handle must point to an executable file with proper permissions.
    ///
    /// Only supported for Linux based platforms.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_safe_io::DirConfigBuilder;
    /// use rust_safe_io::execute::ExecuteOptionsBuilder;
    /// use rust_safe_io::options::{OpenDirOptionsBuilder, OpenFileOptionsBuilder};
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// # use caps::Capability;
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    ///
    /// let dir_handle = DirConfigBuilder::default()
    ///     .path("/usr/bin".to_string())
    ///     .build().unwrap()
    ///     .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap())
    ///     .unwrap();
    ///
    /// let file_handle = dir_handle.safe_open_file(
    ///     &cedar_auth,
    ///     "ls",
    ///     OpenFileOptionsBuilder::default().read(true).build().unwrap()
    /// ).unwrap();
    ///
    /// let args = vec![
    ///     ("-la".to_string(), None),
    ///     ("/tmp".to_string(), None),
    /// ];
    ///
    /// let env = vec![
    ///     ("LANG".to_string(), "en_US.UTF-8".to_string()),
    /// ];
    ///
    /// let options = ExecuteOptionsBuilder::default()
    ///     .args(args)
    ///     .env(env)
    ///     .capabilities(vec![Capability::CAP_DAC_OVERRIDE])
    ///     .user("root")
    ///     .group("root")
    ///     .build()
    ///     .unwrap();
    ///
    /// let result = file_handle.safe_execute(&cedar_auth, options).unwrap();
    /// println!("Exit code: {}", result.exit_code());
    /// println!("Output:\n{}", result.stdout());
    /// if !result.stderr().is_empty() {
    ///     println!("Errors:\n{}", result.stderr());
    /// }
    /// ```
    #[allow(clippy::needless_pass_by_value)]
    #[allow(unsafe_code)]
    pub fn safe_execute(
        &self,
        cedar_auth: &CedarAuth,
        options: ExecuteOptions,
    ) -> Result<ExecuteResult, RustSafeIoError> {
        let file_entity = FileEntity::from_string_path(&self.full_path())?;

        let (target_user_id, target_group_id) = resolve_user_and_group_ids(&options)?;

        let (context, context_entities) =
            create_safe_execute_context(&options, target_user_id, target_group_id);
        is_authorized_with_context_entities(
            cedar_auth,
            &FilesystemAction::Execute,
            &file_entity,
            Some(context_entities),
            &context,
        )?;

        self.safe_execute_impl(
            &self.file_handle.file_path,
            &options,
            target_user_id,
            target_group_id,
        )
    }

    /// Internal implementation function for safe command execution with pre-resolved user/group IDs
    ///
    /// This function accepts pre-resolved Uid/Gid to avoid TOCTOU vulnerabilities.
    #[allow(unsafe_code)]
    fn safe_execute_impl(
        &self,
        executable_name: &str,
        options: &ExecuteOptions,
        target_user_id: Option<Uid>,
        target_group_id: Option<Gid>,
    ) -> Result<ExecuteResult, RustSafeIoError> {
        self.validate_read_only_open_option()?;

        let original_pidfd = if let Some(ns_opts) = &options.namespace {
            let original = Some(get_pid_fd(id())?);

            let target_pidfd = get_pid_fd(ns_opts.target_process)?;
            enter_namespace(&target_pidfd)?;

            original
        } else {
            None
        };

        let (stdout_read, stdout_write) = pipe()?;
        let (stderr_read, stderr_write) = pipe()?;

        match unsafe { fork() }? {
            ForkResult::Parent { child } => {
                drop(stdout_write);
                drop(stderr_write);
                if let Some(ref original) = original_pidfd {
                    enter_namespace(original)?;
                }
                handle_parent_process(child, stdout_read, stderr_read)
            }
            ForkResult::Child => {
                drop(stdout_read);
                drop(stderr_read);

                handle_child_process(
                    self,
                    executable_name,
                    options,
                    target_user_id,
                    target_group_id,
                    &stdout_write,
                    &stderr_write,
                )
            }
        }
    }

    /// Internal utility function for safe command execution
    ///
    /// This function provides a standalone safe execution utility that can be used by
    /// wrapper REX APIs.
    ///
    /// # Security Note
    ///
    /// This function does NOT perform Cedar authorization checks.
    /// It should only be called by wrapper REX APIs that have already performed appropriate authorization.
    /// Direct use of this function bypasses the security controls of the safe execute API.
    ///
    /// # Example Usage in Wrapper REX API
    ///
    /// ```no_run
    /// use rust_safe_io::{DirConfigBuilder, options::OpenDirOptionsBuilder, options::OpenFileOptionsBuilder};
    /// use rust_safe_io::execute::ExecuteOptionsBuilder;
    /// use rust_safe_io::errors::RustSafeIoError;
    /// use rex_cedar_auth::cedar_auth::CedarAuth;
    ///
    /// // In a wrapper API implementation
    /// pub fn systemctl_enable(
    ///     cedar_auth: &CedarAuth,
    ///     service_name: &str
    /// ) -> Result<(), RustSafeIoError> {
    ///     // Perform Cedar authorization check
    ///     // cedar_auth.is_authorized(...)?;
    ///
    ///     let bin_dir = DirConfigBuilder::default()
    ///         .path("/usr/bin".to_string())
    ///         .build()?
    ///         .safe_open(cedar_auth, OpenDirOptionsBuilder::default().build()?)?;
    ///
    ///     let systemctl_file = bin_dir.safe_open_file(
    ///         cedar_auth,
    ///         "systemctl",
    ///         OpenFileOptionsBuilder::default().read(true).build()?
    ///     )?;
    ///
    ///     let options = ExecuteOptionsBuilder::default()
    ///         .args(vec![
    ///             ("enable".to_string(), None),
    ///             (service_name.to_string(), None),
    ///         ])
    ///         .build()?;
    ///
    ///     let exec_result = systemctl_file.safe_execute_util(&options)?;
    ///
    ///     match *exec_result.exit_code() {
    ///         0 => Ok(()),
    ///         _ => Err(RustSafeIoError::UnexpectedStatus {
    ///             status: format!("Failed to enable service {}: {}",
    ///                 service_name, exec_result.stderr().trim())
    ///         })
    ///     }
    /// }
    /// ```
    #[allow(unsafe_code)]
    pub fn safe_execute_util(
        &self,
        options: &ExecuteOptions,
    ) -> Result<ExecuteResult, RustSafeIoError> {
        let (target_user_id, target_group_id) = resolve_user_and_group_ids(options)?;
        self.safe_execute_impl(
            &self.file_handle.file_path,
            options,
            target_user_id,
            target_group_id,
        )
    }
}

fn handle_child_process_error<E: Display>(message: &str, error: E) -> ! {
    error!("{message}: {error}");
    eprintln!("{message}: {error}");
    exit(EXIT_FAILURE);
}

fn handle_parent_process(
    child: Pid,
    stdout_read: OwnedFd,
    stderr_read: OwnedFd,
) -> Result<ExecuteResult, RustSafeIoError> {
    // Spawn threads to read pipes concurrently to prevent deadlock when output exceeds
    // the 64KB pipe buffer. Without concurrent reading, if the child writes more than
    // 64KB to stdout/stderr, it will block waiting for the pipe to be drained, while
    // the parent is waiting for the child to exit - causing a deadlock.
    let stdout_thread = thread::spawn(move || read_pipe_data(stdout_read));
    let stderr_thread = thread::spawn(move || read_pipe_data(stderr_read));

    let mut sigkill_sent = false;
    let mut log_printed = false;
    let exit_code = loop {
        match waitpid(child, Some(WaitPidFlag::WNOHANG))? {
            WaitStatus::StillAlive => {
                // Child is still running, continue monitoring
                // (pipe reader threads are draining output in the background)
            }
            WaitStatus::Exited(_, code) => {
                break code;
            }
            WaitStatus::Signaled(_, signal, _) => {
                error!(target: RUNNER_AND_SYSLOG_TARGET, "Execute API: Child stopped because it received a signal {signal}");
                break -(signal as i32); // Negative indicates signal number
            }
            status => {
                // Kill child to close pipe ends and unblock reader threads
                let _ = kill(child, Signal::SIGKILL);
                let _ = waitpid(child, None);
                // Join threads to ensure clean shutdown
                let _ = stdout_thread.join();
                let _ = stderr_thread.join();
                return Err(RustSafeIoError::UnexpectedStatus {
                    status: format!("{status:?}"),
                });
            }
        }
        // Check SIGTERM status and handle timeout
        if SigtermHandler::is_received() {
            if !log_printed {
                error!(target: RUNNER_AND_SYSLOG_TARGET,
                    "SIGTERM received, monitoring child process {child} for graceful shutdown");
                log_printed = true;
            }

            if let Some(elapsed) = SigtermHandler::get_elapsed_seconds()
                && elapsed >= SIGTERM_TIMEOUT_SECONDS
                && !sigkill_sent
            {
                error!(target: RUNNER_AND_SYSLOG_TARGET,
                        "SIGTERM timeout exceeded ({SIGTERM_TIMEOUT_SECONDS}s), sending SIGKILL to child process {child}");
                match kill(child, Signal::SIGKILL) {
                    Ok(()) => {}
                    Err(e) => {
                        error!(target: RUNNER_AND_SYSLOG_TARGET,
                                "Failed to send SIGKILL to child process {child}: {e:?}");
                    }
                }
                sigkill_sent = true;
            }
        }
        thread::sleep(Duration::from_millis(
            EXECUTE_API_CHILD_MONITORING_INTERNVAL_MSEC,
        ));
    };

    let stdout_data = stdout_thread
        .join()
        .map_err(|_| RustSafeIoError::UnexpectedStatus {
            status: "stdout reader thread panicked".to_string(),
        })??;
    let stderr_data = stderr_thread
        .join()
        .map_err(|_| RustSafeIoError::UnexpectedStatus {
            status: "stderr reader thread panicked".to_string(),
        })??;

    Ok(ExecuteResult {
        exit_code,
        stdout: String::from_utf8_lossy(&stdout_data).to_string(),
        stderr: String::from_utf8_lossy(&stderr_data).to_string(),
    })
}

/// This function never returns on success as `fexecve()` replaces the process image.
#[allow(unsafe_code)]
#[allow(clippy::unreachable)]
fn handle_child_process(
    file_handle: &RcFileHandle,
    executable_name: &str,
    options: &ExecuteOptions,
    target_user_id: Option<Uid>,
    target_group_id: Option<Gid>,
    stdout_write: &OwnedFd,
    stderr_write: &OwnedFd,
) -> ! {
    let mut stdout_fd = unsafe { OwnedFd::from_raw_fd(STDOUT_FILENO) };
    let mut stderr_fd = unsafe { OwnedFd::from_raw_fd(STDERR_FILENO) };

    match set_inheritable_and_ambient_capabilities(&options.capabilities) {
        Ok(()) => {}
        Err(e) => {
            handle_child_process_error("Failed to set capabilities", e);
        }
    }

    if let Err(e) = dup2(stdout_write, &mut stdout_fd) {
        handle_child_process_error("Failed to redirect stdout", e);
    }

    if let Err(e) = dup2(stderr_write, &mut stderr_fd) {
        handle_child_process_error("Failed to redirect stderr", e);
    }

    forget(stdout_fd);
    forget(stderr_fd);

    let args = match prepare_args(executable_name, options) {
        Ok(args) => args,

        Err(e) => {
            handle_child_process_error("Failed to prepare arguments", e);
        }
    };

    let env = match prepare_env(options) {
        Ok(env) => env,

        Err(e) => {
            handle_child_process_error("Failed to prepare environment", e);
        }
    };

    if let Some(gid) = target_group_id {
        set_group_id(gid);
    }

    if let Some(uid) = target_user_id {
        set_user_id(uid);
    }

    // Using `dup` here lets us execute shell scripts (like pstack) in addition to binaries. Duping isn't required if we're safe_executing a binary.
    // But for scripts, `fexecve` can't just run the script - it has to run the appropriate shell (sh, bash, etc) with the script fd as input. By default
    // though, the script fd is closed: it has the `O_CLOEXEC` flag applied whose purpose is exactly this (to protect against information leaks).
    // Since in this case we want the script fd to be available in the child process, we dup it, providing an fd that doesn't have O_CLOEXEC set.
    match dup(&file_handle.file_handle.file) {
        Ok(executable_fd) => match fexecve(executable_fd, &args, &env) {
            Ok(_) => {
                unreachable!("fexecve succeeded but didn't replace the process");
            }
            Err(e) => {
                handle_child_process_error("fexecve failed", e);
            }
        },

        Err(e) => {
            handle_child_process_error("Failed to dup the executable file descriptor", e);
        }
    }
}

fn prepare_args(
    executable_name: &str,
    options: &ExecuteOptions,
) -> Result<Vec<CString>, RustSafeIoError> {
    let mut args = Vec::new();
    args.push(CString::new(executable_name)?);

    for (key, value) in &options.args {
        args.push(CString::new(key.as_str())?);
        if let Some(val) = value {
            args.push(CString::new(val.as_str())?);
        }
    }

    Ok(args)
}

fn prepare_env(options: &ExecuteOptions) -> Result<Vec<CString>, RustSafeIoError> {
    let mut env = Vec::new();
    for (key, value) in &options.env {
        let env_var = format!("{key}={value}");
        env.push(CString::new(env_var)?);
    }

    Ok(env)
}

pub fn get_current_user() -> Result<(String, Uid), RustSafeIoError> {
    let current_uid = getuid();
    let users = Users::new_with_refreshed_list();

    users
        .list()
        .iter()
        .find(|user| **user.id() == current_uid.as_raw())
        .map_or_else(
            || {
                Err(RustSafeIoError::IdentityResolutionError {
                    reason: "Current user not found".to_string(),
                    value: current_uid.to_string(),
                })
            },
            |user| Ok((user.name().to_string(), current_uid)),
        )
}

pub fn get_current_group() -> Result<(String, Gid), RustSafeIoError> {
    let current_gid = getgid();
    let groups = Groups::new_with_refreshed_list();

    groups
        .list()
        .iter()
        .find(|group| **group.id() == current_gid.as_raw())
        .map_or_else(
            || {
                Err(RustSafeIoError::IdentityResolutionError {
                    reason: "Current group not found".to_string(),
                    value: current_gid.to_string(),
                })
            },
            |group| Ok((group.name().to_string(), current_gid)),
        )
}

/// Resolves user and group names to their corresponding UIDs and GIDs
fn resolve_user_and_group_ids(
    options: &ExecuteOptions,
) -> Result<(Option<Uid>, Option<Gid>), RustSafeIoError> {
    let uid = if let Some(username) = &options.user {
        Some(resolve_username_to_uid(username)?)
    } else {
        None
    };

    let gid = if let Some(groupname) = &options.group {
        Some(resolve_groupname_to_gid(groupname)?)
    } else {
        None
    };

    Ok((uid, gid))
}

/// Creates Cedar authorization context from `ExecuteOptions`
fn create_safe_execute_context(
    options: &ExecuteOptions,
    uid: Option<Uid>,
    gid: Option<Gid>,
) -> (Value, Vec<(String, Entity)>) {
    let mut context_map = Map::new();
    let mut context_entities = Vec::new();

    let args: Vec<(String, Option<String>)> = options
        .args
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let arguments_entity = ArgumentsEntity::new(args);
    if let Ok(entity) = arguments_entity.to_cedar_entity() {
        context_entities.push(("arguments".to_string(), entity));
    }

    let environment_entity = EnvironmentEntity::new(options.env.clone());
    if let Ok(entity) = environment_entity.to_cedar_entity() {
        context_entities.push(("environment".to_string(), entity));
    }

    if let Some(username) = &options.user {
        if let Some(user_id) = uid.map(Uid::as_raw) {
            context_map.insert(
                "user".to_string(),
                json!({
                    "username": username,
                    "uid": user_id
                }),
            );
        }
    } else if let Ok((current_username, current_uid)) = get_current_user() {
        context_map.insert(
            "user".to_string(),
            json!({
                "username": current_username,
                "uid": current_uid.as_raw()
            }),
        );
    }

    if let Some(groupname) = &options.group {
        if let Some(group_id) = gid.map(Gid::as_raw) {
            context_map.insert(
                "group".to_string(),
                json!({
                    "groupname": groupname,
                    "gid": group_id
                }),
            );
        }
    } else if let Ok((current_groupname, current_gid)) = get_current_group() {
        context_map.insert(
            "group".to_string(),
            json!({
                "groupname": current_groupname,
                "gid": current_gid.as_raw()
            }),
        );
    }

    if let Some(ns) = &options.namespace {
        context_map.insert(
            "namespace".to_string(),
            json!({
                "target_process_id": ns.target_process
            }),
        );
    }

    (Value::Object(context_map), context_entities)
}

/// Sets the specified capabilities in the inheritable and ambient capability set to enable passing to child process.
///
/// NOTE: Ambient caps do not set if calling set-user-ID or set-group-ID or if file has capabilities set.
fn set_inheritable_and_ambient_capabilities(caps: &[Capability]) -> Result<(), RustSafeIoError> {
    caps::clear(None, CapSet::Inheritable).map_err(|e| RustSafeIoError::CapabilityError {
        reason: format!("Failed to clear inheritable capabilities: {e}"),
        source: Box::new(e),
    })?;

    caps::clear(None, CapSet::Ambient).map_err(|e| RustSafeIoError::CapabilityError {
        reason: format!("Failed to clear ambient capabilities: {e}"),
        source: Box::new(e),
    })?;

    if caps.is_empty() {
        return Ok(());
    }

    let caps_set: HashSet<Capability> = caps.iter().copied().collect();

    caps::set(None, CapSet::Inheritable, &caps_set).map_err(|e| {
        RustSafeIoError::CapabilityError {
            reason: format!("Failed to set capabilities: {e}"),
            source: Box::new(e),
        }
    })?;

    caps::set(None, CapSet::Ambient, &caps_set).map_err(|e| RustSafeIoError::CapabilityError {
        reason: format!("Failed to set capabilities: {e}"),
        source: Box::new(e),
    })?;

    Ok(())
}

/// Resolves a username to its corresponding UID
fn resolve_username_to_uid(username: &str) -> Result<Uid, RustSafeIoError> {
    let users = Users::new_with_refreshed_list();

    users
        .list()
        .iter()
        .find(|user| user.name() == username)
        .ok_or_else(|| RustSafeIoError::IdentityResolutionError {
            reason: NO_USER_MAPPING_ERR.to_string(),
            value: username.to_string(),
        })
        .map(|user| Uid::from_raw(**user.id()))
}

/// Resolves a group name to its corresponding GID
fn resolve_groupname_to_gid(groupname: &str) -> Result<Gid, RustSafeIoError> {
    let groups = Groups::new_with_refreshed_list();
    groups
        .list()
        .iter()
        .find(|group| group.name() == groupname)
        .map(|group| Gid::from_raw(**group.id()))
        .ok_or_else(|| RustSafeIoError::IdentityResolutionError {
            reason: NO_GROUP_MAPPING_ERR.to_string(),
            value: groupname.to_string(),
        })
}

/// Sets to the specified user ID with temporary `CAP_SETUID` capability
fn set_user_id(uid: Uid) {
    if let Err(e) = setuid(uid) {
        handle_child_process_error(&format!("Failed to set UID {uid}"), e);
    }
}

/// Sets to the specified group ID with temporary `CAP_SETGID` capability
fn set_group_id(gid: Gid) {
    if let Err(e) = setgid(gid) {
        handle_child_process_error(&format!("Failed to set GID {gid}"), e);
    }

    if let Err(e) = setgroups(&[]) {
        handle_child_process_error("Failed to clear supplementary groups", e);
    }
}

/// Creates a process file descriptor (pidfd) for the specified PID.
#[allow(clippy::cast_possible_wrap)]
fn get_pid_fd(source_pid: u32) -> Result<OwnedFd, RustSafeIoError> {
    let pidfd = RustixPid::from_raw(source_pid as i32)
        .and_then(|rustix_pid| pidfd_open(rustix_pid, PidfdFlags::empty()).ok())
        .ok_or_else(|| RustSafeIoError::FileDescriptorError {
            reason: format!("Failed to open pidfd for PID {source_pid}"),
        })?;

    Ok(pidfd)
}

/// Enter PID namespace using `setns()` with a process file descriptor
///
/// NOTE: `CAP_SYS_ADMIN` will be required to change PID namespace. Reassociating with a
/// PID namespace is allowed only if the target PID namespace is a descendant (child,
/// grandchild, etc) of, or is the same as, the current PID namespace of the caller.
/// Additionally `CAP_SYS_PTRACE` will also be required if UID and GID of target PID is
/// different than caller PID.
fn enter_namespace(pidfd: &OwnedFd) -> Result<(), RustSafeIoError> {
    setns(pidfd, CloneFlags::CLONE_NEWPID).map_err(|e| {
        error!(
            "Failed to set namespace using pidfd. Hint: try running with CAP_SYS_ADMIN capability"
        );
        RustSafeIoError::ProcessNamespaceFatalError {
            reason: format!("Failed to switch to namespace using pidfd: {e}"),
        }
    })?;

    Ok(())
}

/// Reads data from a pipe file descriptor
///
/// Note: This function uses `std::fs` directly instead of `RustSafeIO` APIs because
/// pipe file descriptors are not regular filesystem objects. Pipes are anonymous
/// in-memory channels created by the OS for inter-process communication and do not
/// have filesystem paths, making them incompatible with `RustSafeIO`'s APIs.
#[allow(clippy::disallowed_types)]
fn read_pipe_data(fd: OwnedFd) -> Result<Vec<u8>, RustSafeIoError> {
    let mut file = File::from(fd);
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::{
        Capability, ExecuteOptions, ExecuteOptionsBuilder, Gid, Uid, prepare_args, prepare_env,
        resolve_groupname_to_gid, resolve_username_to_uid,
        set_inheritable_and_ambient_capabilities,
    };
    use crate::RustSafeIoError::{CapabilityError, IdentityResolutionError, ValidationError};
    use caps::{CapSet, read};
    /// Given: ExecuteOptions with mixed flags, arguments and environment variables
    /// When: Preparing args and env for fexecve
    /// Then: Flags are included without values, arguments and environment variables are formatted correctly
    #[test]
    fn test_prepare_args_and_env_for_execution() {
        let env = vec![
            ("PATH".to_string(), "/usr/bin".to_string()),
            ("HOME".to_string(), "/home/test".to_string()),
        ];

        let options = ExecuteOptions {
            args: vec![
                ("--verbose".to_string(), None),
                ("--file".to_string(), Some("test.txt".to_string())),
            ],
            env,
            capabilities: vec![],
            user: None,
            group: None,
            namespace: None,
        };

        let args = prepare_args("test_program", &options).unwrap();
        assert_eq!(args.len(), 4);
        assert_eq!(args[0].to_str().unwrap(), "test_program");
        assert_eq!(args[1].to_str().unwrap(), "--verbose");
        assert_eq!(args[2].to_str().unwrap(), "--file");
        assert_eq!(args[3].to_str().unwrap(), "test.txt");

        let env = prepare_env(&options).unwrap();
        assert_eq!(env.len(), 2);
        assert!(env.iter().any(|e| e.to_str().unwrap() == "PATH=/usr/bin"));
        assert!(env.iter().any(|e| e.to_str().unwrap() == "HOME=/home/test"));
    }

    /// Given: Process with some permitted capabilities
    /// When: Setting capabilities we do have
    /// Then: Should succeed or fail with capability operation error
    #[test]
    fn test_set_capabilities_with_permitted_caps() {
        let permitted = read(None, CapSet::Permitted).unwrap_or_default();

        assert!(permitted.is_empty());

        let missing_caps = vec![Capability::CAP_NET_ADMIN, Capability::CAP_SYS_ADMIN];
        let result = set_inheritable_and_ambient_capabilities(&missing_caps);

        if let Err(CapabilityError { reason, .. }) = result {
            assert!(reason.contains("Failed to set capabilities"));
        }
    }

    /// Given: A valid system username
    /// When: Resolving the username to UID
    /// Then: Should return the corresponding UID
    #[test]
    fn test_resolve_username_to_uid_valid_user() {
        let result = resolve_username_to_uid("root");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Uid::from_raw(0));
    }

    /// Given: An invalid/non-existent username
    /// When: Resolving the username to UID
    /// Then: Should return IdentityResolutionError
    #[test]
    fn test_resolve_username_to_uid_invalid_user() {
        let result = resolve_username_to_uid("nonexistentuser12345");
        assert!(result.is_err());

        let error = result.unwrap_err();
        assert!(matches!(error, IdentityResolutionError { .. }));

        if let IdentityResolutionError { reason, value } = error {
            assert!(reason.contains("No user mapping found"));
            assert_eq!(value, "nonexistentuser12345");
        }
    }

    /// Given: A valid system groupname
    /// When: Resolving the groupname to GID
    /// Then: Should return the corresponding GID
    #[test]
    fn test_resolve_groupname_to_gid_valid_group() {
        let result = resolve_groupname_to_gid("root");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Gid::from_raw(0));
    }

    /// Given: An invalid/non-existent groupname
    /// When: Resolving the groupname to GID
    /// Then: Should return IdentityResolutionError
    #[test]
    fn test_resolve_groupname_to_gid_invalid_group() {
        let result = resolve_groupname_to_gid("nonexistentgroup12345");
        assert!(result.is_err());

        let error = result.unwrap_err();
        assert!(matches!(error, IdentityResolutionError { .. }));

        if let IdentityResolutionError { reason, value } = error {
            assert!(reason.contains("No group mapping found"));
            assert_eq!(value, "nonexistentgroup12345");
        }
    }

    /// Given: ExecuteOptions with empty argument key or value
    /// When: Building ExecuteOptions
    /// Then: Should return ValidationError
    #[test]
    fn test_args_validation_fails() {
        let result = ExecuteOptionsBuilder::default()
            .args(vec![("".to_string(), Some("value".to_string()))])
            .build();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ValidationError { .. }));

        let result = ExecuteOptionsBuilder::default()
            .args(vec![("--key".to_string(), Some("".to_string()))])
            .build();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ValidationError { .. }));
    }

    /// Given: ExecuteOptions with empty environment variable key or value
    /// When: Building ExecuteOptions
    /// Then: Should return ValidationError
    #[test]
    fn test_env_validation_fails() {
        let env = vec![("".to_string(), "value".to_string())];
        let result = ExecuteOptionsBuilder::default().env(env).build();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ValidationError { .. }));

        let env = vec![("KEY".to_string(), "".to_string())];
        let result = ExecuteOptionsBuilder::default().env(env).build();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ValidationError { .. }));
    }
}
