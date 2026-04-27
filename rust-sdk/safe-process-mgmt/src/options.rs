use crate::constants::error_constants::INVALID_NAMESPACE_OPTIONS;
use crate::errors::RustSafeProcessMgmtError;
use derive_builder::Builder;
use rustix::process::Signal;

/// Configuration for process enumeration operations
///
/// Specifies options for retrieving process information, including whether to load
/// PID namespace information for each process and whether to include threads.
///
/// # Examples
///
/// ```no_run
/// use rust_safe_process_mgmt::options::ProcessOptionsBuilder;
///
/// // Load namespace information
/// let options = ProcessOptionsBuilder::default()
///     .load_namespace_info(true)
///     .build()
///     .unwrap();
///
/// // Include threads in process listing
/// let options_with_threads = ProcessOptionsBuilder::default()
///     .include_threads(true)
///     .build()
///     .unwrap();
/// ```
#[derive(Builder, Debug, Clone, Copy)]
#[builder(derive(Debug), build_fn(error = "RustSafeProcessMgmtError"))]
pub struct ProcessOptions {
    /// Whether to load PID namespace information for each process
    #[builder(default = "false")]
    pub load_namespace_info: bool,

    /// Whether to include threads in the process list (default: false).
    ///
    /// When `true`, one [`ProcessInfo`](crate::ProcessInfo) entry is returned per
    /// thread (like `ps -eLf`). For thread entries:
    /// - `pid` is the thread ID (TID / LWP), **not** the process PID.
    /// - `ppid` is the PID of the process that owns the thread.
    /// - `command` and `username` match the owning process.
    #[builder(default = "false")]
    pub include_threads: bool,
}

/// Configuration for monitoring CPU usage of processes
///
/// Specifies which processes to monitor and how frequently to sample CPU usage.
/// At least one PID must be provided.
///
/// # Examples
///
/// ```no_run
/// use rust_safe_process_mgmt::options::MonitorProcessesCpuOptionsBuilder;
///
/// // Monitor specific processes with 5 samples, 1 second delay
/// let options = MonitorProcessesCpuOptionsBuilder::default()
///     .pids_to_monitor(vec![1234, 5678])
///     .batches(5)
///     .delay_in_seconds(1)
///     .build()
///     .unwrap();
///
/// // Include threads in CPU monitoring
/// let options_with_threads = MonitorProcessesCpuOptionsBuilder::default()
///     .pids_to_monitor(vec![1234])
///     .include_threads(true)
///     .build()
///     .unwrap();
/// ```
#[derive(Builder, Debug, Clone)]
#[builder(
    derive(Debug),
    build_fn(error = "RustSafeProcessMgmtError", validate = "Self::validate")
)]
pub struct MonitorProcessesCpuOptions {
    /// Array of process IDs to monitor
    #[builder(default)]
    pub pids_to_monitor: Vec<u32>,
    /// Number of batches to process
    #[builder(default = "1")]
    pub batches: u32,
    /// Delay between updates in seconds
    #[builder(default = "0")]
    pub delay_in_seconds: u64,
    /// Whether to include threads in monitoring
    #[builder(default = "false")]
    pub include_threads: bool,
}

impl MonitorProcessesCpuOptionsBuilder {
    fn validate(&self) -> Result<(), RustSafeProcessMgmtError> {
        if let Some(pids) = &self.pids_to_monitor {
            if pids.is_empty() {
                return Err(RustSafeProcessMgmtError::ValidationError {
                    reason: "PIDs array cannot be empty".to_string(),
                });
            }
        }
        Ok(())
    }
}

/// Configuration for namespace operations
///
/// Specifies which namespaces to enter during nsenter operations.
/// Mount namespaces can be entered using a target process PID.
/// Network namespaces can be entered using either a target process PID or a network namespace file.
/// At least one namespace must be enabled.
///
/// # Examples
///
/// ```no_run
/// use rust_safe_process_mgmt::options::NamespaceOptionsBuilder;
/// use std::io::Error;
///
/// let pid_options = NamespaceOptionsBuilder::default()
///     .pid(1234)
///     .mount(true)
///     .net(true)
///     .build()
///     .unwrap();
///
/// let net_ns_file_options = NamespaceOptionsBuilder::default()
///     .net_ns_name("customer")
///     .build()
///     .unwrap();
/// Ok::<(), Error>(())
/// ```

#[derive(Builder, Debug, Clone)]
#[builder(derive(Debug), build_fn(error = "RustSafeProcessMgmtError"))]
pub struct NamespaceOptions {
    /// Enter the mount namespace
    #[builder(default = "false")]
    pub mount: bool,

    /// Enter the network namespace
    #[builder(default = "false")]
    pub net: bool,

    /// Target process PID (mutually exclusive with namespace paths)
    #[builder(default, setter(strip_option))]
    pub pid: Option<u32>,

    /// Name of the network namespace file located in /var/run/netns/
    #[builder(default, setter(into, strip_option))]
    pub net_ns_name: Option<String>,
}

impl NamespaceOptions {
    /// Validates that at least one namespace is enabled and only the pid or name is set
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rust_safe_process_mgmt::options::NamespaceOptionsBuilder;
    ///
    /// let options = NamespaceOptionsBuilder::default()
    ///     .mount(true)
    ///     .build()
    ///     .unwrap();
    ///
    /// assert!(options.validate().is_ok());
    /// ```
    pub fn validate(&self) -> Result<(), RustSafeProcessMgmtError> {
        let has_pid = self.pid.is_some();
        let has_name = self.net_ns_name.is_some();

        if !has_pid && !has_name {
            return Err(RustSafeProcessMgmtError::ValidationError {
                reason: format!(
                    "{INVALID_NAMESPACE_OPTIONS}. Must specify pid or namespace filename"
                ),
            });
        }

        if has_pid && !self.mount && !self.net {
            return Err(RustSafeProcessMgmtError::ValidationError {
                reason: "At least one namespace type (mount or net) must be enabled".to_string(),
            });
        }

        if has_name && (has_pid || self.mount) {
            return Err(RustSafeProcessMgmtError::ValidationError {
                reason: "Cannot set both name and pid, and entering a mount namespace by filename is not supported"
                    .to_string(),
            });
        }

        Ok(())
    }
}

/// Helper function to convert string signal to rustix Signal
pub fn string_to_signal(signal_str: &str) -> Result<Signal, RustSafeProcessMgmtError> {
    match signal_str.to_uppercase().as_str() {
        "SIGTERM" => Ok(Signal::TERM),
        "SIGQUIT" => Ok(Signal::QUIT),
        "SIGHUP" => Ok(Signal::HUP),
        "SIGKILL" => Ok(Signal::KILL),
        _ => Err(RustSafeProcessMgmtError::ValidationError {
            reason: format!(
                "Invalid signal '{signal_str}'. Only SIGTERM, SIGQUIT, SIGHUP, and SIGKILL are allowed"
            ),
        }),
    }
}

/// Configuration parameters for killing processes
///
/// This struct is used to specify how processes should be killed. It supports two mutually
/// exclusive targeting modes: kill by PID, or kill by process characteristics (name/username).
///
/// # Validation Rules
///
/// * `signal` must always be specified (required field)
/// * Either `pid` OR (`process_name`/`username`/`command`) must be set, but not both
/// * If `pid` is set, `process_name`, `username`, and `command` must not be set
/// * If `process_name`, `username`, or `command` is set, `pid` must not be set
///
/// # Arguments
///
/// * `pid` - An optional u32 [`KillOptions::pid`] specifying the process ID to kill (default = None)
/// * `process_name` - An optional String [`KillOptions::process_name`] specifying the process name to match (default = None)
/// * `username` - An optional String [`KillOptions::username`] specifying the username to filter processes by (default = None)
/// * `exact_match` - A bool [`KillOptions::exact_match`] indicating whether to match process names exactly (default = false)
/// * `signal` - A rustix Signal [`KillOptions::signal`] specifying which signal to send to the process (required)
/// * `command` - An optional String [`KillOptions::command`] specifying command line arguments to match against (default = None)
///
/// # Examples
///
/// ```no_run
/// use rust_safe_process_mgmt::options::KillOptionsBuilder;
/// use rustix::process::Signal;
///
/// // Valid: Kill by PID only
/// let kill_by_pid = KillOptionsBuilder::default()
///     .pid(1234)
///     .signal(Signal::TERM)
///     .build()
///     .unwrap();
///
/// // Valid: Kill by process name only
/// let kill_by_name = KillOptionsBuilder::default()
///     .process_name("firefox")
///     .signal(Signal::KILL)
///     .exact_match(true)
///     .build()
///     .unwrap();
///
/// // Valid: Kill by username only (all processes by user)
/// let kill_by_user = KillOptionsBuilder::default()
///     .username("testuser")
///     .signal(Signal::TERM)
///     .build()
///     .unwrap();
///
/// // Valid: Kill by full command line
/// let kill_by_command = KillOptionsBuilder::default()
///     .command("node /path/to/server.js --port=3000")
///     .signal(Signal::TERM)
///     .build()
///     .unwrap();
///
/// // Valid: Combine username with process name
/// let kill_user_firefox = KillOptionsBuilder::default()
///     .process_name("firefox")
///     .username("testuser")
///     .signal(Signal::TERM)
///     .build()
///     .unwrap();
///
/// // Invalid: Cannot mix process_name with command
/// let invalid = KillOptionsBuilder::default()
///     .process_name("firefox")
///     .command("firefox --safe-mode")  // Error!
///     .signal(Signal::TERM)
///     .build();
/// ```
#[derive(Builder, Debug, Clone)]
#[builder(
    derive(Debug),
    build_fn(error = "RustSafeProcessMgmtError", validate = "Self::validate")
)]
pub struct KillOptions {
    /// Process ID to kill (mutually exclusive with all other targeting methods)
    #[builder(default, setter(strip_option))]
    pub pid: Option<i64>,

    /// Process name to match (mutually exclusive with `pid` and `command`)
    #[builder(default, setter(into, strip_option))]
    pub process_name: Option<String>,

    /// Username to filter processes by (can be used alone or with `process_name`/`command`)
    #[builder(default, setter(into, strip_option))]
    pub username: Option<String>,

    /// Whether to match process names exactly (only applies with `process_name`)
    #[builder(default = "false")]
    pub exact_match: bool,

    /// [`Signal`] to send to the process (required)
    pub signal: Signal,

    /// Full command line to match against (mutually exclusive with `pid` and `process_name`)
    #[builder(default, setter(into, strip_option))]
    pub command: Option<String>,
}

impl KillOptionsBuilder {
    fn validate(&self) -> Result<(), RustSafeProcessMgmtError> {
        if self.signal.is_none() {
            return Err(RustSafeProcessMgmtError::ValidationError {
                reason: "signal is required".to_string(),
            });
        }

        let has_pid = self.pid.flatten().is_some();
        let has_process_name = self
            .process_name
            .as_ref()
            .and_then(|opt| opt.as_ref())
            .is_some();
        let has_username = self
            .username
            .as_ref()
            .and_then(|opt| opt.as_ref())
            .is_some();
        let has_command = self.command.as_ref().and_then(|opt| opt.as_ref()).is_some();

        if has_pid && self.pid.flatten().is_some_and(|pid| pid < 0) {
            return Err(RustSafeProcessMgmtError::ValidationError {
                reason: "PID cannot be negative".to_string(),
            });
        }

        // Rule 1: Must have at least one targeting method
        if !has_pid && !has_process_name && !has_username && !has_command {
            return Err(RustSafeProcessMgmtError::ValidationError {
                reason: "At least one targeting method must be specified: pid, process_name, username, or command".to_string(),
            });
        }

        // Rule 2: PID is mutually exclusive with everything else
        if has_pid && (has_process_name || has_username || has_command) {
            return Err(RustSafeProcessMgmtError::ValidationError {
                reason: "pid cannot be used together with process_name, username, or command"
                    .to_string(),
            });
        }

        // Rule 3: process_name and command are mutually exclusive
        if has_process_name && has_command {
            return Err(RustSafeProcessMgmtError::ValidationError {
                reason: "process_name and command cannot be used together - choose either name-based or command-based targeting".to_string(),
            });
        }

        Ok(())
    }
}

/// Configuration for lsof operations
///
/// Specifies how to list open files. Currently supports path-based listing.
///
/// # Examples
///
/// ```no_run
/// use rust_safe_process_mgmt::options::LsofOptionsBuilder;
///
/// // Path-based: list open files in a directory
/// let options = LsofOptionsBuilder::default()
///     .path("/tmp".to_string())
///     .include_subdir(true)
///     .build()
///     .unwrap();
///
/// // PID-based: list all open files for a specific process
/// let options = LsofOptionsBuilder::default()
///     .pid(1234_u32)
///     .build()
///     .unwrap();
/// ```
#[derive(Builder, Debug, Clone)]
#[builder(
    derive(Debug),
    build_fn(error = "RustSafeProcessMgmtError", validate = "Self::validate")
)]
pub struct LsofOptions {
    /// Directory path to scan for open files (mutually exclusive with pid)
    #[builder(default, setter(into, strip_option))]
    pub path: Option<String>,
    /// Whether to include subdirectories in the scan (lsof +D). Only used with path.
    #[builder(default = "false")]
    pub include_subdir: bool,
    /// Process ID to list open files for (mutually exclusive with path)
    #[builder(default, setter(strip_option))]
    pub pid: Option<u32>,
}

impl LsofOptionsBuilder {
    fn validate(&self) -> Result<(), RustSafeProcessMgmtError> {
        let has_path = self.path.as_ref().is_some_and(Option::is_some);
        let has_pid = self.pid.as_ref().is_some_and(Option::is_some);

        if has_path && has_pid {
            return Err(RustSafeProcessMgmtError::ValidationError {
                reason: "pid and path are mutually exclusive".to_string(),
            });
        }

        if !has_path && !has_pid {
            return Err(RustSafeProcessMgmtError::ValidationError {
                reason: "Either path or pid is required".to_string(),
            });
        }

        if let Some(Some(path)) = &self.path {
            if path.is_empty() {
                return Err(RustSafeProcessMgmtError::ValidationError {
                    reason: "Path cannot be empty".to_string(),
                });
            }
        }

        Ok(())
    }
}

/// Configuration for process tracing
///
/// Specifies options such as which sandbox environment (pid namespace) to run the trace in.
///
/// # Examples
///
/// ```no_run
/// use rust_safe_process_mgmt::options::TraceOptionsBuilder;
///
/// // This process is PID 1 inside the sandbox, but its PID is 1234 in the default namespace.
/// let sandbox_pid = 1234;  
/// let options = TraceOptionsBuilder::default()
///     .ns_pid(sandbox_pid)
///     .build()
///     .unwrap();
/// ```
#[derive(Builder, Debug, Clone, Copy)]
#[builder(derive(Debug), build_fn(error = "RustSafeProcessMgmtError"))]
pub struct TraceOptions {
    /// A PID in the default namespace representing the namespace you want to enter.
    ///
    /// This can be the PID for any process in the PID namespace; it doesn't specifically need to be the namespace's root process.
    /// For example, if a process is running inside a sandbox, the PID of any process in the sandbox can be used to enter
    /// the sandbox namespace; the sandbox PID itself isn't required.
    ///
    /// When this option is used, the `pid` argument to the trace API will represent the PID _inside_ the namespace, not
    /// in the default namespace.
    pub ns_pid: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rex_test_utils::assertions::assert_error_contains;
    use rustix::process::Signal;

    /// Given: NamespaceOptions with no namespaces enabled
    /// When: Validating the options
    /// Then: Validation should fail with an appropriate error message
    #[test]
    fn test_namespace_options_validate_none() {
        let options = NamespaceOptionsBuilder::default().build().unwrap();
        let result = options.validate();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("At least one namespace must be enabled")
        );
    }

    /// Given: NamespaceOptions with both a path and a pid enabled to enter a mount namespace
    /// When: Validating the options
    /// Then: Validation should fail with an appropriate error message
    #[test]
    fn test_namespace_options_pid_and_name() {
        let options = NamespaceOptionsBuilder::default()
            .net_ns_name("test-ns")
            .pid(1234)
            .mount(true)
            .build()
            .unwrap();
        let result = options.validate();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Cannot set both name and pid")
        );
    }

    /// Given: Valid KillOptionsBuilder with all options set
    /// When: Building KillOptions
    /// Then: Should succeed and create valid KillOptions
    #[test]
    fn test_kill_options_valid_build() {
        let result = KillOptionsBuilder::default()
            .process_name("firefox")
            .username("testuser")
            .exact_match(true)
            .signal(Signal::TERM)
            .build();

        assert!(result.is_ok());
        let options = result.unwrap();
        assert_eq!(options.process_name, Some("firefox".to_string()));
        assert_eq!(options.username, Some("testuser".to_string()));
        assert!(options.exact_match);
    }

    /// Given: KillOptionsBuilder with no signal set
    /// When: Building KillOptions
    /// Then: Should return error indicating signal is required
    #[test]
    fn test_kill_options_no_signal_error() {
        let result = KillOptionsBuilder::default().pid(1234).build();

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("signal is required"));
    }

    /// Given: KillOptionsBuilder with signal but no targeting method
    /// When: Building KillOptions
    /// Then: Should return error indicating at least one targeting method is required
    #[test]
    fn test_kill_options_no_targeting_method_error() {
        let result = KillOptionsBuilder::default().signal(Signal::TERM).build();

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("At least one targeting method must be specified"));
    }

    /// Given: KillOptionsBuilder with negative pid
    /// When: Building KillOptions
    /// Then: Should return error indicating pid is negative
    #[test]
    fn test_kill_options_negative_pid_error() {
        let result = KillOptionsBuilder::default()
            .pid(-1234)
            .process_name("firefox")
            .signal(Signal::TERM)
            .build();

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("PID cannot be negative"));
    }

    /// Given: KillOptionsBuilder with pid and another targeting method
    /// When: Building KillOptions
    /// Then: Should return error indicating pid cannot be used with other targeting methods
    #[test]
    fn test_kill_options_pid_with_other_targeting_error() {
        let result = KillOptionsBuilder::default()
            .pid(1234)
            .process_name("firefox")
            .signal(Signal::TERM)
            .build();

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("pid cannot be used together with"));
    }

    /// Given: KillOptionsBuilder with process_name and command
    /// When: Building KillOptions
    /// Then: Should return error indicating process_name and command are mutually exclusive
    #[test]
    fn test_kill_options_process_name_with_command_error() {
        let result = KillOptionsBuilder::default()
            .process_name("firefox")
            .command("firefox --safe-mode")
            .signal(Signal::TERM)
            .build();

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("process_name and command cannot be used together"));
    }

    /// Given: Various signal strings (valid and invalid)
    /// When: Converting to signal using string_to_signal
    /// Then: Should return correct Signal enum or appropriate error
    #[test]
    fn test_string_to_signal_comprehensive() {
        assert_eq!(string_to_signal("sigterm").unwrap(), Signal::TERM);
        assert_eq!(string_to_signal("SIGQUIT").unwrap(), Signal::QUIT);
        assert_eq!(string_to_signal("SIGHUP").unwrap(), Signal::HUP);
        assert_eq!(string_to_signal("SigKill").unwrap(), Signal::KILL);
        assert_error_contains(string_to_signal("Term"), "Invalid signal 'Term'");
    }

    /// Given: Valid LsofOptionsBuilder with path set
    /// When: Building LsofOptions
    /// Then: Should succeed and create valid LsofOptions
    #[test]
    fn test_lsof_options_valid_build() {
        let result = LsofOptionsBuilder::default()
            .path("/tmp".to_string())
            .build();

        assert!(result.is_ok());
        let options = result.unwrap();
        assert_eq!(options.path, Some("/tmp".to_string()));
    }

    /// Given: LsofOptionsBuilder with neither path nor pid set
    /// When: Building LsofOptions
    /// Then: Should return error indicating path or pid is required
    #[test]
    fn test_lsof_options_no_path_error() {
        let result = LsofOptionsBuilder::default().build();

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Either path or pid is required"));
    }

    /// Given: LsofOptionsBuilder with both path and pid set
    /// When: Building LsofOptions
    /// Then: Should return error indicating mutual exclusivity
    #[test]
    fn test_lsof_options_pid_and_path_error() {
        let result = LsofOptionsBuilder::default()
            .path("/tmp".to_string())
            .pid(1234_u32)
            .build();

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("pid and path are mutually exclusive"));
    }

    /// Given: LsofOptionsBuilder with only pid set
    /// When: Building LsofOptions
    /// Then: Should build successfully with pid set and path None
    #[test]
    fn test_lsof_options_pid_only() {
        let options = LsofOptionsBuilder::default().pid(1234_u32).build().unwrap();

        assert_eq!(options.pid, Some(1234));
        assert_eq!(options.path, None);
    }

    /// Given: LsofOptionsBuilder with empty path
    /// When: Building LsofOptions
    /// Then: Should return error indicating path cannot be empty
    #[test]
    fn test_lsof_options_empty_path_error() {
        let result = LsofOptionsBuilder::default().path("".to_string()).build();

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Path cannot be empty"));
    }

    /// Given: LsofOptionsBuilder with include_subdir set to true
    /// When: Building LsofOptions
    /// Then: Should succeed and create valid LsofOptions with include_subdir enabled
    #[test]
    fn test_lsof_options_with_include_subdir_true() {
        let result = LsofOptionsBuilder::default()
            .path("/tmp".to_string())
            .include_subdir(true)
            .build();

        assert!(result.is_ok());
        let options = result.unwrap();
        assert_eq!(options.path, Some("/tmp".to_string()));
        assert!(options.include_subdir);
    }

    /// Given: LsofOptionsBuilder with include_subdir set to false
    /// When: Building LsofOptions
    /// Then: Should succeed and create valid LsofOptions with include_subdir disabled
    #[test]
    fn test_lsof_options_with_include_subdir_false() {
        let result = LsofOptionsBuilder::default()
            .path("/tmp".to_string())
            .include_subdir(false)
            .build();

        assert!(result.is_ok());
        let options = result.unwrap();
        assert_eq!(options.path, Some("/tmp".to_string()));
        assert!(!options.include_subdir);
    }

    /// Given: LsofOptionsBuilder without setting include_subdir
    /// When: Building LsofOptions
    /// Then: Should succeed and create valid LsofOptions with include_subdir defaulting to false
    #[test]
    fn test_lsof_options_default_include_subdir() {
        let result = LsofOptionsBuilder::default()
            .path("/tmp".to_string())
            .build();

        assert!(result.is_ok());
        let options = result.unwrap();
        assert_eq!(options.path, Some("/tmp".to_string()));
        assert!(!options.include_subdir);
    }

    /// Given: ProcessOptionsBuilder with default values
    /// When: Building ProcessOptions
    /// Then: Should succeed with load_namespace_info defaulting to false
    #[test]
    fn test_process_options_default() {
        let result = ProcessOptionsBuilder::default().build();

        assert!(result.is_ok());
        let options = result.unwrap();
        assert!(!options.load_namespace_info);
    }

    /// Given: ProcessOptionsBuilder with load_namespace_info set to true
    /// When: Building ProcessOptions
    /// Then: Should succeed with load_namespace_info enabled
    #[test]
    fn test_process_options_with_namespace_info() {
        let result = ProcessOptionsBuilder::default()
            .load_namespace_info(true)
            .build();

        assert!(result.is_ok());
        let options = result.unwrap();
        assert!(options.load_namespace_info);
    }

    /// Given: ProcessOptionsBuilder with include_threads set to true
    /// When: Building ProcessOptions
    /// Then: Should succeed with include_threads enabled
    #[test]
    fn test_process_options_with_threads() {
        let result = ProcessOptionsBuilder::default()
            .include_threads(true)
            .build();

        assert!(result.is_ok());
        let options = result.unwrap();
        assert!(options.include_threads);
    }

    /// Given: ProcessOptionsBuilder with default values
    /// When: Building ProcessOptions
    /// Then: Should have include_threads=false by default
    #[test]
    fn test_process_options_defaults() {
        let result = ProcessOptionsBuilder::default().build();

        assert!(result.is_ok());
        let options = result.unwrap();
        assert!(!options.include_threads);
        assert!(!options.load_namespace_info);
    }
}
