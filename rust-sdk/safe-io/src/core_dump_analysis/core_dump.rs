use crate::core_dump_analysis::TracedProcess;
use crate::core_dump_analysis::parser::{parse_backtrace_output, parse_variable_output};
use crate::errors::RustSafeIoError;
use crate::execute::{ExecuteOptionsBuilder, ExecuteResult};
use crate::options::{OpenDirOptionsBuilder, OpenFileOptionsBuilder};
use crate::{DirConfigBuilder, RcFileHandle};
use rex_cedar_auth::cedar_auth::CedarAuth;
use serde::Serialize;
use std::collections::HashMap;
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::process;

/// Core dump analyzer using GDB.
///
/// The GDB executable file, executable file, and core dump handle are opened lazily: not when this struct is first instantiated, but
/// instead when one of its APIs (such as backtrace) is first called. This means authorization checks only occur when one of the APIs
/// is called.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, Serialize)]
pub struct CoreDump {
    exe_path: String,
    core_dump_path: String,
    #[serde(skip)]
    gdb_handle: Option<RcFileHandle>,
    #[serde(skip)]
    exe_handle: Option<RcFileHandle>,
    #[serde(skip)]
    core_dump_handle: Option<RcFileHandle>,
}

impl CoreDump {
    /// Create a new `CoreDump` instance. This function does not perform any input validation; that is done lazily
    /// when one of this struct's APIs are called.
    ///
    /// Arguments:
    /// * `exe_path`: the path to the exe that produced the core file (not the GDB executable)
    /// * `core_dump_path`: the path to the core dump file to analyze
    pub fn new(exe_path: String, core_dump_path: String) -> Self {
        Self {
            exe_path,
            core_dump_path,
            gdb_handle: None,
            exe_handle: None,
            core_dump_handle: None,
        }
    }

    /// Execute backtrace command and return parsed output
    #[allow(clippy::needless_pass_by_value)] // because rhai won't let us pass around references
    pub fn backtrace(&mut self, cedar_auth: &CedarAuth) -> Result<TracedProcess, RustSafeIoError> {
        self.init(cedar_auth)?;

        let mut args = vec![];
        args.push(("-batch".to_string(), None));
        args.push(("-ex".to_string(), Some("\"bt\"".to_string())));

        let output = self.execute_gdb(&mut args)?;

        if output.stderr().contains("not in executable format") {
            return Err(RustSafeIoError::InvalidExecutableError {
                exe: self.exe_path(),
            });
        }

        let parsed_output = parse_backtrace_output(output.stdout())?;
        parsed_output.ok_or(RustSafeIoError::InvalidTraceError {
            exe: self.exe_path(),
            core: self.core_dump_path(),
        })
    }

    /// Get variables for specific frame with default thread
    ///
    /// NB: even though the `variable_names` vec should really be borrowed, this takes an owned vec instead
    /// because I haven't found a way to convert a Rhai owned Array (aka `Vec<Dynamic>`) to a borrowed Array
    /// Ditto with `gdb_binary`
    #[allow(clippy::needless_pass_by_value)]
    pub fn get_variables(
        &mut self,
        cedar_auth: &CedarAuth,
        frame_number: u32,
        variable_names: Vec<String>,
    ) -> Result<HashMap<String, String>, RustSafeIoError> {
        self.get_variables_impl(cedar_auth, None, frame_number, &variable_names)
    }

    /// Get variables for specific frame with explicit thread
    ///
    /// NB: even though the `variable_names` vec should really be borrowed, this takes an owned vec instead
    /// because I haven't found a way to convert a Rhai owned Array (aka `Vec<Dynamic>`) to a borrowed Array
    /// Ditto with `gdb_binary`
    #[allow(clippy::needless_pass_by_value)]
    pub fn get_variables_with_thread(
        &mut self,
        cedar_auth: &CedarAuth,
        thread_id: u32,
        frame_number: u32,
        variable_names: Vec<String>,
    ) -> Result<HashMap<String, String>, RustSafeIoError> {
        self.get_variables_impl(cedar_auth, Some(thread_id), frame_number, &variable_names)
    }

    /// Internal implementation for variable extraction
    fn get_variables_impl(
        &mut self,
        cedar_auth: &CedarAuth,
        thread_id: Option<u32>,
        frame_number: u32,
        variable_names: &Vec<String>,
    ) -> Result<HashMap<String, String>, RustSafeIoError> {
        self.init(cedar_auth)?;

        let mut args = vec![];
        args.push(("-batch".to_string(), None));
        if let Some(tid) = thread_id {
            args.push(("-ex".to_string(), Some(format!("thread {tid}"))));
        }
        args.push(("-ex".to_string(), Some(format!("f {frame_number}"))));
        for var_name in variable_names {
            args.push(("-ex".to_string(), Some(format!("p {var_name}"))));
        }

        let output = self.execute_gdb(&mut args)?;

        parse_variable_output(output.stdout(), variable_names)
    }

    pub fn exe_path(&self) -> String {
        self.exe_path.clone()
    }

    pub fn core_dump_path(&self) -> String {
        self.core_dump_path.clone()
    }

    /// This function checks permissions, opens and caches the file handles needed to perform a core dump analysis.
    fn init(&mut self, cedar_auth: &CedarAuth) -> Result<(), RustSafeIoError> {
        if self.gdb_handle.is_none() {
            // Possible improvement: we may need to check different installation locations to find the GDB executable.
            // For now we'll assume GDB is in /usr/bin.
            let gdb_path = PathBuf::from("/usr/bin/gdb");
            // Here we only check if the caller has the open permission on GDB. Later on the call to safe_exec checks for
            // the execute permission. follow_symlinks is required because on AL2023 gdb is a symlink to `../libexec/gdb`.
            let gdb_handle = open_file_handle(cedar_auth, &gdb_path, true)?;
            self.gdb_handle = Some(gdb_handle);
        }

        if self.exe_handle.is_none() {
            let exe_path = PathBuf::from(&self.exe_path);
            let exe_handle = open_file_handle(cedar_auth, &exe_path, false)?;
            exe_handle.validate_read_open_option(cedar_auth)?;
            self.exe_handle = Some(exe_handle);
        }

        if self.core_dump_handle.is_none() {
            let core_dump_path = PathBuf::from(&self.core_dump_path);
            let core_dump_handle = open_file_handle(cedar_auth, &core_dump_path, false)?;
            core_dump_handle.validate_read_open_option(cedar_auth)?;
            self.core_dump_handle = Some(core_dump_handle);
        }

        Ok(())
    }

    /// The actual command being run here is:
    /// `gdb <args> /proc/<runner_pid>/fd/<exe_fd> /proc/<runner_pid>/fd/<core_dump_fd>`
    /// We use proc magic paths as inputs to gdb because they're not vulnerable to symlink poisoning TOCTOU attacks.
    #[allow(clippy::unwrap_used)] // TBD
    fn execute_gdb(
        &self,
        args: &mut Vec<(String, Option<String>)>,
    ) -> Result<ExecuteResult, RustSafeIoError> {
        let exe_path = proc_fd_path(self.exe_handle.as_ref().map(AsRawFd::as_raw_fd).unwrap());
        let core_dump_path = proc_fd_path(
            self.core_dump_handle
                .as_ref()
                .map(AsRawFd::as_raw_fd)
                .unwrap(),
        );

        // add the proc magic paths of the executable and the core dump to the args
        args.push((exe_path, None));
        args.push((core_dump_path, None));

        let execute_options = ExecuteOptionsBuilder::default()
            .args(args.clone())
            .build()?;

        self.gdb_handle
            .as_ref()
            .unwrap()
            .safe_execute_util(&execute_options)
    }
}

/// Opens a file handle with Cedar authorization.
///
/// When `follow_symlinks` is true the open will resolve symlinks (required for gdb on AL2023 where `/usr/bin/gdb` is a symlink to `../libexec/gdb`).
/// When false, follows the restrictive default to prevent TOCTOU attacks where a symlink could be swapped to point to a different file.
///
/// Only pass `follow_symlinks = true` for trusted system binaries whose symlink target is well-known.
fn open_file_handle(
    cedar_auth: &CedarAuth,
    file_path: &Path,
    follow_symlinks: bool,
) -> Result<RcFileHandle, RustSafeIoError> {
    let parent_dir = file_path
        .parent()
        .ok_or_else(|| RustSafeIoError::InvalidPath {
            reason: "File has no parent directory".to_string(),
            path: file_path.to_path_buf(),
        })?;

    let file_name = file_path
        .file_name()
        .ok_or_else(|| RustSafeIoError::InvalidPath {
            reason: "Invalid file name".to_string(),
            path: file_path.to_path_buf(),
        })?
        .to_str()
        .ok_or_else(|| RustSafeIoError::InvalidPath {
            reason: "File name contains invalid UTF-8".to_string(),
            path: file_path.to_path_buf(),
        })?;

    let dir = DirConfigBuilder::default()
        .path(parent_dir.to_string_lossy().to_string())
        .build()?
        .safe_open(cedar_auth, OpenDirOptionsBuilder::default().build()?)?;

    dir.safe_open_file(
        cedar_auth,
        file_name,
        OpenFileOptionsBuilder::default()
            .read(true)
            .follow_symlinks(follow_symlinks)
            .build()?,
    )
}

/// Get the proc link to a file descriptor so we can pass it to another process
fn proc_fd_path(fd: RawFd) -> String {
    let self_pid = process::id(); // the runner pid
    format!("/proc/{self_pid}/fd/{fd}")
}
