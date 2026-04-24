//! Linux-specific sysctl implementation

use super::common::{SysctlEntry, SysctlProvider};
use crate::RustSysteminfoError;
use caps::{CapSet, Capability};
use nix::sys::prctl;
use nix::unistd::{Uid, geteuid, seteuid, setresuid};
use rex_cedar_auth::cedar_auth::CedarAuth;
use rust_safe_io::{
    DirConfigBuilder, WalkEntry, errors::RustSafeIoError, execute::ExecuteOptionsBuilder,
    options::FindOptionsBuilder, options::OpenDirOptionsBuilder, options::OpenFileOptionsBuilder,
};
use rust_sdk_common_utils::execute_with_privilege_drop;
use std::io::{Error, ErrorKind};
use std::path::Path;
use tracing::warn;

const PROC_SYS_PATH: &str = "/proc/sys";
const SYSCTL_BINARY_PATH: &str = "/usr/sbin";
const SYSCTL_BINARY_NAME: &str = "sysctl";

// Parameters that should be skipped during enumeration
// See Notes: https://man7.org/linux/man-pages/man8/sysctl.8.html
const SKIPPABLE: &[&str] = &["base_reachable_time", "retrans_time", "stat_refresh"];

// Security-sensitive parameters that require additional capabilities beyond `CAP_SETUID`
const SECURITY_SENSITIVE_PARAMS: &[&str] = &["kernel.yama.ptrace_scope", "kernel.kptr_restrict"];

/// Internal sysctl implementation for Linux systems
#[derive(Debug, Clone, Copy)]
pub(crate) struct Sysctl {
    uid: Uid,
    allow_root_params: bool,
}

impl SysctlProvider for Sysctl {
    fn read(&self, cedar_auth: &CedarAuth, key: &str) -> Result<String, RustSysteminfoError> {
        let path = Self::key_to_path(key);
        let parent_path = Self::get_parent_path(&path)?;
        let file_name: String = Self::get_file_name(&path)?;

        match Self::read_sysctl_file(cedar_auth, &parent_path, &file_name) {
            Ok(content) => Ok(content),

            Err(e) if is_permission_denied(&e) && self.allow_root_params => {
                // Retry as root if permission denied and SUID=0
                match self.as_root(|| Self::read_sysctl_file(cedar_auth, &parent_path, &file_name))
                {
                    Ok(content) => Ok(content),
                    Err(elevated_err) => {
                        warn!(
                            "Failed to read {key} as root. Hint: CAP_SYS_ADMIN and CAP_DAC_READ_SEARCH may be required"
                        );
                        Err(elevated_err)
                    }
                }
            }
            Err(e) if is_permission_denied(&e) => {
                warn!(
                    "Failed to read {key}. Hint: CAP_SETUID, CAP_SYS_ADMIN and CAP_DAC_READ_SEARCH required"
                );
                Err(e)
            }

            Err(e) => Err(e),
        }
    }

    fn write(
        &self,
        cedar_auth: &CedarAuth,
        key: &str,
        value: &str,
    ) -> Result<(), RustSysteminfoError> {
        let path = Self::key_to_path(key);
        let parent_path = Self::get_parent_path(&path)?;
        let file_name = Self::get_file_name(&path)?;

        self.as_root(|| {
            let dir_handle = DirConfigBuilder::default()
                .path(parent_path.clone())
                .build()?
                .safe_open(cedar_auth, OpenDirOptionsBuilder::default().build()?)?;

            // Open with special_file=true since /proc/sys files don't support truncate/sync/rewind
            let file_handle = dir_handle.safe_open_file(
                cedar_auth,
                &file_name,
                OpenFileOptionsBuilder::default()
                    .write(true)
                    .special_file(true)
                    .build()?,
            )?;

            file_handle.safe_write_in_place(cedar_auth, value)?;
            Ok(())
        })
        .map_err(|e| match &e {
            RustSysteminfoError::SafeIoError(RustSafeIoError::IoError(io_err)) => {
                match io_err.raw_os_error() {
                    Some(2) => RustSysteminfoError::InvalidParameter {
                        key: key.to_string(),
                    },
                    Some(22) => RustSysteminfoError::InvalidValue {
                        key: key.to_string(),
                        value: value.to_string(),
                        reason: "Invalid argument".to_string(),
                    },
                    _ => e,
                }
            }
            _ => e,
        })
        .inspect_err(|e| {
            if SECURITY_SENSITIVE_PARAMS.contains(&key) {
                warn!(
                    "Failed to set security-sensitive parameter '{key}': {e}. Hint: Required capabilities CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_SETUID"
                );
            }
        })
    }

    fn load_system(&self, cedar_auth: &CedarAuth) -> Result<(), RustSysteminfoError> {
        let usr_sbin_handle = DirConfigBuilder::default()
            .path(SYSCTL_BINARY_PATH.to_string())
            .build()?
            .safe_open(cedar_auth, OpenDirOptionsBuilder::default().build()?)?;

        let sysctl_binary = usr_sbin_handle.safe_open_file(
            cedar_auth,
            SYSCTL_BINARY_NAME,
            OpenFileOptionsBuilder::default().read(true).build()?,
        )?;

        let mut execute_options = ExecuteOptionsBuilder::default();

        let mut caps_to_pass = Vec::new();
        if caps::has_cap(None, CapSet::Effective, Capability::CAP_SETUID)? {
            caps_to_pass.push(Capability::CAP_SETUID);
        }
        if caps::has_cap(None, CapSet::Effective, Capability::CAP_SYS_ADMIN)? {
            caps_to_pass.push(Capability::CAP_SYS_ADMIN);
        }
        if caps::has_cap(None, CapSet::Effective, Capability::CAP_SYS_PTRACE)? {
            caps_to_pass.push(Capability::CAP_SYS_PTRACE);
        }

        if !caps_to_pass.is_empty() {
            execute_options.capabilities(caps_to_pass);
        }

        execute_options
            .args(vec![("--system".to_string(), None)])
            .user("root".to_string());

        let result = sysctl_binary.safe_execute_util(&execute_options.build()?)?;

        if *result.exit_code() != 0 {
            return Err(RustSysteminfoError::IoError(std::io::Error::other(
                format!(
                    "sysctl --system failed with exit code {}: {}",
                    result.exit_code(),
                    result.stderr()
                ),
            )));
        }

        // sysctl --system is best-effort; stderr warnings about unsupported params are expected
        if !result.stderr().is_empty() {
            warn!("sysctl --system produced warnings: {}", result.stderr());
        }

        Ok(())
    }

    fn find(
        &self,
        cedar_auth: &CedarAuth,
        pattern: &str,
    ) -> Result<Vec<SysctlEntry>, RustSysteminfoError> {
        let proc_sys_dir = DirConfigBuilder::default()
            .path(PROC_SYS_PATH.to_string())
            .build()?
            .safe_open(cedar_auth, OpenDirOptionsBuilder::default().build()?)?;

        let mut results = Vec::new();

        let find_options = FindOptionsBuilder::default()
            .regex(pattern.to_string())
            .build()?;

        proc_sys_dir.safe_find(cedar_auth, find_options, |entry| {
            if let WalkEntry::Entry(dir_entry) = entry
                && dir_entry.is_file() {
                    if let Some(filename) = Path::new(&dir_entry.full_path()).file_name() {
                        let filename_str = filename.to_string_lossy();
                        // Skip parameters that should not be enumerated
                        if Self::skippable(&filename_str) {
                            return Ok(());
                        }
                    }

                    if let Some(key) = Self::path_to_key(&dir_entry.full_path()) {
                        let mut owned_entry = dir_entry.clone();
                        // Try to read as current user
                        let read_result = (|| -> Result<String, RustSysteminfoError> {
                            let file_handle = owned_entry.open_as_file(
                                cedar_auth,
                                OpenFileOptionsBuilder::default().read(true).build()?,
                            )?;
                            Ok(file_handle.safe_read(cedar_auth)?)
                        })();

                        match read_result {
                            Ok(value) => {
                                results.push(SysctlEntry::new(key, value.trim().to_string()));
                            }
                            Err(e) if is_permission_denied(&e) && self.allow_root_params => {
                                // Retry as root
                                let key_clone = key.clone();
                                let elevated_result = self.as_root(|| {
                                    let mut retry_entry = dir_entry.clone();
                                    let file_handle = retry_entry.open_as_file(
                                        cedar_auth,
                                        OpenFileOptionsBuilder::default().read(true).build()?,
                                    )?;
                                    Ok(file_handle.safe_read(cedar_auth)?)
                                });

                                match elevated_result {
                                    Ok(value) => {
                                        results.push(SysctlEntry::new(key_clone, value.trim().to_string()));
                                    }
                                    Err(_) => {
                                        warn!("Failed to read {key_clone} as root, skipping. Hint: CAP_SYS_ADMIN and CAP_DAC_READ_SEARCH may be required");
                                    }
                                }
                            }
                            Err(e) if is_permission_denied(&e) => {
                                warn!("Failed to read {key}, skipping. Hint: CAP_SETUID, CAP_SYS_ADMIN and CAP_DAC_READ_SEARCH required");
                            }
                            Err(e) => {
                                // Skip other errors to continue directory traversal
                                warn!("Failed to read {key}, skipping: {e}");
                            }
                        }
                    }
                }
            Ok(())
        })?;

        Ok(results)
    }
}

impl Sysctl {
    pub(crate) fn new() -> Result<Self, RustSysteminfoError> {
        let uid = geteuid();
        let allow_root_params =
            caps::has_cap(None, CapSet::Effective, Capability::CAP_SETUID).unwrap_or(false);

        if allow_root_params {
            prctl::set_keepcaps(true).map_err(|e| RustSysteminfoError::PrivilegeError {
                message: format!("Failed to set keepcaps: {e}"),
            })?;
            setresuid(uid, uid, Uid::from_raw(0)).map_err(|e| {
                warn!("Failed to set saved uid as 0. CAP_SETUID capability is required");
                RustSysteminfoError::PrivilegeError {
                    message: format!("Failed to initialize sysctl manager: {e}"),
                }
            })?;
        }

        Ok(Self {
            uid,
            allow_root_params,
        })
    }

    fn as_root<F, R>(self, f: F) -> Result<R, RustSysteminfoError>
    where
        F: FnOnce() -> Result<R, RustSysteminfoError>,
    {
        let initial_caps = caps::read(None, CapSet::Effective).map_err(|e| {
            RustSysteminfoError::PrivilegeError {
                message: format!("Failed to read effective capabilities: {e}"),
            }
        })?;

        seteuid(Uid::from_raw(0)).map_err(|e| RustSysteminfoError::PrivilegeError {
            message: format!("Failed to switch privileges: {e}"),
        })?;

        let result = execute_with_privilege_drop!(
            f,
            seteuid(self.uid).map_err(|_| ()).and_then(|_| {
                if geteuid() != self.uid {
                    Err(())
                } else {
                    Ok(())
                }
            }),
            format!(
                "FATAL: Failed to drop privileges: expected UID {}, but current UID is {}. Terminating process",
                self.uid.as_raw(),
                geteuid().as_raw()
            ),
            |msg| RustSysteminfoError::PrivilegeError {
                message: format!("Panic during privileged execution: {msg}"),
            },
            |msg| RustSysteminfoError::PrivilegeError { message: msg }
        );

        caps::set(None, CapSet::Effective, &initial_caps).map_err(|e| {
            RustSysteminfoError::PrivilegeError {
                message: format!("Failed to restore effective capabilities: {e}"),
            }
        })?;

        result
    }

    fn read_sysctl_file(
        cedar_auth: &CedarAuth,
        parent_path: &str,
        file_name: &str,
    ) -> Result<String, RustSysteminfoError> {
        let dir_handle = DirConfigBuilder::default()
            .path(parent_path.to_string())
            .build()?
            .safe_open(cedar_auth, OpenDirOptionsBuilder::default().build()?)?;

        let file_handle = dir_handle.safe_open_file(
            cedar_auth,
            file_name,
            OpenFileOptionsBuilder::default().read(true).build()?,
        )?;

        let content = file_handle.safe_read(cedar_auth)?;
        Ok(content.trim().to_string())
    }

    pub(crate) fn key_to_path(key: &str) -> String {
        format!("{}/{}", PROC_SYS_PATH, key.replace('.', "/"))
    }

    fn path_to_key(path: &str) -> Option<String> {
        path.strip_prefix("/proc/sys/")
            .map(|key_path| key_path.replace('/', "."))
    }

    fn get_parent_path(path: &str) -> Result<String, RustSysteminfoError> {
        let parent = Path::new(path).parent().ok_or_else(|| {
            RustSysteminfoError::IoError(Error::new(
                ErrorKind::NotFound,
                format!("Invalid sysctl path: {path}"),
            ))
        })?;
        Ok(parent.to_string_lossy().to_string())
    }

    fn get_file_name(path: &str) -> Result<String, RustSysteminfoError> {
        let filename = Path::new(path).file_name().ok_or_else(|| {
            RustSysteminfoError::IoError(Error::new(
                ErrorKind::NotFound,
                format!("Invalid sysctl path: {path}"),
            ))
        })?;
        Ok(filename.to_string_lossy().to_string())
    }

    fn skippable(filename: &str) -> bool {
        SKIPPABLE.contains(&filename)
    }
}

fn is_permission_denied(error: &RustSysteminfoError) -> bool {
    matches!(
        error,
        RustSysteminfoError::SafeIoError(RustSafeIoError::IoError(e)) if e.raw_os_error() == Some(13)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rex_test_utils::assertions::assert_error_contains;
    use rstest::rstest;
    use rust_safe_io::errors::RustSafeIoError;
    use std::io::Error;

    /// Given: A sysctl key in dot notation
    /// When: Converting the key to a file path
    /// Then: The key is converted to the correct /proc/sys path
    #[rstest]
    #[case("kernel.hostname", "/proc/sys/kernel/hostname")]
    #[case("net.ipv4.ip_forward", "/proc/sys/net/ipv4/ip_forward")]
    #[case("vm.swappiness", "/proc/sys/vm/swappiness")]
    fn test_key_to_path(#[case] key: &str, #[case] expected_path: &str) {
        assert_eq!(Sysctl::key_to_path(key), expected_path);
    }

    /// Given: A valid file path
    /// When: Extracting the parent directory path
    /// Then: The parent directory path is returned
    #[rstest]
    #[case("/proc/sys/kernel/hostname", "/proc/sys/kernel")]
    #[case("/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv4")]
    #[case("/a/b/c", "/a/b")]
    fn test_get_parent_path_valid(#[case] path: &str, #[case] expected_parent: &str) {
        let result = Sysctl::get_parent_path(path);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_parent);
    }

    /// Given: An invalid file path
    /// When: Extracting the parent directory path
    /// Then: A NotFound error is returned
    #[rstest]
    #[case("/")]
    #[case("")]
    fn test_get_parent_path_invalid(#[case] path: &str) {
        let result = Sysctl::get_parent_path(path);
        assert_error_contains(result, "Invalid sysctl path");
    }

    /// Given: A valid file path
    /// When: Extracting the filename
    /// Then: The filename is returned
    #[rstest]
    #[case("/proc/sys/kernel/hostname", "hostname")]
    #[case("/proc/sys/net/ipv4/ip_forward", "ip_forward")]
    #[case("/a/b/c", "c")]
    fn test_get_file_name_valid(#[case] path: &str, #[case] expected_filename: &str) {
        let result = Sysctl::get_file_name(path);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_filename);
    }

    /// Given: An invalid file path
    /// When: Extracting the filename
    /// Then: A NotFound error is returned
    #[rstest]
    #[case("/proc/sys/..")]
    #[case("/")]
    #[case("")]
    fn test_get_file_name_invalid(#[case] path: &str) {
        let result = Sysctl::get_file_name(path);
        assert_error_contains(result, "Invalid sysctl path");
    }

    /// Given: Various error types
    /// When: is_permission_denied is called
    /// Then: Returns true only for SafeIoError with errno 13
    #[rstest]
    #[case(
        RustSysteminfoError::SafeIoError(RustSafeIoError::IoError(Error::from_raw_os_error(13))),
        true
    )]
    #[case(
        RustSysteminfoError::SafeIoError(RustSafeIoError::IoError(Error::from_raw_os_error(1))),
        false
    )]
    #[case(RustSysteminfoError::InvalidParameter { key: "test".to_string() }, false)]
    fn test_is_permission_denied(#[case] error: RustSysteminfoError, #[case] expected: bool) {
        assert_eq!(is_permission_denied(&error), expected);
    }

    /// Given: Various filenames
    /// When: skippable is called
    /// Then: Returns true only for skippable parameters
    #[rstest]
    #[case("base_reachable_time", true)]
    #[case("retrans_time", true)]
    #[case("stat_refresh", true)]
    #[case("base_reachable_time_ms", false)]
    #[case("retrans_time_ms", false)]
    #[case("vm.stat_refresh", false)]
    #[case("stat_interval", false)]
    #[case("hostname", false)]
    fn test_skippable(#[case] filename: &str, #[case] expected: bool) {
        assert_eq!(Sysctl::skippable(filename), expected);
    }
}
