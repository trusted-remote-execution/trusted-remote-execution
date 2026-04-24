use cap_std::fs::Dir;
use std::fmt::{Display, Formatter, Result as FmtResult};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use crate::DirConfig;
use crate::error_constants::FILE_PATH_INVALID;
use crate::errors::RustSafeIoError;

/// A file descriptor handle for a directory, that has both the
/// opened directory [`Dir`] and its configurations [`DirConfig`].
///
/// # Fields
///
/// * `dir_config` - configuration parameters used to open the directory
/// * `dir_handle` - reference to [`Dir`] that is opened using [`DirConfig::safe_open()`]
#[derive(Debug)]
pub struct DirHandle {
    // [`DirConfig`] is kept private to enforce immutability of directory settings after creation.
    pub(crate) dir_config: DirConfig,
    pub(crate) dir: Dir,
    pub(crate) basename: String,
}

/// A wrapper around [`Rc<DirHandle>`].
///
/// By wrapping [`Rc<DirHandle>`], we can define methods that
/// operate on the reference-counted [`DirHandle`] directly.
/// This allows us to create functions that expect or return [`Rc<DirHandle>`],
/// ensuring that the reference counting is maintained throughout the API.
#[derive(Clone, Debug)]
pub struct RcDirHandle {
    pub(crate) dir_handle: Rc<DirHandle>,
}

impl PartialEq for RcDirHandle {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.dir_handle, &other.dir_handle)
    }
}

/// Displays the path this directory was opened with. If the path contained a symlink, this displays the unresolved path rather than the resolved path.
impl Display for RcDirHandle {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", &self.dir_handle.dir_config.path)
    }
}

impl RcDirHandle {
    pub(crate) fn basename(&self) -> &str {
        &self.dir_handle.basename
    }
}

/// Validates that `file_name_path` is a basename, i.e. a relative path with a single component.
/// This prevents access to parent directories: otherwise someone could get access by creating
/// a path like "../dir".
pub(crate) fn validate_is_basename(file_name_path: &Path) -> Result<(), RustSafeIoError> {
    if file_name_path.file_name().is_some() && file_name_path.parent() != Some(Path::new("")) {
        return Err(RustSafeIoError::InvalidPath {
            reason: FILE_PATH_INVALID.to_string(),
            path: PathBuf::from(&file_name_path),
        });
    }
    Ok(())
}

/// Resolves the actual filesystem path from an open file descriptor.
///
/// This function uses `/proc/self/fd` to determine the real path that an open
/// file descriptor points to, which is useful for symlink resolution and
/// security validation. This approach is TOCTOU-safe because it queries
/// the already-opened file descriptor rather than re-resolving paths.
#[cfg(target_os = "linux")]
pub(crate) fn get_resolved_path_from_fd<T: AsRawFd>(
    fd_holder: &T,
) -> Result<String, RustSafeIoError> {
    let fd = fd_holder.as_raw_fd();
    let proc_dir = Dir::open_ambient_dir("/proc/self/fd", cap_std::ambient_authority())?;

    let fd_str = fd.to_string();
    let target_path = proc_dir.read_link_contents(&fd_str)?;
    Ok(target_path.to_string_lossy().to_string())
}

#[cfg(target_os = "macos")]
pub(crate) fn get_resolved_path_from_fd<T: std::os::fd::AsRawFd>(
    fd_holder: &T,
) -> Result<String, RustSafeIoError> {
    use std::ffi::CStr;
    let fd = fd_holder.as_raw_fd();
    // PATH_MAX on macOS is 1024; use a vec so we don't blow the stack.
    let mut buf: Vec<libc::c_char> = vec![0; libc::PATH_MAX as usize];
    // SAFETY: buf is valid, correctly sized, and fd is an open file descriptor.
    if unsafe { libc::fcntl(fd, libc::F_GETPATH, buf.as_mut_ptr()) } == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: fcntl(F_GETPATH) fills buf with a null-terminated UTF-8 path.
    let path = unsafe { CStr::from_ptr(buf.as_ptr()) };
    Ok(path.to_string_lossy().to_string())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn get_resolved_path_from_fd<T>(_fd_holder: &T) -> Result<String, RustSafeIoError> {
    Err(RustSafeIoError::UnsupportedOperationError {
        reason: "Symlink resolution not supported on this platform".to_string(),
    })
}
