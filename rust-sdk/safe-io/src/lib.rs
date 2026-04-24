//! The rust safe IO crate provides capstd exposed wrappers
//! for IO operations such as write and read. All APIs operate
//! on capstd's file descriptors via [`cap_std::fs::File`] and [`cap_std::fs::Dir`]
//!
//! The implementations rely on cap-std. You can learn
//! more about the crate here: `<https://blog.sunfishcode.online/introducing-cap-std>`

use anyhow::Result;
use cfg_if::cfg_if;
use derive_getters::Getters;
use regex::Regex;

use rex_logger::debug;

#[cfg(target_os = "linux")]
use rustix::fs::{AtFlags, Gid, Uid, chownat};
#[cfg(target_os = "linux")]
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use sysinfo::{Groups, Users};

pub mod constants;
pub mod dir_entry;
pub mod errors;
pub mod execute;
pub mod options;
pub(crate) mod utils;

mod file;
pub use file::{FileHandle, Match, RcFileHandle, WordCount, gzip};

#[cfg(target_os = "linux")]
pub use file::truncate;

#[cfg(target_os = "linux")]
pub use options::{DiskAllocationOptions, DiskAllocationOptionsBuilder};

#[cfg(target_os = "linux")]
pub use options::{SetXAttrOptions, SetXAttrOptionsBuilder};

#[cfg(target_os = "linux")]
pub use file::elf_info::ElfInfo;

mod dir;
pub use dir::{DirConfig, DirConfigBuilder, DirHandle, RcDirHandle};

#[cfg(unix)]
pub use dir::{DiskUsageEntry, DiskUsageResult};

mod symlink;
pub use symlink::{RcSymlinkHandle, SymlinkHandle};

pub(crate) mod auth;
pub(crate) use self::auth::{is_authorized, is_authorized_with_context};

pub(crate) mod recursive;
pub use self::recursive::{DirWalk, WalkEntry};

// Export GDB functionality
cfg_if! {
    if #[cfg(target_os = "linux")] { // safe_exec is only supported on linux for now
        mod core_dump_analysis;
        pub use core_dump_analysis::{parse_backtrace_output, CoreDump, Frame, TracedProcess, TracedThread};
    }
}

pub(crate) mod redaction;

pub use constants::CHUNK_SIZE;
pub use constants::error_constants::{
    self, CHOWN_CAP_REQUIRED_ERR, DEST_FILE_NOT_EMPTY_ERR, DIR_DNE_ERR, DIR_NED_ERR,
    FAILED_CREATE_DIR, FAILED_OPEN_DIR, FAILED_OPEN_FILE, FAILED_OPEN_LEAF, FAILED_OPEN_PARENT,
    FILE_DNE_ERR, FILE_PATH_INVALID, INVALID_GLOB_PATTERN_ERR, INVALID_OPEN_FILE_OPTIONS,
    INVALID_PERMISSIONS_ERR, INVALID_REGEX_PATTERN_ERR, LEAF_PATH_INVALID, NO_GROUP_MAPPING_ERR,
    NO_READ_LINE_MODE_SPECIFIED_ERR, NO_USER_MAPPING_ERR, PARENT_PATH_INVALID,
    PATH_COMPONENT_NOT_UTF8, PATH_TRAVERSAL, PATH_TRAVERSAL_DETECTED, READ_FILE_FLAG_ERR,
    SPECIAL_FILE_ATOMIC_WRITE_ERR, SPECIAL_FILE_REQUIRES_WRITE_ERR, WRITE_FILE_FLAG_ERR,
};
pub use dir_entry::{DirEntry, Metadata};
use errors::RustSafeIoError;

use options::ReplacementOptions;

/// Represents the ownership information of a filesystem object (dir or file).
#[derive(Clone, Debug, Getters)]
pub struct Ownership {
    #[getter(rename = "user")]
    owner: String,
    group: String,
}

/// Validates that permissions are within the valid range (0o000 to 0o777)
fn validate_permissions(permissions: u32) -> Result<(), RustSafeIoError> {
    if permissions > 0o777 {
        return Err(RustSafeIoError::ValidationError {
            reason: format!("{INVALID_PERMISSIONS_ERR}: {permissions:#o}"),
        });
    }
    Ok(())
}

/// Builds a file path by joining directory path and file name
fn build_path(dir_path: &str, file_name: &str) -> String {
    Path::new(dir_path)
        .join(file_name)
        .to_string_lossy()
        .to_string()
}

/// Get basename from a path
fn get_basename(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map(|os_str| os_str.to_string_lossy().to_string())
        .unwrap_or_default()
}

/// Get parent directory from a path
fn get_parent(path: &str) -> String {
    Path::new(path)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default()
}

/// Change the user and group ownership on a file descriptor using raw uid/gid.
///
/// Errors:
/// * The caller doesn't have OS permission to chown the target fd (e.g. missing `CAP_CHOWN`)
#[cfg(target_os = "linux")]
fn chown_fd<Fd: AsFd>(fd: Fd, uid: Option<Uid>, gid: Option<Gid>) -> Result<(), RustSafeIoError> {
    chownat(
        fd,
        "",
        uid,
        gid,
        AtFlags::SYMLINK_NOFOLLOW | AtFlags::EMPTY_PATH,
    )
    .map_err(|e| {
        if e == rustix::io::Errno::PERM {
            RustSafeIoError::IoError(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                CHOWN_CAP_REQUIRED_ERR,
            ))
        } else {
            e.into()
        }
    })
}

/// Change the user and group ownership on a file descriptor by username/group name.
/// NB: to obtain a file descriptor to a symlink, open the symlink using the `O_PATH` and `O_NOFOLLOW` flags.
/// If neither user nor group is provided, this function does effectively nothing.
///
/// Errors:
/// * If user or group parameters are invalid (e.g. the group doesn't exist)
/// * The caller doesn't have OS permission to chown the target fd
#[cfg(target_os = "linux")]
fn set_ownership_inner<Fd: AsFd>(
    fd: Fd,
    user: Option<String>,
    group: Option<String>,
) -> Result<(), RustSafeIoError> {
    let user = user
        .map(|user| {
            Users::new_with_refreshed_list()
                .list()
                .iter()
                .find(|u| u.name() == user)
                .map(|u| Uid::from_raw(**u.id()))
                .ok_or_else(|| RustSafeIoError::IdentityResolutionError {
                    reason: NO_USER_MAPPING_ERR.to_string(),
                    value: user.clone(),
                })
        })
        .transpose()?;

    let group = group
        .map(|group| {
            Groups::new_with_refreshed_list()
                .list()
                .iter()
                .find(|g| g.name() == group)
                .map(|g| Gid::from_raw(**g.id()))
                .ok_or_else(|| RustSafeIoError::IdentityResolutionError {
                    reason: NO_GROUP_MAPPING_ERR.to_string(),
                    value: group.clone(),
                })
        })
        .transpose()?;

    chown_fd(fd, user, group)
}

/// Looks up the username and group name for the given user ID and group ID.
///
/// # Arguments
///
/// * `uid` - The user ID to look up
/// * `gid` - The group ID to look up
///
/// # Returns
///
/// * `Result<(String, String)>` - The username and group name
///
/// # Errors
///
/// * No mapping found for user ID
/// * No mapping found for group ID
#[cfg(unix)]
fn get_user_and_group_names(uid: u32, gid: u32) -> Result<(String, String), RustSafeIoError> {
    let users = Users::new_with_refreshed_list();
    let groups = Groups::new_with_refreshed_list();

    let uid_str = uid.to_string();
    let gid_str = gid.to_string();

    let username = users
        .list()
        .iter()
        .find(|user| user.id().to_string() == uid_str)
        .ok_or_else(|| RustSafeIoError::IdentityResolutionError {
            reason: NO_USER_MAPPING_ERR.to_string(),
            value: uid_str.clone(),
        })?
        .name()
        .to_string();

    let groupname = groups
        .list()
        .iter()
        .find(|group| group.id().to_string() == gid_str)
        .ok_or_else(|| RustSafeIoError::IdentityResolutionError {
            reason: NO_GROUP_MAPPING_ERR.to_string(),
            value: gid_str.clone(),
        })?
        .name()
        .to_string();

    Ok((username, groupname))
}

// checks the path for traversal and returns an error
// if path traversal is detected.
//
// n.b. - this is not safe from TOCTOU detection of
// symlinks and is only used to detect a path traversal in a path name like "../dir".
fn check_for_traversal(path: &Path) -> Result<(), RustSafeIoError> {
    let orig_path = PathBuf::from(path);
    let can_path = orig_path.canonicalize()?;

    if orig_path != can_path {
        return Err(RustSafeIoError::InvalidPath {
            reason: format!(
                "path traversal detected: original path '{}' does not match canonical path '{}'",
                orig_path.display(),
                can_path.display()
            ),
            path: PathBuf::from(&path),
        });
    }
    Ok(())
}

/// Replaces text using either string matching or [rust regex patterns](https://docs.rs/regex/latest/regex/)
///
/// # Arguments
/// * `text` - The input text to search and replace in
/// * `old_string` - The pattern to search for (string or regex)
/// * `new_string` - The replacement text
/// * `replacement_options` - Options controlling the replacement behavior
///
/// # Returns
/// * `Result<String>` - The text with replacements applied
///
/// # Errors
/// * Returns error if regex pattern is invalid when `replacement_options.is_regex` is true
///
/// # Regex Pattern Note
///
/// This function uses the Rust `regex` crate, which does not support PCRE's `\K` (keep) assertion.
/// To achieve the same effect, remove `\K` and wrap the text you want to capture in parentheses `()`.
///
/// Example:
/// ```no_run
/// // PCRE pattern with \K (not supported)
/// // "execfn: '\K[^']+"
///
/// // Equivalent Rust regex pattern
/// // "execfn: '([^']+)"
///```
///
/// # Replacement Syntax
///
/// When using captured groups in the replacement string, use `$1`, `$2`, etc. (not `\1`, `\2` as in PCRE/sed).
///
/// Example:
/// ```rust
/// # use rust_safe_io::{replace_text, options::ReplacementOptionsBuilder};
/// let pattern = r"execfn: '([^']+)'";
/// let replacement = "$1";  // Use $1, not \1
/// let options = ReplacementOptionsBuilder::default()
///     .is_regex(true)
///     .build()
///     .unwrap();
///
/// let result = replace_text("execfn: 'myapp'", pattern, replacement, options).unwrap();
/// assert_eq!(result, "myapp");
/// ```
pub fn replace_text(
    text: &str,
    old_string: &str,
    new_string: &str,
    replacement_options: ReplacementOptions,
) -> Result<String, RustSafeIoError> {
    let modified_content = if replacement_options.is_regex {
        let re = Regex::new(old_string)
            .map_err(|e| RustSafeIoError::invalid_regex_err(old_string, &e))?;

        match (replacement_options.replace_all, re.is_match(text)) {
            (true, true) => re.replace_all(text, new_string).to_string(),
            (false, true) => re.replace(text, new_string).to_string(),
            _ => text.to_string(),
        }
    } else {
        match (replacement_options.replace_all, text.contains(old_string)) {
            (true, true) => text.replace(old_string, new_string),
            (false, true) => text.replacen(old_string, new_string, 1),
            _ => text.to_string(),
        }
    };

    debug!("{modified_content}");

    Ok(modified_content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Result, anyhow};
    use rex_test_utils::{assertions::assert_error_contains, io::create_temp_dir_and_path};
    use rstest::rstest;
    #[cfg(target_os = "linux")]
    use std::fs;
    use std::path::Path;

    /// Given: A path with traversal components
    /// When: Checking for path traversal on the constructed path
    /// Then: The check should detect the traversal and return an error
    #[test]
    fn test_path_traversal_detected() -> Result<()> {
        let (_temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
        let dir_path = Path::new(&temp_dir_path);
        let dir_name = dir_path
            .file_name()
            .ok_or_else(|| anyhow!("cannot extract dirname"))?
            .to_string_lossy()
            .to_string();
        let mut path_with_traversal = dir_path.join("..");
        path_with_traversal.push(dir_name);

        let result = check_for_traversal(&path_with_traversal);

        assert_error_contains(result, PATH_TRAVERSAL_DETECTED);
        Ok(())
    }

    /// Given: Different combinations of valid/invalid user and group IDs
    /// When: Attempting to get username and groupname mappings
    /// Then: Should return appropriate MappingError based on which ID is invalid
    #[rstest]
    #[case(u32::MAX, 0, NO_USER_MAPPING_ERR, u32::MAX.to_string())]
    #[cfg_attr(not(target_vendor = "apple"), case(0, u32::MAX, NO_GROUP_MAPPING_ERR, u32::MAX.to_string()))]
    fn test_get_user_and_group_names_invalid_mappings(
        #[case] uid: u32,
        #[case] gid: u32,
        #[case] expected_error: &str,
        #[case] expected_value: String,
    ) {
        let result = get_user_and_group_names(uid, gid);

        assert!(result.is_err());
        if let Err(e) = result {
            match e {
                RustSafeIoError::IdentityResolutionError { reason, value } => {
                    assert_eq!(reason, expected_error);
                    assert_eq!(value, expected_value);
                }
                other => panic!("Expected MappingError, got {:?}", other),
            }
        }
    }

    /// Given: Different combinations of valid/invalid user and group names
    /// When: Attempting to set ownership with invalid user or group names
    /// Then: Should return appropriate IdentityResolutionError based on which name is invalid
    #[rstest]
    #[case(Some("nonexistent_user".to_string()), None, NO_USER_MAPPING_ERR, "nonexistent_user")]
    #[case(None, Some("nonexistent_group".to_string()), NO_GROUP_MAPPING_ERR, "nonexistent_group")]
    #[cfg(target_os = "linux")]
    fn test_set_ownership_inner_invalid_names(
        #[case] user: Option<String>,
        #[case] group: Option<String>,
        #[case] expected_error: &str,
        #[case] expected_value: &str,
    ) -> Result<()> {
        // Create a temporary file to test with
        let (temp_dir, _temp_dir_path) = create_temp_dir_and_path()?;
        let test_file_path = temp_dir.path().join("test_file.txt");
        fs::write(&test_file_path, "test content")?;

        let file = fs::File::open(&test_file_path)?;

        let result = set_ownership_inner(&file, user, group);

        assert!(result.is_err());
        if let Err(e) = result {
            match e {
                RustSafeIoError::IdentityResolutionError { reason, value } => {
                    assert_eq!(reason, expected_error);
                    assert_eq!(value, expected_value);
                }
                other => panic!("Expected IdentityResolutionError, got {:?}", other),
            }
        }

        temp_dir.close()?;
        Ok(())
    }
}
