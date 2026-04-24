//! `mv` — Move/rename a file
//!
//! # Example (Rhai)
//! ```rhai
//! mv("/path/to/old.txt", "/path/to/new.txt");
//!
//! // With backup
//! mv([mv::backup], "/path/to/old.txt", "/path/to/new.txt");
//! ```

use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::Array;
use rhai_sdk_common_utils::args::{extract_flags, has_flag};
use rust_safe_io::errors::RustSafeIoError;
use rust_safe_io::options::{MoveOptionsBuilder, OpenFileOptionsBuilder};
use rust_safe_io::{DirConfigBuilder, options::OpenDirOptionsBuilder};
use std::path::Path;

/// Flags for the `mv` command, registered as a Rhai custom type.
///
/// Available flags:
/// - `mv::backup` / `mv::b` — backup destination file if it exists
/// - `mv::verbose` / `mv::v` — log source and destination after move
#[derive(Debug, Clone)]
pub(crate) enum MvFlag {
    Backup,
    Verbose,
}

pub(crate) struct MvOptions {
    pub backup: bool,
    pub verbose: bool,
}

impl MvOptions {
    pub(crate) fn from_flags(flags: &[MvFlag]) -> Self {
        Self {
            backup: has_flag(flags, |f| matches!(f, MvFlag::Backup)),
            verbose: has_flag(flags, |f| matches!(f, MvFlag::Verbose)),
        }
    }
}

/// Move a file from src to dst.
pub(crate) fn mv(src: &str, dst: &str, cedar_auth: &CedarAuth) -> Result<(), RustSafeIoError> {
    mv_with_flags(src, dst, &Array::new(), cedar_auth)
}

/// Move a file from src to dst with user-provided flags.
pub(crate) fn mv_with_flags(
    src: &str,
    dst: &str,
    flags_arr: &Array,
    cedar_auth: &CedarAuth,
) -> Result<(), RustSafeIoError> {
    let flags = extract_flags::<MvFlag>(flags_arr)?;
    let opts = MvOptions::from_flags(&flags);

    let src_path = Path::new(src);
    let dst_path = Path::new(dst);

    let src_dir = src_path
        .parent()
        .map_or_else(|| ".".to_string(), |p| p.to_string_lossy().to_string());
    let src_name = src_path
        .file_name()
        .ok_or_else(|| RustSafeIoError::InvalidArguments {
            reason: format!("Invalid source path: {src}"),
        })?
        .to_string_lossy()
        .to_string();

    let dst_dir = dst_path
        .parent()
        .map_or_else(|| ".".to_string(), |p| p.to_string_lossy().to_string());
    let dst_name = dst_path
        .file_name()
        .ok_or_else(|| RustSafeIoError::InvalidArguments {
            reason: format!("Invalid destination path: {dst}"),
        })?
        .to_string_lossy()
        .to_string();

    let src_dir_handle = DirConfigBuilder::default()
        .path(src_dir)
        .build()
        .map_err(|e| RustSafeIoError::InvalidArguments {
            reason: e.to_string(),
        })?
        .safe_open(
            cedar_auth,
            OpenDirOptionsBuilder::default().build().map_err(|e| {
                RustSafeIoError::InvalidArguments {
                    reason: e.to_string(),
                }
            })?,
        )?;

    let src_file = src_dir_handle.safe_open_file(
        cedar_auth,
        &src_name,
        OpenFileOptionsBuilder::default()
            .read(true)
            .write(true)
            .build()
            .map_err(|e| RustSafeIoError::InvalidArguments {
                reason: e.to_string(),
            })?,
    )?;

    let dst_dir_handle = DirConfigBuilder::default()
        .path(dst_dir)
        .build()
        .map_err(|e| RustSafeIoError::InvalidArguments {
            reason: e.to_string(),
        })?
        .safe_open(
            cedar_auth,
            OpenDirOptionsBuilder::default().build().map_err(|e| {
                RustSafeIoError::InvalidArguments {
                    reason: e.to_string(),
                }
            })?,
        )?;

    let move_opts = MoveOptionsBuilder::default()
        .backup(opts.backup)
        .verbose(opts.verbose)
        .build()
        .map_err(|e| RustSafeIoError::InvalidArguments {
            reason: e.to_string(),
        })?;

    src_file.safe_move(cedar_auth, dst_dir_handle, &dst_name, move_opts)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_fs::TempDir;
    use assert_fs::prelude::*;
    use rex_test_utils::rhai::common::create_default_test_cedar_auth;
    use std::fs;

    /// Given: A source file
    /// When: Moving to a new location
    /// Then: The file exists at the new location and not the old
    #[test]
    fn test_mv_basic() {
        let temp = TempDir::new().unwrap();
        let canonical_temp = fs::canonicalize(temp.path()).unwrap();
        temp.child("old.txt").write_str("content").unwrap();
        let src = canonical_temp.join("old.txt").to_str().unwrap().to_string();
        let dst_path = canonical_temp.join("new.txt");
        let dst = dst_path.to_str().unwrap().to_string();
        let cedar_auth = create_default_test_cedar_auth();

        mv(&src, &dst, &cedar_auth).unwrap();
        assert!(dst_path.exists());
        assert!(!Path::new(&src).exists());
    }

    /// Given: An array with a non-MvFlag element
    /// When: Extracting flags
    /// Then: An error is returned
    #[test]
    fn test_mv_rejects_wrong_flag_type() {
        let temp = TempDir::new().unwrap();
        let canonical_temp = fs::canonicalize(temp.path()).unwrap();
        temp.child("a.txt").write_str("x").unwrap();
        let src = canonical_temp.join("a.txt").to_str().unwrap().to_string();
        let dst = canonical_temp.join("b.txt").to_str().unwrap().to_string();
        let cedar_auth = create_default_test_cedar_auth();
        let flags: Array = vec![rhai::Dynamic::from("not_a_flag")];

        let result = mv_with_flags(&src, &dst, &flags, &cedar_auth);
        assert!(result.is_err());
    }
}
