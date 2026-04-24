//! `cp` — Copy a file
//!
//! # Example (Rhai)
//! ```rhai
//! cp("/path/to/source.txt", "/path/to/dest.txt");
//! cp([cp::force, cp::preserve], "/path/to/source.txt", "/path/to/dest.txt");
//! ```

use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::Array;
use rhai_sdk_common_utils::args::{extract_flags, has_flag};
use rust_safe_io::errors::RustSafeIoError;
use rust_safe_io::options::{CopyFileOptionsBuilder, OpenFileOptionsBuilder};
use rust_safe_io::{DirConfigBuilder, options::OpenDirOptionsBuilder};
use std::path::Path;

/// Flags for the `cp` command.
#[derive(Debug, Clone)]
pub(crate) enum CpFlag {
    Force,
    Preserve,
}

struct CpOptions {
    force: bool,
    preserve: bool,
}

impl CpOptions {
    fn from_flags(flags: &[CpFlag]) -> Self {
        Self {
            force: has_flag(flags, |f| matches!(f, CpFlag::Force)),
            preserve: has_flag(flags, |f| matches!(f, CpFlag::Preserve)),
        }
    }
}

/// Copy a file from src to dst with default options.
pub(crate) fn cp(src: &str, dst: &str, cedar_auth: &CedarAuth) -> Result<(), RustSafeIoError> {
    cp_with_flags(src, dst, &Array::new(), cedar_auth)
}

/// Copy a file from src to dst with flags.
pub(crate) fn cp_with_flags(
    src: &str,
    dst: &str,
    flags_arr: &Array,
    cedar_auth: &CedarAuth,
) -> Result<(), RustSafeIoError> {
    let flags = extract_flags::<CpFlag>(flags_arr)?;
    let opts = CpOptions::from_flags(&flags);

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

    let dst_file = dst_dir_handle.safe_open_file(
        cedar_auth,
        &dst_name,
        OpenFileOptionsBuilder::default()
            .write(true)
            .create(true)
            .build()
            .map_err(|e| RustSafeIoError::InvalidArguments {
                reason: e.to_string(),
            })?,
    )?;

    let copy_opts = CopyFileOptionsBuilder::default()
        .force(opts.force)
        .preserve(opts.preserve)
        .build()
        .map_err(|e| RustSafeIoError::InvalidArguments {
            reason: e.to_string(),
        })?;

    src_file.safe_copy(cedar_auth, dst_file, copy_opts)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_fs::TempDir;
    use assert_fs::prelude::*;
    use rex_test_utils::rhai::common::create_default_test_cedar_auth;
    use std::fs;

    /// Given: A source file with content
    /// When: Copying to a new destination
    /// Then: The destination file has the same content
    #[test]
    fn test_cp_basic() {
        let temp = TempDir::new().unwrap();
        temp.child("src.txt").write_str("hello").unwrap();
        temp.child("dst.txt").write_str("").unwrap();
        let src = fs::canonicalize(temp.path().join("src.txt"))
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let dst = fs::canonicalize(temp.path().join("dst.txt"))
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let cedar_auth = create_default_test_cedar_auth();

        cp(&src, &dst, &cedar_auth).unwrap();
        assert_eq!(fs::read_to_string(&dst).unwrap(), "hello");
    }
}
