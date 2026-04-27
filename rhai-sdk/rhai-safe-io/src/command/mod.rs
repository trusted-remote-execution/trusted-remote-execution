//! Command implementations
//!
//! This module provides wrapper functions that implement common commands
//! by calling the underlying safe I/O functions with sensible defaults.
//!
//! These functions accept simple string paths (like real CLI commands) and
//! handle all the directory/file handle creation internally.
//!
//! Each command defines a flag enum registered as a Rhai custom type.
//! Flags come before arguments, mirroring CLI convention:
//! ```rhai
//! cat([cat::number], "/path")
//! ls([ls::all, ls::long], "/tmp")
//! grep([grep::ignore_case], "pattern", "/path")
//! tail([tail::n(5)], "/path")
//! ```

pub mod awk;
pub mod cat;
pub mod cp;
pub mod du;
pub mod glob;
pub mod grep;
pub mod ls;
pub mod mkdir;
pub mod mv;
pub mod rm;
pub mod sed;
pub mod seq;
pub mod tail;
pub mod touch;
pub mod wc;
pub mod write;

pub(crate) use awk::{
    awk_count_unique, awk_field, awk_filter, awk_filter_field, awk_filter_range, awk_split, awk_sum,
};
pub(crate) use cat::{CatFlag, cat, cat_with_flags};
pub(crate) use cp::{CpFlag, cp, cp_with_flags};
pub(crate) use du::{DuFlag, du, du_with_flags};
pub(crate) use glob::{GlobFlag, glob, glob_with_flags};
pub(crate) use grep::{GrepFlag, grep, grep_with_flags};
pub(crate) use ls::{LsFlag, ls_rhai, ls_rhai_with_flags};
pub(crate) use mkdir::{MkdirFlag, mkdir, mkdir_with_flags};
pub(crate) use mv::{MvFlag, mv, mv_with_flags};
pub(crate) use rm::{RmFlag, rm, rm_with_flags};
pub(crate) use sed::{SedFlag, sed, sed_with_flags};
pub(crate) use seq::{SeqFlag, seq, seq_with_flags};
pub(crate) use tail::{TailFlag, tail, tail_with_flags};
pub(crate) use touch::touch;
pub(crate) use wc::{WcFlag, wc, wc_with_flags};
pub(crate) use write::{WriteFlag, write, write_with_flags};

use rex_cedar_auth::cedar_auth::CedarAuth;
use rust_safe_io::{
    DirConfigBuilder, RcDirHandle, RcFileHandle,
    errors::RustSafeIoError,
    options::{OpenDirOptionsBuilder, OpenFileOptionsBuilder},
};
use std::path::Path;

/// Opens a directory from a path string
pub(crate) fn open_dir_from_path(
    path: &str,
    cedar_auth: &CedarAuth,
) -> Result<RcDirHandle, RustSafeIoError> {
    let config = DirConfigBuilder::default()
        .path(path.to_string())
        .build()
        .map_err(|e| RustSafeIoError::InvalidArguments {
            reason: e.to_string(),
        })?;

    let options = OpenDirOptionsBuilder::default()
        .follow_symlinks(true)
        .build()
        .map_err(|e| RustSafeIoError::InvalidArguments {
            reason: e.to_string(),
        })?;

    config.safe_open(cedar_auth, options)
}

/// Opens a file from a fully qualified path string
pub(crate) fn open_file_from_path(
    path: &str,
    cedar_auth: &CedarAuth,
) -> Result<RcFileHandle, RustSafeIoError> {
    let path_obj = Path::new(path);

    let dir_path = path_obj
        .parent()
        .map_or_else(|| ".".to_string(), |p| p.to_string_lossy().to_string());

    let file_name = path_obj
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .ok_or_else(|| RustSafeIoError::InvalidArguments {
            reason: format!("Invalid file path: {path}"),
        })?;

    let dir_handle = open_dir_from_path(&dir_path, cedar_auth)?;

    let file_options = OpenFileOptionsBuilder::default()
        .read(true)
        .build()
        .map_err(|e| RustSafeIoError::InvalidArguments {
            reason: e.to_string(),
        })?;

    dir_handle.safe_open_file(cedar_auth, &file_name, file_options)
}

/// Opens a file for writing, creating it if it doesn't exist.
pub(crate) fn open_writable(
    path: &str,
    cedar_auth: &CedarAuth,
) -> Result<RcFileHandle, RustSafeIoError> {
    let path_obj = Path::new(path);

    let dir_path = path_obj
        .parent()
        .map_or_else(|| ".".to_string(), |p| p.to_string_lossy().to_string());

    let file_name = path_obj
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .ok_or_else(|| RustSafeIoError::InvalidArguments {
            reason: format!("Invalid file path: {path}"),
        })?;

    let dir_handle = open_dir_from_path(&dir_path, cedar_auth)?;

    dir_handle.safe_open_file(
        cedar_auth,
        &file_name,
        OpenFileOptionsBuilder::default()
            .write(true)
            .create(true)
            .build()
            .map_err(|e| RustSafeIoError::InvalidArguments {
                reason: e.to_string(),
            })?,
    )
}
