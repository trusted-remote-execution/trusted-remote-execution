use anyhow::Result;
use cap_std::fs::File;
use rex_cedar_auth::fs::FileEntity;
use rex_cedar_auth::fs::actions::FilesystemAction;
use std::collections::VecDeque;
use std::io::Seek;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
use std::path::PathBuf;
use std::rc::Rc;

use crate::constants::REDACTION_DICTIONARY;
use crate::error_constants::{
    READ_FILE_FLAG_ERR, READ_ONLY_FILE_FLAG_ERR, SPECIAL_FILE_ATOMIC_WRITE_ERR, WRITE_FILE_FLAG_ERR,
};
use crate::errors::RustSafeIoError;
use crate::options::OpenFileOptions;
use crate::{DirHandle, build_path, is_authorized};
use rex_cedar_auth::cedar_auth::CedarAuth;

/// Represents the determined read mode after authorization checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadMode {
    Full,
    Redacted,
}

macro_rules! zeros {
    ($size:expr) => {
        vec![0; $size]
    };
}

pub(crate) use zeros;

/// Streams lines with optional skip and take, enabling early exit.
/// - `skip`: number of lines to skip from the start (0-indexed; lines 1..=skip are excluded)
/// - `take`: if Some(n), take at most n lines; if None, take all remaining
pub(crate) fn stream_lines_range<I>(
    lines: I,
    skip: usize,
    take: Option<usize>,
) -> std::result::Result<Vec<String>, std::io::Error>
where
    I: Iterator<Item = std::result::Result<String, std::io::Error>>,
{
    let skipped = lines.skip(skip);
    match take {
        Some(n) => skipped.take(n).collect(),
        None => skipped.collect(),
    }
}

/// Collects the last N items from an iterator using a ring buffer.
/// - `count`: number of items to keep in the buffer
/// - `end_idx`: if Some(n), stop after index n (0-indexed); if None, scan to end
///
/// This is memory-efficient for tail operations on non-seekable streams
/// since it only keeps the last N items in memory.
pub(crate) fn collect_last_n<T>(
    items: impl Iterator<Item = T>,
    count: usize,
    end_idx: Option<usize>,
) -> Vec<T> {
    let mut buffer: VecDeque<T> = VecDeque::with_capacity(count);
    for (idx, item) in items.enumerate() {
        if let Some(end) = end_idx
            && idx >= end
        {
            break;
        }
        if buffer.len() >= count {
            buffer.pop_front();
        }
        buffer.push_back(item);
    }
    buffer.into_iter().collect()
}

/// Represents a file handle containing a reference to a file, its path, and associated directory handle.
#[derive(Debug)]
pub struct FileHandle {
    pub(crate) file: File,
    pub(crate) file_path: String,
    pub(crate) resolved_path: Option<String>,
    pub(crate) dir_handle: Rc<DirHandle>,
    pub(crate) open_options: OpenFileOptions,
}

/// A wrapper around [`Rc<FileHandle>`].
///
/// By wrapping [`Rc<FileHandle>`], we can define methods that
/// operate on the reference-counted [`FileHandle`] directly.
/// This allows us to create functions that expect or return [`Rc<FileHandle>`],
/// ensuring that the reference counting is maintained throughout the API.
#[derive(Clone, Debug)]
pub struct RcFileHandle {
    pub(crate) file_handle: Rc<FileHandle>,
}

impl PartialEq for RcFileHandle {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.file_handle, &other.file_handle)
    }
}

impl RcFileHandle {
    /// Validates that the file handle was opened with the `write` option. Returns `Ok` when the file was opened with the write option
    /// and `Err` when the file was not opened with the write option.
    pub(crate) fn validate_write_open_option(&self) -> Result<(), RustSafeIoError> {
        if !(&self.file_handle.open_options.write) {
            return Err(RustSafeIoError::InvalidFileMode {
                reason: WRITE_FILE_FLAG_ERR.to_string(),
                path: PathBuf::from(&self.full_path()),
            });
        }
        Ok(())
    }

    /// Validates that the `special_file` option is not set. Returns `Ok` when `special_file` is false
    /// and `Err` when `special_file` is true (only valid for `safe_write_in_place`).
    pub(crate) fn validate_special_file_option(&self) -> Result<(), RustSafeIoError> {
        if self.file_handle.open_options.special_file {
            return Err(RustSafeIoError::InvalidFileMode {
                reason: SPECIAL_FILE_ATOMIC_WRITE_ERR.to_string(),
                path: PathBuf::from(&self.full_path()),
            });
        }
        Ok(())
    }

    /// Returns a reference to the path of the opened file
    ///
    /// # Returns
    /// * `&str` - A reference to the path
    #[allow(clippy::missing_const_for_fn)]
    pub fn path(&self) -> &str {
        &self.file_handle.file_path
    }

    /// Returns a reference to the directory that the file is in
    ///
    /// # Returns
    /// * `&str` - a reference to the directory path
    #[allow(clippy::missing_const_for_fn)]
    pub(crate) fn dir_path(&self) -> &str {
        &self.file_handle.dir_handle.dir_config.path
    }

    /// Returns the full file path for Cedar authorization and operations.
    ///
    /// This method provides the appropriate path based on how the file was opened:
    /// - For files opened with `follow_symlinks=true`: Returns the cached resolved target path
    /// - For regular files and non-followed symlinks: Returns the original path
    pub(crate) fn full_path(&self) -> String {
        self.file_handle
            .resolved_path
            .as_ref()
            .map_or_else(|| build_path(self.dir_path(), self.path()), Clone::clone)
    }

    /// Validates that the file handle was opened with read permissions
    pub(crate) fn validate_read_open_option(
        &self,
        cedar_auth: &CedarAuth,
    ) -> Result<(), RustSafeIoError> {
        // In case the user opened without the read action, let's double check the correct
        // Cedar permission
        is_authorized(
            cedar_auth,
            &FilesystemAction::Read,
            &FileEntity::from_string_path(&self.full_path())?,
        )?;

        self.file_handle
            .open_options
            .read
            .then_some(())
            .ok_or_else(|| RustSafeIoError::InvalidFileMode {
                reason: READ_FILE_FLAG_ERR.to_string(),
                path: PathBuf::from(&self.full_path()),
            })
    }

    /// Validates that the file handle was opened read-only
    ///
    /// This is required for operations like fexecve that requires `O_RDONLY` file descriptors.
    pub(crate) fn validate_read_only_open_option(&self) -> Result<(), RustSafeIoError> {
        if self.file_handle.open_options.write {
            return Err(RustSafeIoError::InvalidFileMode {
                reason: READ_ONLY_FILE_FLAG_ERR.to_string(),
                path: PathBuf::from(&self.full_path()),
            });
        }

        Ok(())
    }
    pub(crate) fn validate_redacted_read_action(
        &self,
        cedar_auth: &CedarAuth,
    ) -> Result<(), RustSafeIoError> {
        is_authorized(
            cedar_auth,
            &FilesystemAction::RedactedRead,
            &FileEntity::from_string_path(&self.full_path())?,
        )
    }

    /// Determines the read mode based on authorization.
    ///
    /// Checks Read permission first, then falls back to `RedactedRead`.
    /// Guards against `RedactedRead` on the redaction dictionary itself
    /// to prevent information leakage about the redaction patterns.
    pub(crate) fn determine_read_mode(
        &self,
        cedar_auth: &CedarAuth,
    ) -> Result<ReadMode, RustSafeIoError> {
        let read_err = match self.validate_read_open_option(cedar_auth) {
            Ok(()) => return Ok(ReadMode::Full),
            Err(e) => e,
        };

        if self.validate_redacted_read_action(cedar_auth).is_ok() {
            // Guard against recursive redaction of the dictionary file itself

            if self.full_path() == REDACTION_DICTIONARY {
                return Err(RustSafeIoError::UnsupportedOperationError {
                    reason:
                        "Trying to redacted_read the redaction dictionary is not supported/allowed"
                            .to_string(),
                });
            }

            return Ok(ReadMode::Redacted);
        }

        // Neither permission - fallback to the normal read authorization error
        Err(read_err)
    }

    /// Rewinds the file position to the beginning.
    ///
    /// This allows the file to be read again from the start after a read or write operation.
    /// Uses interior mutability through the underlying file descriptor, which allows
    /// seeking on a shared reference.
    pub(crate) fn rewind(&self) -> Result<(), RustSafeIoError> {
        let mut file = &self.file_handle.file;
        file.rewind()?;
        Ok(())
    }
}

impl AsRawFd for RcFileHandle {
    fn as_raw_fd(&self) -> RawFd {
        self.file_handle.file.as_raw_fd()
    }
}

impl AsFd for RcFileHandle {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file_handle.file.as_fd()
    }
}
