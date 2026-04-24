//! The error module defines various error types that can occur during safe IO operations
//!
//! The `RustSafeIoError` enum provides specific error variants for different failure scenarios,
//! including path validation, directory operations, and authorization checks

use crate::error_constants::{
    INVALID_REGEX_PATTERN_ERR, NOT_A_DIR, PATH_LED_OUTSIDE_FILESYSTEM, TOO_MANY_SYMLINKS,
};
use anyhow::Error as AnyhowError;
use derive_builder::UninitializedFieldError;
use regex::Error as RegexError;
use rust_sdk_common_utils::cedar_auth::CedarAuthorizationError;
use rust_sdk_common_utils::errors::RustCommonUtilsError;
use rustix::io::Errno;
use std::error::Error as SourceError;
use std::ffi::NulError;
use std::io::Error as StdError;
use std::num::{ParseIntError, TryFromIntError};
use std::path::PathBuf;
use std::str::Utf8Error;
use std::string::FromUtf8Error;
use thiserror::Error;

/// Represents errors that can occur during safe IO operations
///
/// This enum provides specific error variants for different types of failures that can occur
/// during safe IO operations, including path validation, directory operations, and authorization checks
///
/// # Variants
///
/// * `InvalidPath` - Error when a path is invalid, includes reason and optional path
/// * `PathTraversal` - Error when path traversal is detected, includes original and canonical paths
/// * `NonUtf8Path` - Error when a path contains non-UTF8 characters
/// * `DirectoryReadError` - Error when reading a directory fails
/// * `DirectoryCreateError` - Error when creating a directory fails
/// * `DirectoryOpenError` - Error when opening a directory fails
/// * `PermissionDenied` - Error when an operation is not permitted
/// * `AuthorizationError` - Error when authorization check fails
/// * `IoError` - Standard IO errors
/// * `Other` - Anyhow for other errors
///
/// # Examples
///
/// ```no_run
/// use rust_safe_io::errors::RustSafeIoError;
/// use std::path::PathBuf;
///
/// let error = RustSafeIoError::InvalidPath {
///     reason: "Path contains invalid characters".to_string(),
///     path: PathBuf::from("/invalid/path")
/// };
/// ```
/// Details for move operations in permission denied errors
#[derive(Debug)]
pub struct MoveDetails {
    pub source_resource_type: String,
    pub source_resource_id: String,
    pub dest_resource_type: String,
    pub dest_resource_id: String,
}

#[non_exhaustive]
#[derive(Error, Debug)]
pub enum RustSafeIoError {
    /// Error indicating an invalid path
    ///
    /// # Fields
    ///
    /// * `reason` - Description of error
    /// * `path` - `PathBuf` of the invalid path
    #[error("Invalid path: {reason}")]
    InvalidPath { reason: String, path: PathBuf },

    /// Error indicating an invalid options
    ///
    /// # Fields
    ///
    /// * `reason` - Description of error
    #[error("Invalid arguments: {reason}")]
    InvalidArguments { reason: String },

    /// Error indicating an invalid file mode
    ///
    /// # Fields
    ///
    /// * `reason` - Description of error
    /// * `path` - `PathBuf` of the invalid path
    #[error("Invalid file mode: {reason}: {path}")]
    InvalidFileMode { reason: String, path: PathBuf },

    /// Error indicating validation failed
    ///
    /// # Fields
    ///
    /// * `reason` - Description of error
    #[error("Validation error: {reason}")]
    ValidationError { reason: String },

    /// Error indicating failure to open directory
    ///
    /// # Fields
    ///
    /// * `reason` - Description of error
    /// * `path` - Path to the directory
    /// * `source` - Underlying error that caused the failure
    #[error("Directory error: {reason}: {path}")]
    DirectoryOpenError {
        reason: String,
        path: PathBuf,
        #[source]
        source: Box<dyn SourceError + Send + Sync>,
    },

    /// Error indicating directory operation failed
    ///
    /// # Fields
    ///
    /// * `reason` - Description of error
    /// * `path` - Path to the directory
    /// * `source` - Underlying error that caused the failure
    #[error("Directory error: {reason}: {path}")]
    DirectoryError {
        reason: String,
        path: PathBuf,
        #[source]
        source: Box<dyn SourceError + Send + Sync>,
    },

    /// Error indicating file operation failed
    ///
    /// # Fields
    ///
    /// * `reason` - Description of error
    /// * `path` - Path to the file
    /// * `source` - Underlying error that caused the failure
    #[error("File error: {reason}: {path}")]
    FileError {
        reason: String,
        path: PathBuf,
        #[source]
        source: Box<dyn SourceError + Send + Sync>,
    },

    /// Error indicating destination file is not empty during copy operation
    ///
    /// # Fields
    ///
    /// * `reason` - Description of error
    /// * `destination_path` - Path to the destination file that is not empty
    /// * `file_size` - Size of the existing destination file in bytes
    #[error("Destination file not empty: File: {destination_path}, Size: {file_size} bytes")]
    DestinationFileNotEmptyError {
        destination_path: PathBuf,
        file_size: u64,
    },

    /// Error indicating failure to find directory/file
    ///
    /// # Fields
    ///
    /// * `path` - Path to the directory/file
    /// * `source` - Underlying error that caused the failure
    #[error("No such file or directory found: {path}")]
    NotFound {
        path: PathBuf,
        #[source]
        source: Box<dyn SourceError + Send + Sync>,
    },

    /// Error indicating directory is not empty
    ///
    /// # Fields
    ///
    /// * `path` - Path to the directory
    /// * `source` - Underlying error that caused the failure
    #[error(
        "Directory not empty: A path led to a non-empty directory location. To include contents of this directory, use the recursive flag: {path}"
    )]
    DirectoryNotEmpty {
        path: PathBuf,
        #[source]
        source: Box<dyn SourceError + Send + Sync>,
    },

    /// Error indicating the file system entity is not recognized
    ///
    /// # Fields
    /// * `reason` - Description of error
    /// * `path` - Path to the file
    #[error("Invalid filesystem entity for open: {reason}: {path}")]
    InvalidFsEntity { reason: String, path: PathBuf },

    /// Error indicating permission denied
    ///
    /// # Fields
    ///
    /// * `principal` - The user/entity that was denied
    /// * `action` - The action that was attempted
    /// * `resource_type` - Type of resource that was accessed
    /// * `resource_id` - Identifier of the resource
    /// * `move_details` - Optional move-specific details for move operations
    #[error(
        "Permission denied: {principal} unauthorized to perform {action} for {resource_type}::{resource_id}"
    )]
    PermissionDenied {
        principal: String,
        action: String,
        resource_type: String,
        resource_id: String,
        move_details: Option<Box<MoveDetails>>,
    },

    /// Error indicating authorization check failure
    ///
    /// # Fields
    ///
    /// * `principal` - The user/entity that failed authorization
    /// * `action` - The action that was attempted
    /// * `resource_type` - Type of resource that was accessed
    /// * `resource_id` - Identifier of the resource
    #[error("Authorization check failed")]
    AuthorizationError {
        principal: String,
        action: String,
        resource_type: String,
        resource_id: String,
    },

    /// Error indicating failure to map an identifier to its corresponding name/value
    ///
    /// # Fields
    ///
    /// * `reason` - Description of error
    /// * `value` - The identifier value that failed to map
    #[error("Identity resolution error: {reason}: {value}")]
    IdentityResolutionError { reason: String, value: String },

    /// Error indicating that operation being used is not supoorted
    ///
    /// # Fields
    ///
    /// * `reason` - Description of error
    #[error("Unsupported Operation error: {reason}")]
    UnsupportedOperationError { reason: String },

    /// Error indicating that file content is too large
    ///
    /// # Fields
    ///
    /// * `reason` - Description of error
    /// * `content_size` - Size of the content being written in bytes
    /// * `block_size` - Maximum allowed block size in bytes
    /// * `path` - Path to the file where the error occurred
    #[error(
        "File content too large: {reason}. Content size: {content_size} bytes, Block size limit: {block_size} bytes, File: {path}"
    )]
    FileContentTooLargeError {
        reason: String,
        content_size: u64,
        block_size: u64,
        path: PathBuf,
    },

    /// Error indicating file copy operation failed
    ///
    /// # Fields
    ///
    /// * `source` - Underlying error that caused the failure
    #[error("File copy failed: {source}")]
    FileCopyError {
        #[source]
        source: Box<dyn SourceError + Send + Sync>,
    },

    /// Error indicating file read operation failed
    ///
    /// # Fields
    ///
    /// * `source` - Underlying error that caused the failure
    #[error("File read failed: {source}")]
    FileReadError {
        #[source]
        source: Box<dyn SourceError + Send + Sync>,
    },

    /// Error indicating directory entry is not the expected type
    ///
    /// # Fields
    ///
    /// * `reason` - Description of error
    #[error("Entry type mismatch: {reason}")]
    EntryTypeMismatchError { reason: String },

    /// Error indicating callback function failed
    ///
    /// # Fields
    ///
    /// * `reason` - Description of error
    /// * `source` - Underlying error that caused the failure
    #[error("{reason}")]
    CallbackError {
        reason: String,
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Error indicating process was terminated by signal
    ///
    /// # Fields
    ///
    /// * `signal` - The signal that terminated the process
    #[error("Process terminated by signal: {signal}")]
    ProcessTerminated { signal: String },

    /// Error indicating unexpected process status
    ///
    /// # Fields
    ///
    /// * `status` - The unexpected status
    #[error("Unexpected process status: {status}")]
    UnexpectedStatus { status: String },

    /// Error indicating capability operation failed
    ///
    /// # Fields
    ///
    /// * `reason` - Description of the capability error
    /// * `source` - Underlying error that caused the failure
    #[error("Capability error: {reason}")]
    CapabilityError {
        reason: String,
        #[source]
        source: Box<dyn SourceError + Send + Sync>,
    },

    /// Error indicating file descriptor operation failed
    ///
    /// # Fields
    ///
    /// * `reason` - Description of the file descriptor error
    #[error("File descriptor operation failed: {reason}")]
    FileDescriptorError { reason: String },

    /// Process namespace fatal error
    ///
    /// # Fields
    ///
    /// * `reason` - Detailed description of why the namespace operation failed
    #[error("Process namespace fatal error: {reason}")]
    ProcessNamespaceFatalError { reason: String },

    /// GDB invalid input error
    #[error("Invalid executable: {exe}")]
    InvalidExecutableError { exe: String },

    /// GDB output parsing error
    #[error("Unable to parse trace for executable {exe} and core file {core}")]
    InvalidTraceError { exe: String, core: String },

    /// Error indicating certificate parsing failed
    ///
    /// # Fields
    ///
    /// * `reason` - Description of the parsing error
    #[error("Certificate parse error: {reason}")]
    CertificateParseError { reason: String },

    /// Error indicating certificate chain verification failed
    ///
    /// # Fields
    ///
    /// * `reason` - Description of why verification failed
    #[error("Certificate verification error: {reason}")]
    CertificateVerificationError { reason: String },

    /// Standard IO errors
    #[error(transparent)]
    IoError(#[from] StdError),

    /// Number conversion errors
    #[error(transparent)]
    TryFromIntError(#[from] TryFromIntError),

    #[error(transparent)]
    ParseIntError(#[from] ParseIntError),

    /// Rustix errors
    #[error(transparent)]
    RustixError(#[from] Errno),

    /// UTF-8 conversion errors
    #[error(transparent)]
    Utf8Error(#[from] Utf8Error),

    // RustCommonUtilsError
    #[error(transparent)]
    RustCommonUtilsError(#[from] RustCommonUtilsError),

    #[error(transparent)]
    RegexError(#[from] RegexError),

    /// Anyhow for other errors
    #[error(transparent)]
    Other(#[from] AnyhowError),
}

impl From<UninitializedFieldError> for RustSafeIoError {
    fn from(value: UninitializedFieldError) -> Self {
        RustSafeIoError::InvalidArguments {
            reason: value.to_string(),
        }
    }
}

impl From<FromUtf8Error> for RustSafeIoError {
    fn from(err: FromUtf8Error) -> Self {
        RustSafeIoError::Utf8Error(err.utf8_error())
    }
}

impl From<String> for RustSafeIoError {
    fn from(err: String) -> Self {
        RustSafeIoError::Other(AnyhowError::msg(err))
    }
}

impl From<nix::Error> for RustSafeIoError {
    fn from(err: nix::Error) -> Self {
        RustSafeIoError::IoError(StdError::from(err))
    }
}

impl From<NulError> for RustSafeIoError {
    fn from(err: NulError) -> Self {
        RustSafeIoError::ValidationError {
            reason: format!("String contains null byte: {err}"),
        }
    }
}

impl CedarAuthorizationError for RustSafeIoError {
    fn permission_denied(
        principal: String,
        action: String,
        resource_type: String,
        resource_id: String,
    ) -> Self {
        // move_details is always None in the generic authorization path
        Self::PermissionDenied {
            principal,
            action,
            resource_type,
            resource_id,
            move_details: None,
        }
    }

    fn authorization_error(
        principal: String,
        action: String,
        resource_type: String,
        resource_id: String,
    ) -> Self {
        Self::AuthorizationError {
            principal,
            action,
            resource_type,
            resource_id,
        }
    }
}

impl RustSafeIoError {
    pub fn invalid_regex_err(pattern: &str, err: &RegexError) -> Self {
        RustSafeIoError::ValidationError {
            reason: format!("{INVALID_REGEX_PATTERN_ERR}: '{pattern}' - {err}"),
        }
    }
}

pub(crate) fn map_dir_symlink_error(err: StdError, path: &str) -> RustSafeIoError {
    if err.to_string().contains(PATH_LED_OUTSIDE_FILESYSTEM)
        || err.kind() == std::io::ErrorKind::NotADirectory
    {
        RustSafeIoError::DirectoryOpenError {
            reason: format!("{NOT_A_DIR}, enable follow_symlinks to open the target directory"),
            path: PathBuf::from(path),
            source: Box::new(err),
        }
    } else {
        err.into()
    }
}

pub(crate) fn map_file_symlink_error(err: StdError, path: &str) -> RustSafeIoError {
    let err_str = err.to_string();
    if err_str.contains(PATH_LED_OUTSIDE_FILESYSTEM) || err_str.contains(TOO_MANY_SYMLINKS) {
        RustSafeIoError::FileError {
            reason: "file is a symbolic link but follow_symlinks is not enabled".to_string(),
            path: PathBuf::from(path),
            source: Box::new(err),
        }
    } else {
        err.into()
    }
}

#[cfg(test)]
mod test {
    use super::RustSafeIoError;
    use std::ffi::CString;
    use std::io::ErrorKind;

    /// Given: a `FromUtf8Error`
    /// When: we create a `RustSafeIoError` from it
    /// Then: it creates a `RustSafeIoError::Utf8Error`
    #[test]
    fn test_from_utf8_error() {
        let result = String::from_utf8(vec![0, 159, 146, 150]);
        assert!(result.is_err());
        let err = RustSafeIoError::from(result.unwrap_err());

        // Here we don't really care what the inner values of Utf8Error are, just want to check that the type is correct
        assert!(matches!(err, RustSafeIoError::Utf8Error { .. }));
    }

    /// Given: a `nix::Error`
    /// When: we create a `RustSafeIoError` from it
    /// Then: it creates a `RustSafeIoError::IoError` containing the converted std::io::Error
    #[test]
    fn test_from_nix_error() {
        let nix_err = nix::Error::ENOENT;
        let rust_safe_io_err = RustSafeIoError::from(nix_err);
        match rust_safe_io_err {
            RustSafeIoError::IoError(io_err) => {
                assert_eq!(io_err.kind(), ErrorKind::NotFound);
            }
            _ => panic!("Expected IoError variant, got {:?}", rust_safe_io_err),
        }
    }

    /// Given: a `std::ffi::NulError`
    /// When: we create a `RustSafeIoError` from it
    /// Then: it creates a `RustSafeIoError::ValidationError` with appropriate message
    #[test]
    fn test_from_nul_error() {
        let result = CString::new("hello\0world");
        assert!(result.is_err());

        let nul_err = result.unwrap_err();
        let rust_safe_io_err = RustSafeIoError::from(nul_err);

        match rust_safe_io_err {
            RustSafeIoError::ValidationError { reason } => {
                assert!(
                    reason.starts_with("String contains null byte:"),
                    "Expected error message to start with 'String contains null byte:', got: {}",
                    reason
                );
                assert!(
                    reason.len() > "String contains null byte:".len(),
                    "Expected error message to contain NulError details, got: {}",
                    reason
                );
            }
            _ => panic!(
                "Expected ValidationError variant, got {:?}",
                rust_safe_io_err
            ),
        }
    }

    /// Given: RustSafeIoError certificate variants
    /// When: Converting the errors to strings
    /// Then: Should display the appropriate error messages
    #[test]
    fn test_certificate_error_display() {
        let parse_err = RustSafeIoError::CertificateParseError {
            reason: "test error".to_string(),
        };
        assert_eq!(parse_err.to_string(), "Certificate parse error: test error");

        let verify_err = RustSafeIoError::CertificateVerificationError {
            reason: "chain failed".to_string(),
        };
        assert_eq!(
            verify_err.to_string(),
            "Certificate verification error: chain failed"
        );
    }
}
