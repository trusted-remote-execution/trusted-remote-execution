//! Error types for filesystem operations
use anyhow::Error as AnyhowError;
#[cfg(target_os = "linux")]
use nix::errno::Errno;
#[cfg(target_os = "linux")]
use procfs::ProcError;
use rust_sdk_common_utils::cedar_auth::CedarAuthorizationError;
use std::error::Error as SourceError;
use std::io::Error as StdError;
use std::num::TryFromIntError;
use std::path::PathBuf;
use thiserror::Error;

/// Represents errors that can occur during filesystem operations
///
/// This enum provides specific error variants for different types of failures that can occur
/// during filesystem operations, including path validation, authorization checks, and system errors.
///
/// # Variants
///
/// * `AuthorizationError` - Error when authorization check fails
/// * `InvalidPath` - Error when a path is invalid, includes reason and optional path
/// * `PermissionDenied` - Error when an operation is not permitted
/// * `SystemError` - Error when a system error occurs
/// * `Other` - Anyhow for other errors
///
/// # Examples
///
/// ```no_run
/// use rust_safe_disk_info::RustDiskinfoError;
/// use std::path::PathBuf;
///
/// let error = RustDiskinfoError::InvalidPath {
///     reason: "Path contains invalid characters".to_string(),
///     path: PathBuf::from("/invalid/path")
/// };
/// ```
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum RustDiskinfoError {
    /// Error indicating permission denied
    ///
    /// # Fields
    ///
    /// * `principal` - The user/entity that was denied
    /// * `action` - The action that was attempted
    /// * `resource_type` - Type of resource that was accessed
    /// * `resource_id` - Identifier of the resource
    #[error(
        "Permission denied: {principal} unauthorized to perform {action} for {resource_type}::{resource_id}"
    )]
    PermissionDenied {
        principal: String,
        action: String,
        resource_type: String,
        resource_id: String,
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

    /// Error indicating a system error occurred
    ///
    /// # Fields
    ///
    /// * `reason` - Description of error
    /// * `source` - Underlying error that caused the failure
    #[error("System error occurred: {reason}")]
    SystemError {
        reason: String,
        #[source]
        source: Box<dyn SourceError + Send + Sync>,
    },

    /// Error indicating an invalid path
    ///
    /// # Fields
    ///
    /// * `reason` - Description of error
    /// * `path` - `PathBuf` of the invalid path
    #[error("Invalid filesystem path: {reason}")]
    InvalidPath { reason: String, path: PathBuf },

    /// Error indicating an unsupported operation
    ///
    /// # Fields
    ///
    /// * `operation` - The operation that is not supported
    /// * `reason` - Description of why the operation is not supported
    #[error("Unsupported operation '{operation}': {reason}")]
    UnsupportedOperationError { operation: String, reason: String },

    /// Error indicating unmount operation failed
    ///
    /// # Fields
    ///
    /// * `path` - Path to the mount point
    /// * `error` - Description of the unmount error
    #[error("Failed to unmount {path}: {error}")]
    UnmountError { path: String, error: String },

    /// Standard IO errors
    #[error(transparent)]
    IoError(#[from] StdError),

    /// Number conversion errors
    #[error(transparent)]
    TryFromIntError(#[from] TryFromIntError),

    // Nix errors
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    NixError(#[from] Errno),

    // Procfs errors
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    ProcReadError(#[from] ProcError),

    /// Anyhow for other errors
    #[error(transparent)]
    Other(#[from] AnyhowError),
}

impl CedarAuthorizationError for RustDiskinfoError {
    fn permission_denied(
        principal: String,
        action: String,
        resource_type: String,
        resource_id: String,
    ) -> Self {
        Self::PermissionDenied {
            principal,
            action,
            resource_type,
            resource_id,
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
