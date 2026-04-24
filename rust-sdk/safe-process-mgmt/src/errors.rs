//! The error module defines various error types that can occur during safe process management operations
//!
//! The `RustSafeProcessMgmtError` enum provides specific error variants for different failure scenarios,
//! including process operations, namespace operations, and authorization checks

use anyhow::Error as AnyhowError;
use rust_safe_io::errors::RustSafeIoError;
use rust_sdk_common_utils::cedar_auth::CedarAuthorizationError;
use thiserror::Error;

/// Represents errors that can occur during safe process management operations
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum RustSafeProcessMgmtError {
    /// Error indicating a process was not found
    ///
    /// # Fields
    ///
    /// * `reason` - Description of error
    /// * `pid` - Process ID that was not found
    #[error("Process not found: {reason}: PID {pid}")]
    ProcessNotFound { reason: String, pid: u32 },

    /// Error indicating a namespace was not found
    ///
    /// # Fields
    ///
    /// * `reason` - Description of error
    /// * `pid` - Process ID that was not found
    #[error("PID namespace not found for PID {pid}: {reason}")]
    PidNamespaceNotFound { reason: String, pid: u32 },

    /// Error indicating pid namespace operation failed
    ///
    /// # Fields
    ///
    /// * `reason` - Description of error
    /// * `error` - The underlying error message
    /// * `pid` - Process ID for the namespace operation
    #[error("Namespace operation failed: {reason}: {error}: PID {pid}")]
    PidNamespaceOperationError {
        reason: String,
        error: String,
        pid: u32,
    },

    /// Error indicating namespace operation failed
    ///
    /// # Fields
    ///
    /// * `reason` - Description of error
    /// * `error` - The underlying error message
    #[error("Namespace operation failed: {reason}: {error}")]
    NamespaceOperationError { reason: String, error: String },

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

    /// Error indicating validation failed
    ///
    /// # Fields
    ///
    /// * `reason` - Description of error
    #[error("Validation error: {reason}")]
    ValidationError { reason: String },

    /// Error indicating callback execution failed
    ///
    /// # Fields
    ///
    /// * `message` - The callback error message
    #[error("Callback execution failed: {message}")]
    CallbackExecutionError { message: String },

    /// Error indicating process enumeration failed
    ///
    /// # Fields
    ///
    /// * `message` - Description of the enumeration error
    #[error("Process enumeration failed: {message}")]
    ProcessEnumerationError { message: String },

    /// Error indicating file descriptor operation failed
    ///
    /// # Fields
    ///
    /// * `message` - Description of the file descriptor error
    #[error("File descriptor operation failed: {message}")]
    FileDescriptorError { message: String },

    /// D-Bus communication error
    #[error("{message}")]
    DBusError { message: String },

    /// Privilege management error
    #[error("{message}")]
    PrivilegeError { message: String },

    /// Service not found
    #[error("Unit: {service}")]
    ServiceNotFound { service: String },

    /// Error indicating process tracing failed
    ///
    /// # Fields
    ///
    /// * `pid` - Process ID that failed to be traced
    /// * `reason` - Error details
    #[error("Unable to trace process {pid}. Error details: {reason}")]
    TracingError { pid: u32, reason: String },

    /// Error indicating pstack returned empty output. Typically this occurs if the user doesn't have the `CAP_SYS_PTRACE` capability set.
    #[error(
        "Attempting to trace pid {pid} returned empty output. Likely you need to set the CAP_SYS_PTRACE linux capability."
    )]
    TraceEmptyError { pid: u32 },

    /// Error indicating insufficient permissions to trace a process. This occurs on AL2023
    /// where the user doesn't have the `CAP_SYS_PTRACE` capability set.
    ///
    /// # Fields
    ///
    /// * `pid` - Process ID that failed to be traced
    #[error(
        "Unable to trace process {pid}. Likely you need to set the CAP_SYS_PTRACE linux capability."
    )]
    TracePermissionError { pid: u32 },

    /// Error when getting or setting capabilities
    #[error(transparent)]
    CapsError(#[from] caps::errors::CapsError),

    /// `RustSafeIO` errors
    #[error(transparent)]
    SafeIoError(#[from] RustSafeIoError),

    /// Anyhow for other errors
    #[error(transparent)]
    Other(#[from] AnyhowError),

    /// Error indicating builder validation failed
    #[error(transparent)]
    BuilderError(#[from] derive_builder::UninitializedFieldError),
}

impl CedarAuthorizationError for RustSafeProcessMgmtError {
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

impl From<zbus::Error> for RustSafeProcessMgmtError {
    fn from(e: zbus::Error) -> Self {
        RustSafeProcessMgmtError::DBusError {
            message: format!("D-Bus operation failed: {e}"),
        }
    }
}
