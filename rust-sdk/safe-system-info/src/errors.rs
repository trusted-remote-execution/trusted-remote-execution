//! Error types for filesystem operations
use anyhow::Error as AnyhowError;
use core::str::Utf8Error;
use hickory_proto::ProtoErrorKind;
use hickory_resolver::ResolveError;
#[cfg(target_os = "linux")]
use procfs::ProcError;
#[cfg(target_os = "linux")]
use rmesg::error::RMesgError;
use rust_safe_io::errors::RustSafeIoError;
use rust_sdk_common_utils::cedar_auth::CedarAuthorizationError;
use std::io::Error as StdError;
use thiserror::Error;

/// Represents errors that can occur during filesystem operations
///
/// This enum provides specific error variants for different types of failures that can occur
/// during systeminfo operations.
///
/// # Variants
///
/// * `AuthorizationError` - Error when authorization check fails
/// * `PermissionDenied` - Error when an operation is not permitted
/// * `IoError` - Error when an I/O operation fails
/// * `Other` - Anyhow for other errors
///
/// # Examples
///
/// ```no_run
/// use rust_safe_system_info::RustSysteminfoError;
/// use std::path::PathBuf;
///
/// let error = RustSysteminfoError::PermissionDenied {
///     principal: "nobody".to_string(),
///     action: "Filesystem::Read".to_string(),
///     resource_type: "Filesystem".to_string(),
///     resource_id: "File".to_string()
/// };
/// ```
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum RustSysteminfoError {
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

    /// Error when /proc/slabinfo cannot be parsed or format changes
    #[error("Failed to parse slabinfo. This version {version} of slabinfo is not supported")]
    UnsupportedSlabinfoVersion { version: String, supported: String },

    /// Error parsing slabinfo data
    #[error("Failed to parse slabinfo data: {reason}")]
    SlabinfoParseError { reason: String },

    /// Standard IO errors
    #[error(transparent)]
    IoError(#[from] StdError),

    // Procfs errors
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    ProcFsError(#[from] ProcError),

    // rmesg errors
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    RMesgError(#[from] RMesgError),

    /// Error indicating that operation being used is not supoorted
    #[error("Unsupported Operation error: {reason}")]
    UnsupportedOperationError { reason: String },

    /// `RustSafeIO` errors
    #[error(transparent)]
    SafeIoError(#[from] RustSafeIoError),

    #[error(transparent)]
    Utf8Error(#[from] Utf8Error),

    /// DNS resolution timeout
    #[error("DNS resolution timeout for hostname: {hostname}")]
    DnsTimeout { hostname: String },

    /// DNS resolution failed
    #[error("DNS resolution failed for hostname: {hostname}, reason: {reason}")]
    DnsResolutionError {
        hostname: String,
        reason: String,
        kind: Option<Box<ProtoErrorKind>>,
    },

    /// Resolve Error
    #[error(transparent)]
    ResolveError(#[from] ResolveError),

    /// Getting hostname failed
    #[error("Could not get hostname")]
    HostnameError { reason: String },

    /// Error when getting or setting capabilities
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    CapsError(#[from] caps::errors::CapsError),

    /// Privilege management error
    #[error("{message}")]
    PrivilegeError { message: String },

    /// Invalid sysctl parameter (key doesn't exist)
    #[error("Invalid sysctl parameter: {key}")]
    InvalidParameter { key: String },

    /// Invalid sysctl value (wrong type/format for the parameter)
    #[error("Invalid sysctl value for {key}={value}: {reason}")]
    InvalidValue {
        key: String,
        value: String,
        reason: String,
    },

    /// Anyhow for other errors
    #[error(transparent)]
    Other(#[from] AnyhowError),
}

impl CedarAuthorizationError for RustSysteminfoError {
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
