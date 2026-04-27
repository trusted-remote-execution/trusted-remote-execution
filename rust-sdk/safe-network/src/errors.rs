//! Error types for network operations
use anyhow::Error as AnyhowError;
use std::io::Error as StdIoError;

#[cfg(target_os = "linux")]
use procfs::ProcError;
use reqwest::Error as ReqwestError;
use rust_sdk_common_utils::cedar_auth::CedarAuthorizationError;
use thiserror::Error;

/// Represents errors that can occur during network operations
///
/// This enum provides specific error variants for different types of failures that can occur
/// during network operations such as HTTP requests, authorization, and permission checks.
///
/// # Variants
///
/// * `PermissionDenied` - Error when an operation is not permitted
/// * `AuthorizationError` - Error when authorization check fails
/// * `RequestError` - Error when a network request fails
/// * `Other` - Wrapper for other errors via anyhow
///
/// # Examples
///
/// ```no_run
/// use rust_safe_network::RustNetworkError;
///
/// // Creating a permission denied error
/// let error = RustNetworkError::PermissionDenied {
///     principal: "user123".to_string(),
///     action: "Network::Request".to_string(),
///     resource_id: "api.example.com".to_string()
/// };
/// ```
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum RustNetworkError {
    /// Error indicating permission denied
    ///
    /// # Fields
    ///
    /// * `principal` - The user/entity that was denied
    /// * `action` - The action that was attempted
    /// * `resource_id` - Identifier of the resource
    #[error("Permission denied: {principal} unauthorized to perform {action} for {resource_id}")]
    PermissionDenied {
        principal: String,
        action: String,
        resource_id: String,
    },

    /// Error indicating authorization check failure
    ///
    /// # Fields
    ///
    /// * `principal` - The user/entity that failed authorization
    /// * `action` - The action that was attempted
    /// * `resource_id` - Identifier of the resource
    #[error("Authorization check failed")]
    AuthorizationError {
        principal: String,
        action: String,
        resource_id: String,
    },

    /// Error indicating a network request failure
    ///
    /// This variant is used when an HTTP request fails due to network issues,
    /// DNS resolution failures, connection timeouts, or other request-related errors.
    ///
    /// # Fields
    ///
    /// * `reason` - A human-readable description of why the request failed
    /// * `kind` - The underlying reqwest error with detailed failure information
    #[error("Failed to send a request: reason: {reason}")]
    RequestError { reason: String, kind: ReqwestError },

    /// Error indicating a problem with truncating a response
    ///
    /// This variant is used when truncating a response size fails.
    ///
    /// # Fields
    ///
    /// * `reason` - A human-readable description of why truncation failed
    /// * `kind` - The underlying reqwest error with detailed failure information
    #[error("Failed to truncate response: reason: {reason}")]
    TruncateError { reason: String },

    /// Error indicating the buffer size limit exceeds platform capacity
    ///
    /// This variant is used when the configured `max_text_bytes` exceeds the
    /// maximum addressable size on the current platform (e.g., u64 value
    /// exceeds `usize::MAX` on 32-bit systems).
    ///
    /// # Fields
    ///
    /// * `size` - The requested buffer size that exceeded platform capacity
    #[error("Buffer size {size} exceeds maximum capacity for this platform")]
    BufferSizeError { size: u64 },

    /// Error indicating an invalid socket address format
    ///
    /// This variant is used when an endpoint:port combination cannot be parsed
    /// as a valid socket address.
    ///
    /// # Fields
    ///
    /// * `address` - The invalid address string that failed to parse
    #[error("Invalid address format: {address}")]
    AddressParseError { address: String },

    /// Error indicating an unsupported transport protocol
    ///
    /// This variant is used when a transport protocol variant is not supported
    /// by the operation being performed.
    ///
    /// # Fields
    ///
    /// * `protocol` - A string representation of the unsupported protocol
    #[error("Unsupported transport protocol: {protocol}")]
    UnsupportedProtocol { protocol: String },

    /// Error indicating process enumeration failed
    ///
    /// # Fields
    ///
    /// * `message` - Description of the enumeration error
    #[error("Process enumeration failed: {message}")]
    ProcessEnumerationError { message: String },

    /// Error indicating that operation being used is not supported
    #[error("Unsupported Operation error: {reason}")]
    UnsupportedOperationError { reason: String },

    /// for other errors
    #[error(transparent)]
    StdIoError(#[from] StdIoError),

    /// Anyhow for other errors
    #[error(transparent)]
    Other(#[from] AnyhowError),

    // Procfs errors
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    ProcFsError(#[from] ProcError),
}

impl CedarAuthorizationError for RustNetworkError {
    fn permission_denied(
        principal: String,
        action: String,
        _resource_type: String,
        resource_id: String,
    ) -> Self {
        Self::PermissionDenied {
            principal,
            action,
            resource_id,
        }
    }

    fn authorization_error(
        principal: String,
        action: String,
        _resource_type: String,
        resource_id: String,
    ) -> Self {
        Self::AuthorizationError {
            principal,
            action,
            resource_id,
        }
    }
}
