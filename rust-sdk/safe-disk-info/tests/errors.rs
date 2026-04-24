//! Comprehensive tests for RustDiskinfoError to achieve 100% branch coverage
use anyhow::Error as AnyhowError;
use rust_disk_info::RustDiskinfoError;
use std::error::Error as SourceError;
use std::path::PathBuf;

/// Test creating each RustDiskinfoError variant
mod construction_tests {
    use super::*;

    /// Given: Values for permission denied error
    /// When: Creating a RustDiskinfoError::PermissionDenied variant
    /// Then: The error should contain the provided values
    #[test]
    fn test_permission_denied_construction() {
        let error = RustDiskinfoError::PermissionDenied {
            principal: "user1".to_string(),
            action: "read".to_string(),
            resource_type: "file".to_string(),
            resource_id: "/path/to/file".to_string(),
        };

        match error {
            RustDiskinfoError::PermissionDenied {
                principal,
                action,
                resource_type,
                resource_id,
            } => {
                assert_eq!(principal, "user1");
                assert_eq!(action, "read");
                assert_eq!(resource_type, "file");
                assert_eq!(resource_id, "/path/to/file");
            }
            _ => panic!("Expected PermissionDenied variant"),
        }
    }

    /// Given: Values for authorization error
    /// When: Creating a RustDiskinfoError::AuthorizationError variant
    /// Then: The error should contain the provided values
    #[test]
    fn test_authorization_error_construction() {
        let error = RustDiskinfoError::AuthorizationError {
            principal: "user1".to_string(),
            action: "write".to_string(),
            resource_type: "file".to_string(),
            resource_id: "/path/to/file".to_string(),
        };

        match error {
            RustDiskinfoError::AuthorizationError {
                principal,
                action,
                resource_type,
                resource_id,
            } => {
                assert_eq!(principal, "user1");
                assert_eq!(action, "write");
                assert_eq!(resource_type, "file");
                assert_eq!(resource_id, "/path/to/file");
            }
            _ => panic!("Expected AuthorizationError variant"),
        }
    }

    /// Given: Values for system error
    /// When: Creating a RustDiskinfoError::SystemError variant
    /// Then: The error should contain the provided values
    #[test]
    fn test_system_error_construction() {
        let source_error = std::io::Error::new(std::io::ErrorKind::Other, "underlying error");
        let boxed_source: Box<dyn SourceError + Send + Sync> = Box::new(source_error);

        let error = RustDiskinfoError::SystemError {
            reason: "test system error".to_string(),
            source: boxed_source,
        };

        match error {
            RustDiskinfoError::SystemError { reason, .. } => {
                assert_eq!(reason, "test system error");
                // We can't easily compare the boxed error, but we can check it exists
            }
            _ => panic!("Expected SystemError variant"),
        }
    }

    /// Given: Values for invalid path error
    /// When: Creating a RustDiskinfoError::InvalidPath variant
    /// Then: The error should contain the provided values
    #[test]
    fn test_invalid_path_construction() {
        let path = PathBuf::from("/invalid/path");
        let error = RustDiskinfoError::InvalidPath {
            reason: "test invalid path".to_string(),
            path: path.clone(),
        };

        match error {
            RustDiskinfoError::InvalidPath {
                reason,
                path: error_path,
            } => {
                assert_eq!(reason, "test invalid path");
                assert_eq!(error_path, path);
            }
            _ => panic!("Expected InvalidPath variant"),
        }
    }

    /// Given: An anyhow error
    /// When: Creating a RustDiskinfoError::Other variant
    /// Then: The error should contain the provided error
    #[test]
    fn test_other_construction() {
        let anyhow_error = AnyhowError::msg("test other error");
        let error = RustDiskinfoError::Other(anyhow_error);

        match error {
            RustDiskinfoError::Other(_) => {
                // Success - we can't easily compare the anyhow error
            }
            _ => panic!("Expected Other variant"),
        }
    }
}

/// Test Display implementation for all RustDiskinfoError variants
mod display_tests {
    use super::*;

    /// Given: A RustDiskinfoError::PermissionDenied with specific values
    /// When: Formatting the error for display
    /// Then: The output should follow the expected format
    #[test]
    fn test_permission_denied_display() {
        let error = RustDiskinfoError::PermissionDenied {
            principal: "user1".to_string(),
            action: "read".to_string(),
            resource_type: "file".to_string(),
            resource_id: "/path/to/file".to_string(),
        };

        let display_output = format!("{}", error);
        assert_eq!(
            display_output,
            "Permission denied: user1 unauthorized to perform read for file::/path/to/file"
        );
    }

    /// Given: A RustDiskinfoError::AuthorizationError with specific values
    /// When: Formatting the error for display
    /// Then: The output should be "Authorization check failed"
    #[test]
    fn test_authorization_error_display() {
        let error = RustDiskinfoError::AuthorizationError {
            principal: "user1".to_string(),
            action: "write".to_string(),
            resource_type: "file".to_string(),
            resource_id: "/path/to/file".to_string(),
        };

        let display_output = format!("{}", error);
        assert_eq!(display_output, "Authorization check failed");
    }

    /// Given: A RustDiskinfoError::SystemError with a specific reason
    /// When: Formatting the error for display
    /// Then: The output should be "{SYSTEM_ERROR}: {reason}"
    #[test]
    fn test_system_error_display() {
        let source_error = std::io::Error::new(std::io::ErrorKind::Other, "underlying error");
        let boxed_source: Box<dyn SourceError + Send + Sync> = Box::new(source_error);

        let error = RustDiskinfoError::SystemError {
            reason: "disk not found".to_string(),
            source: boxed_source,
        };

        let display_output = format!("{}", error);
        assert_eq!(
            display_output,
            format!("System error occurred: disk not found")
        );
    }

    /// Given: A RustDiskinfoError::InvalidPath with a specific reason and path
    /// When: Formatting the error for display
    /// Then: The output should be "{INVALID_PATH_ERR}: {reason}"
    #[test]
    fn test_invalid_path_display() {
        let path = PathBuf::from("/invalid/path");
        let error = RustDiskinfoError::InvalidPath {
            reason: "path traversal detected".to_string(),
            path,
        };

        let display_output = format!("{}", error);
        assert_eq!(
            display_output,
            format!("Invalid filesystem path: path traversal detected")
        );
    }

    /// Given: A RustDiskinfoError::Other with an anyhow error
    /// When: Formatting the error for display
    /// Then: The output should contain the anyhow error message
    #[test]
    fn test_other_display() {
        let anyhow_error = AnyhowError::msg("test other error");
        let error = RustDiskinfoError::Other(anyhow_error);

        let display_output = format!("{}", error);
        assert!(display_output.contains("test other error"));
    }
}
