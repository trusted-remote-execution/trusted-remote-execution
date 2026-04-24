//! Comprehensive tests for RustSysteminfoError to achieve 100% branch coverage
use anyhow::Error as AnyhowError;
use rust_system_info::RustSysteminfoError;

/// Test creating each RustSysteminfoError variant
mod construction_tests {
    use super::*;

    /// Given: Values for permission denied error
    /// When: Creating a RustSysteminfoError::PermissionDenied variant
    /// Then: The error should contain the provided values
    #[test]
    fn test_permission_denied_construction() {
        let error = RustSysteminfoError::PermissionDenied {
            principal: "user1".to_string(),
            action: "read".to_string(),
            resource_type: "file".to_string(),
            resource_id: "/path/to/file".to_string(),
        };

        match error {
            RustSysteminfoError::PermissionDenied {
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
    /// When: Creating a RustSysteminfoError::AuthorizationError variant
    /// Then: The error should contain the provided values
    #[test]
    fn test_authorization_error_construction() {
        let error = RustSysteminfoError::AuthorizationError {
            principal: "user1".to_string(),
            action: "write".to_string(),
            resource_type: "file".to_string(),
            resource_id: "/path/to/file".to_string(),
        };

        match error {
            RustSysteminfoError::AuthorizationError {
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

    /// Given: An anyhow error
    /// When: Creating a RustSysteminfoError::Other variant
    /// Then: The error should contain the provided error
    #[test]
    fn test_other_construction() {
        let anyhow_error = AnyhowError::msg("test other error");
        let error = RustSysteminfoError::Other(anyhow_error);

        match error {
            RustSysteminfoError::Other(_) => {
                // Success - we can't easily compare the anyhow error
            }
            _ => panic!("Expected Other variant"),
        }
    }
}

/// Test Display implementation for all RustSysteminfoError variants
mod display_tests {
    use super::*;

    /// Given: A RustSysteminfoError::PermissionDenied with specific values
    /// When: Formatting the error for display
    /// Then: The output should follow the expected format
    #[test]
    fn test_permission_denied_display() {
        let error = RustSysteminfoError::PermissionDenied {
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

    /// Given: A RustSysteminfoError::AuthorizationError with specific values
    /// When: Formatting the error for display
    /// Then: The output should be "Authorization check failed"
    #[test]
    fn test_authorization_error_display() {
        let error = RustSysteminfoError::AuthorizationError {
            principal: "user1".to_string(),
            action: "write".to_string(),
            resource_type: "file".to_string(),
            resource_id: "/path/to/file".to_string(),
        };

        let display_output = format!("{}", error);
        assert_eq!(display_output, "Authorization check failed");
    }

    /// Given: A RustSysteminfoError::Other with an anyhow error
    /// When: Formatting the error for display
    /// Then: The output should contain the anyhow error message
    #[test]
    fn test_other_display() {
        let anyhow_error = AnyhowError::msg("test other error");
        let error = RustSysteminfoError::Other(anyhow_error);

        let display_output = format!("{}", error);
        assert!(display_output.contains("test other error"));
    }
}
