//! Comprehensive tests for RustNetworkError to achieve 100% branch coverage
use rust_network::RustNetworkError;

/// Test creating each RustNetworkError variant
mod construction_tests {
    use super::*;

    /// Given: Values for permission denied error
    /// When: Creating a RustNetworkError::PermissionDenied variant
    /// Then: The error should contain the provided values
    #[test]
    fn test_permission_denied_construction() {
        let error = RustNetworkError::PermissionDenied {
            principal: "user1".to_string(),
            action: "read".to_string(),
            resource_id: "/path/to/file".to_string(),
        };

        match error {
            RustNetworkError::PermissionDenied {
                principal,
                action,
                resource_id,
            } => {
                assert_eq!(principal, "user1");
                assert_eq!(action, "read");
                assert_eq!(resource_id, "/path/to/file");
            }
            _ => panic!("Expected PermissionDenied variant"),
        }
    }

    /// Given: Values for authorization error
    /// When: Creating a RustNetworkError::AuthorizationError variant
    /// Then: The error should contain the provided values
    #[test]
    fn test_authorization_error_construction() {
        let error = RustNetworkError::AuthorizationError {
            principal: "user1".to_string(),
            action: "Network::Request".to_string(),
            resource_id: "api.example.com".to_string(),
        };

        match error {
            RustNetworkError::AuthorizationError {
                principal,
                action,
                resource_id,
            } => {
                assert_eq!(principal, "user1");
                assert_eq!(action, "Network::Request");
                assert_eq!(resource_id, "api.example.com");
            }
            _ => panic!("Expected AuthorizationError variant"),
        }
    }
}
