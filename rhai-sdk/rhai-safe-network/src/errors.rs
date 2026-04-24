//! Error handling for the Rust Network language module
//!
//! Provides error type conversions between `RustNetwork` errors and Rhai dynamic values.
//! Defines a simplified error kind enum that maps detailed `RustNetwork` errors to
//! their basic categories for use in Rhai scripts.

use rhai::{Dynamic, EvalAltResult, Position};
use rust_network::errors::RustNetworkError;
use strum_macros::{AsRefStr, Display, EnumString};

pub(crate) const ERROR_MODULE_NAME: &str = "NetworkErrorKind";

/// Macro to define both the error kind enum and its conversion from `RustNetworkError` and
/// Error categories for Network operations
///
/// A simplified error classification system that maps detailed `RustNetworkError`
/// variants to their basic categories for Rhai script usage.
///
/// # Error Categories
///
/// - `PermissionDenied` - Insufficient permissions for operation
/// - `AuthorizationError` - Failed authorization check
/// - `RequestError` - Error when sending a request
/// - `Other` - Unclassified errors
macro_rules! define_error_kinds {
    ($($variant:ident),* $(,)?) => {
        #[non_exhaustive]
        #[derive(Debug, Clone, Eq, PartialEq, Hash, EnumString, AsRefStr, Display)]
        pub enum RhaiNetworkErrorKind {
            $($variant,)*
            Other,
        }

        impl From<&RustNetworkError> for RhaiNetworkErrorKind {
            fn from(error: &RustNetworkError) -> Self {
                match error {
                    $(RustNetworkError::$variant { .. } => Self::$variant,)*
                    _ => Self::Other,
                }
            }
        }
    };
}
define_error_kinds! {
    PermissionDenied,
    AuthorizationError,
    RequestError,
}

/// Converts a `RustNetworkError` to a Rhai Dynamic value containing error information
///
/// This function creates a map containing the error kind and message, which can be
/// used in Rhai scripts to handle errors.
///
/// # Returns
///
/// Returns a Dynamic value containing a map with:
/// * `kind` - The `RhaiNetworkErrorKind` corresponding to the error
/// * `message` - The error message as a string
pub(crate) fn rust_network_errors_to_dynamic(error: &RustNetworkError) -> Dynamic {
    let mut map = rhai::Map::new();
    let kind: RhaiNetworkErrorKind = error.into();

    map.insert("kind".into(), Dynamic::from(kind));
    map.insert("message".into(), Dynamic::from(format!("{error}")));
    map.insert(
        "source".into(),
        Dynamic::from(ERROR_MODULE_NAME.to_string()),
    );

    Dynamic::from(map)
}

/// Converts a `RustNetworkError` into a Rhai error result
///
/// This function takes a `RustNetworkError` and converts it into a Rhai `EvalAltResult`,
/// maintaining the error information in a format that can be handled by Rhai scripts.
pub(crate) fn convert_to_rhai_error<T>(error: &RustNetworkError) -> Result<T, Box<EvalAltResult>> {
    let error_obj = rust_network_errors_to_dynamic(error);
    Err(Box::new(EvalAltResult::ErrorRuntime(
        error_obj,
        Position::NONE,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_permission_denied_error() -> RustNetworkError {
        RustNetworkError::PermissionDenied {
            principal: "test_user".to_string(),
            action: "GET".to_string(),
            resource_id: "https://example.com".to_string(),
        }
    }

    fn get_authorization_error() -> RustNetworkError {
        RustNetworkError::AuthorizationError {
            principal: "test_user".to_string(),
            action: "GET".to_string(),
            resource_id: "https://example.com".to_string(),
        }
    }

    fn get_other_error() -> RustNetworkError {
        let anyhow_error = anyhow::Error::msg("test other error");
        RustNetworkError::Other(anyhow_error)
    }

    /// Helper function to extract kind from the Dynamic result
    fn get_error_kind(error: &RustNetworkError) -> RhaiNetworkErrorKind {
        let dynamic = rust_network_errors_to_dynamic(error);
        let map = dynamic.try_cast::<rhai::Map>().unwrap();
        map.get("kind")
            .unwrap()
            .clone()
            .cast::<RhaiNetworkErrorKind>()
    }

    /// Given: A RustNetworkError of type PermissionDenied
    /// When: Converting it to a Dynamic value
    /// Then: It maps to RhaiNetworkErrorKind::PermissionDenied
    #[test]
    fn test_permission_denied_mapping() {
        let error = get_permission_denied_error();
        let expected_err = RhaiNetworkErrorKind::PermissionDenied;
        assert_eq!(get_error_kind(&error), expected_err);
    }

    /// Given: A RustNetworkError of type AuthorizationError
    /// When: Converting it to a Dynamic value
    /// Then: It maps to RhaiNetworkErrorKind::AuthorizationError
    #[test]
    fn test_authorization_error_mapping() {
        let error = get_authorization_error();
        let expected_err = RhaiNetworkErrorKind::AuthorizationError;
        assert_eq!(get_error_kind(&error), expected_err);
    }

    /// Given: A RustNetworkError of type Other
    /// When: Converting it to a Dynamic value
    /// Then: It maps to RhaiNetworkErrorKind::Other
    #[test]
    fn test_other_error_mapping() {
        let error = get_other_error();
        let expected_err = RhaiNetworkErrorKind::Other;
        assert_eq!(get_error_kind(&error), expected_err);
    }
}
