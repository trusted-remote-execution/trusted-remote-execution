//! Error handling for the Rust Diskinfo language module
//!
//! Provides error type conversions between `RustSysinfo` errors and Rhai dynamic values.
//! Defines a simplified error kind enum that maps detailed `RustSysinfo` errors to
//! their basic categories for use in Rhai scripts.

use rhai::{Dynamic, EvalAltResult, Position};
use rust_safe_disk_info::errors::RustDiskinfoError;
use strum_macros::{AsRefStr, Display, EnumString};

pub(crate) const ERROR_MODULE_NAME: &str = "DiskinfoErrorKind";

/// Macro to define both the error kind enum and its conversion from `RustDiskinfoError` and
/// Error categories for Diskinfo operations
///
/// A simplified error classification system that maps detailed `RustDiskinfoError`
/// variants to their basic categories for Rhai script usage.
///
/// # Error Categories
///
/// - `InvalidPath` - Invalid path format or characters
/// - `PermissionDenied` - Insufficient permissions for operation
/// - `AuthorizationError` - Failed authorization check
/// - `SystemError` - Error when a system error occurs
/// - `IoError` - General I/O operation failure
/// - `Other` - Unclassified errors
macro_rules! define_error_kinds {
    ($($variant:ident),* $(,)?) => {
        #[non_exhaustive]
        #[derive(Debug, Clone, Eq, PartialEq, Hash, EnumString, AsRefStr, Display)]
        pub enum RhaiDiskinfoErrorKind {
            $($variant,)*
            Other,
            #[cfg(unix)]
            NixError,
        }

        impl From<&RustDiskinfoError> for RhaiDiskinfoErrorKind {
            fn from(error: &RustDiskinfoError) -> Self {
                match error {
                    $(RustDiskinfoError::$variant { .. } => Self::$variant,)*
                    _ => Self::Other,
                }
            }
        }
    };
}
define_error_kinds! {
    InvalidPath,
    PermissionDenied,
    AuthorizationError,
    SystemError,
    TryFromIntError,
    IoError,
}

/// Converts a `RustDiskinfoError` to a Rhai Dynamic value containing error information
///
/// This function creates a map containing the error kind and message, which can be
/// used in Rhai scripts to handle errors.
///
/// # Returns
///
/// Returns a Dynamic value containing a map with:
/// * `kind` - The `RhaiDiskinfoErrorKind` corresponding to the error
/// * `message` - The error message as a string
pub(crate) fn rust_sysinfo_errors_to_dynamic(error: &RustDiskinfoError) -> Dynamic {
    let mut map = rhai::Map::new();
    let kind: RhaiDiskinfoErrorKind = error.into();

    map.insert("kind".into(), Dynamic::from(kind));
    map.insert("message".into(), Dynamic::from(format!("{error}")));
    map.insert(
        "source".into(),
        Dynamic::from(ERROR_MODULE_NAME.to_string()),
    );

    Dynamic::from(map)
}

/// Converts a `RustDiskinfoError` into a Rhai error result
///
/// This function takes a `RustDiskinfoError` and converts it into a Rhai `EvalAltResult`,
/// maintaining the error information in a format that can be handled by Rhai scripts.
pub(crate) fn convert_to_rhai_error<T>(error: &RustDiskinfoError) -> Result<T, Box<EvalAltResult>> {
    let error_obj = rust_sysinfo_errors_to_dynamic(error);
    Err(Box::new(EvalAltResult::ErrorRuntime(
        error_obj,
        Position::NONE,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Common test path used across all test cases
    const TEST_PATH: &str = "/test/path";

    fn get_invalid_path_error() -> RustDiskinfoError {
        RustDiskinfoError::InvalidPath {
            reason: "invalid path".to_string(),
            path: PathBuf::from(TEST_PATH),
        }
    }
    fn get_other_error() -> RustDiskinfoError {
        let anyhow_error = anyhow::Error::msg("test other error");
        RustDiskinfoError::Other(anyhow_error)
    }

    /// Helper function to extract kind from the Dynamic result
    fn get_error_kind(error: &RustDiskinfoError) -> RhaiDiskinfoErrorKind {
        let dynamic = rust_sysinfo_errors_to_dynamic(error);
        let map = dynamic.try_cast::<rhai::Map>().unwrap();
        map.get("kind")
            .unwrap()
            .clone()
            .cast::<RhaiDiskinfoErrorKind>()
    }

    /// Given: A RustDiskinfoError of type InvalidPath
    /// When: Converting it to a Dynamic value
    /// Then: It maps to RhaiDiskinfoErrorKind::InvalidPath
    #[test]
    fn test_invalid_path_mapping() {
        let error = get_invalid_path_error();
        let expected_err = RhaiDiskinfoErrorKind::InvalidPath;
        assert_eq!(get_error_kind(&error), expected_err);
    }

    /// Given: A RustDiskinfoError of type Other
    /// When: Converting it to a Dynamic value
    /// Then: It maps to RhaiDiskinfoErrorKind::Other
    #[test]
    fn test_other_error_mapping() {
        let error = get_other_error();
        let expected_err = RhaiDiskinfoErrorKind::Other;
        assert_eq!(get_error_kind(&error), expected_err);
    }
}
