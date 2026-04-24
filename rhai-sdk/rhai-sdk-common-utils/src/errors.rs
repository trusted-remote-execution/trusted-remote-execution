//! Error handling for the common utils module
//!
//! Provides error type conversions between Rust Common Utils errors and Rhai dynamic values.
//! Defines a simplified error kind enum that maps detailed Rust Common Utils errors to
//! their basic categories for use in Rhai scripts.

use rhai::{Dynamic, EvalAltResult, Position};
use rust_sdk_common_utils::errors::RustCommonUtilsError;
use strum_macros::{AsRefStr, Display, EnumString};

pub(crate) const ERROR_MODULE_NAME: &str = "CommonUtilsErrorKind";

/// Macro to define both the error kind enum and its conversion from `RustCommonUtilsError` and
/// Error categories for Common util operations
///
/// A simplified error classification system that maps detailed `RustCommonUtilsError`
/// variants to their basic categories for Rhai script usage.
///
/// # Error Categories
///
/// - `ParseError` - Error parsing a value from string
/// - `InvalidArguments` - Invalid argument format or characters
/// - `FormatError` - Error indicating formatting failed
/// - `Other` - Unclassified errors
macro_rules! define_error_kinds {
    ($($variant:ident),* $(,)?) => {
        #[non_exhaustive]
        #[derive(Debug, Clone, Eq, PartialEq, Hash, EnumString, AsRefStr, Display)]
        pub enum RhaiCommonUtilsErrorKind {
            $($variant,)*
            Other,
        }

        impl From<&RustCommonUtilsError> for RhaiCommonUtilsErrorKind {
            fn from(error: &RustCommonUtilsError) -> Self {
                match error {
                    $(RustCommonUtilsError::$variant { .. } => Self::$variant,)*
                    _ => Self::Other,
                }
            }
        }
    };
}
define_error_kinds! {
    ParseError,
    InvalidArguments,
    FormatError,
}

/// Converts a `RustCommonUtilsError` to a Rhai Dynamic value containing error information
///
/// This function creates a map containing the error kind and message, which can be
/// used in Rhai scripts to handle errors.
///
/// # Arguments
///
/// * `error` - Reference to the `RustCommonUtilsError` to convert
///
/// # Returns
///
/// Returns a Dynamic value containing a map with:
/// * `kind` - The `RhaiCommonUtilsErrorKind` corresponding to the error
/// * `message` - The error message as a string
/// * `source` - The module error is coming from
///
/// # Examples
///
/// ```
/// use rust_sdk_common_utils::errors::RustCommonUtilsError;
/// use rhai_sdk_common_utils::errors::rust_common_util_errors_to_dynamic;
/// use std::path::PathBuf;
///
/// let error = RustCommonUtilsError::InvalidArguments {
///     message: "Invalid characters".to_string(),
/// };
/// let dynamic = rust_common_util_errors_to_dynamic(&error);
/// ```
pub fn rust_common_util_errors_to_dynamic(error: &RustCommonUtilsError) -> Dynamic {
    let mut map = rhai::Map::new();
    let kind: RhaiCommonUtilsErrorKind = error.into();

    map.insert("kind".into(), Dynamic::from(kind));
    map.insert("message".into(), Dynamic::from(format!("{error}")));
    map.insert(
        "source".into(),
        Dynamic::from(ERROR_MODULE_NAME.to_string()),
    );

    Dynamic::from(map)
}

/// Converts a `RustCommonUtilsError` into a Rhai error result
///
/// This function takes a `RustCommonUtilsError` and converts it into a Rhai `EvalAltResult`,
/// maintaining the error information in a format that can be handled by Rhai scripts.
///
/// # Arguments
///
/// * `error` - The `RustCommonUtilsError` to convert
///
/// # Examples
///
/// ```
/// use rust_sdk_common_utils::errors::RustCommonUtilsError;
/// use rhai_sdk_common_utils::errors::convert_to_rhai_error;
/// use rhai::EvalAltResult;
/// use std::path::PathBuf;
///
/// let error = RustCommonUtilsError::InvalidArguments {
///     message: "Invalid characters".to_string(),
/// };
/// let rhai_error: Result<(), Box<EvalAltResult>> = convert_to_rhai_error(&error);
/// ```
pub fn convert_to_rhai_error<T>(error: &RustCommonUtilsError) -> Result<T, Box<EvalAltResult>> {
    let error_obj = rust_common_util_errors_to_dynamic(error);
    Err(Box::new(EvalAltResult::ErrorRuntime(
        error_obj,
        Position::NONE,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPECTED_ERR: RhaiCommonUtilsErrorKind = RhaiCommonUtilsErrorKind::InvalidArguments;

    fn get_error() -> RustCommonUtilsError {
        RustCommonUtilsError::InvalidArguments {
            message: "invalid arguments".to_string(),
        }
    }

    fn get_error_kind(error: &RustCommonUtilsError) -> RhaiCommonUtilsErrorKind {
        let dynamic = rust_common_util_errors_to_dynamic(error);
        let map = dynamic.try_cast::<rhai::Map>().unwrap();
        map.get("kind")
            .unwrap()
            .clone()
            .cast::<RhaiCommonUtilsErrorKind>()
    }

    /// Given: A RustCommonUtilsError of type InvalidArguments
    /// When: Converting it to a Dynamic value
    /// Then: It maps to RhaiCommonUtilsErrorKind::InvalidArguments
    #[test]
    fn test_invalid_arguments_mapping() {
        let error = get_error();
        assert_eq!(get_error_kind(&error), EXPECTED_ERR);
    }

    /// Given: A RustCommonUtilsError
    /// When: Converting it to a Dynamic value
    /// Then: It maps successfully to RhaiCommonUtilsErrorKind
    #[test]
    fn test_successful_mapping() {
        let error = get_error();
        assert_eq!(get_error_kind(&error), EXPECTED_ERR);
    }

    /// Given: A RustCommonUtilsError
    /// When: Converting it to a Rhai error using convert_to_rhai_error
    /// Then: It should return an EvalAltResult with the error details
    #[test]
    fn test_convert_to_rhai_error() {
        let error = RustCommonUtilsError::InvalidArguments {
            message: "test invalid arguments error".to_string(),
        };

        let result: Result<String, Box<EvalAltResult>> = convert_to_rhai_error(&error);

        assert!(result.is_err());

        if let Err(eval_error) = result {
            if let EvalAltResult::ErrorRuntime(obj, _) = *eval_error {
                let map = obj.try_cast::<rhai::Map>().unwrap();
                assert_eq!(
                    map.get("message").unwrap().to_string(),
                    "Invalid arguments: test invalid arguments error"
                );
                let kind = map
                    .get("kind")
                    .unwrap()
                    .clone()
                    .cast::<RhaiCommonUtilsErrorKind>();
                assert_eq!(kind, RhaiCommonUtilsErrorKind::InvalidArguments);
            }
        }
    }

    /// Given: A ParseError variant
    /// When: Converting it to RhaiCommonUtilsErrorKind
    /// Then: It should map to ParseError
    #[test]
    fn test_parse_error_mapping() {
        let error = RustCommonUtilsError::ParseError {
            message: "parse failed".to_string(),
        };
        let kind = get_error_kind(&error);
        assert_eq!(kind, RhaiCommonUtilsErrorKind::ParseError);
    }

    /// Given: A FormatError variant
    /// When: Converting it to RhaiCommonUtilsErrorKind
    /// Then: It should map to FormatError
    #[test]
    fn test_format_error_mapping() {
        let error = RustCommonUtilsError::FormatError {
            message: "format failed".to_string(),
        };
        let kind = get_error_kind(&error);
        assert_eq!(kind, RhaiCommonUtilsErrorKind::FormatError);
    }
}
