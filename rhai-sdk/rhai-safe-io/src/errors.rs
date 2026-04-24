//! Error handling for the Safe IO language module
//!
//! Provides error type conversions between Rust Safe IO errors and Rhai dynamic values.
//! Defines a simplified error kind enum that maps detailed Rust Safe IO errors to
//! their basic categories for use in Rhai scripts.

use rex_runner_registrar_utils::execution_context::ExecutionContext;
use rhai::plugin::{
    FnNamespace, FuncRegistration, Module, NativeCallContext, PluginFunc, RhaiResult, TypeId,
    export_module, mem,
};
use rhai::{Dynamic, EvalAltResult, Position};
use rust_safe_io::errors::RustSafeIoError;
use strum_macros::{AsRefStr, Display, EnumString};

pub const ERROR_MODULE_NAME: &str = "IoErrorKind";

/// Macro to define both the error kind enum and its conversion from `RustSafeIoError` and
/// Error categories for Safe IO operations
///
/// A simplified error classification system that maps detailed `RustSafeIoError`
/// variants to their basic categories for Rhai script usage.
///
/// # Error Categories
///
/// - `InvalidPath` - Invalid path format or characters
/// - `PathTraversal` - Attempted directory traversal attack
/// - `NonUtf8Path` - Path contains invalid UTF-8 sequences
/// - `DirectoryReadError` - Failed to read directory contents
/// - `DirectoryCreateError` - Failed to create directory
/// - `DirectoryOpenError` - Failed to open directory
/// - `PermissionDenied` - Insufficient permissions for operation
/// - `AuthorizationError` - Failed authorization check
/// - `IoError` - General I/O operation failure
/// - `Utf8Error` - UTF-8 conversion errors
/// - `Other` - Unclassified errors
macro_rules! define_error_kinds {
    ($($variant:ident),* $(,)?) => {
        #[non_exhaustive]
        #[derive(Debug, Clone, Eq, PartialEq, Hash, EnumString, AsRefStr, Display)]
        pub enum RhaiSafeIoErrorKind {
            $($variant,)*
            Other,
        }

        impl From<&RustSafeIoError> for RhaiSafeIoErrorKind {
            fn from(error: &RustSafeIoError) -> Self {
                match error {
                    $(RustSafeIoError::$variant { .. } => Self::$variant,)*
                    _ => Self::Other,
                }
            }
        }
    };
}
define_error_kinds! {
    InvalidPath,
    InvalidArguments,
    InvalidFileMode,
    ValidationError,
    DirectoryOpenError,
    DirectoryError,
    FileError,
    DestinationFileNotEmptyError,
    NotFound,
    DirectoryNotEmpty,
    PermissionDenied,
    AuthorizationError,
    IdentityResolutionError,
    UnsupportedOperationError,
    FileContentTooLargeError,
    FileCopyError,
    FileReadError,
    EntryTypeMismatchError,
    IoError,
    TryFromIntError,
    RustixError,
    Utf8Error,
    CallbackError,
    ProcessNamespaceFatalError,
}

/// Converts a `RustSafeIoError` to a Rhai Dynamic value containing error information
///
/// This function creates a map containing the error kind and message, which can be
/// used in Rhai scripts to handle errors.
///
/// # Arguments
///
/// * `error` - Reference to the `RustSafeIoError` to convert
///
/// # Returns
///
/// Returns a Dynamic value containing a map with:
/// * `kind` - The `RhaiSafeIoErrorKind` corresponding to the error
/// * `message` - The error message as a string
/// * `source` - The module error is coming from
///
/// # Examples
///
/// ```
/// use rust_safe_io::errors::RustSafeIoError;
/// use rhai_safe_io::errors::rust_safe_io_errors_to_dynamic;
/// use std::path::PathBuf;
///
/// let error = RustSafeIoError::InvalidPath {
///     reason: "Invalid characters".to_string(),
///     path: PathBuf::from("/test/path")
/// };
/// let dynamic = rust_safe_io_errors_to_dynamic(&error);
/// ```
pub fn rust_safe_io_errors_to_dynamic(error: &RustSafeIoError) -> Dynamic {
    let mut map = rhai::Map::new();
    let kind: RhaiSafeIoErrorKind = error.into();

    map.insert("kind".into(), Dynamic::from(kind));
    map.insert("message".into(), Dynamic::from(format!("{error}")));
    map.insert(
        "source".into(),
        Dynamic::from(ERROR_MODULE_NAME.to_string()),
    );

    Dynamic::from(map)
}

/// Converts a `RustSafeIoError` into a Rhai error result
///
/// This function takes a `RustSafeIoError` and converts it into a Rhai `EvalAltResult`,
/// maintaining the error information in a format that can be handled by Rhai scripts.
///
/// # Arguments
///
/// * `error` - The `RustSafeIoError` to convert
///
/// # Examples
///
/// ```
/// use rust_safe_io::errors::RustSafeIoError;
/// use rhai_safe_io::errors::convert_to_rhai_error;
/// use rhai::EvalAltResult;
/// use std::path::PathBuf;
///
/// let io_error = RustSafeIoError::InvalidPath {
///     reason: "Invalid characters".to_string(),
///     path: PathBuf::from("/test/path")
/// };
/// let rhai_error: Result<(), Box<EvalAltResult>> = convert_to_rhai_error(&io_error);
/// ```
pub fn convert_to_rhai_error<T>(error: &RustSafeIoError) -> Result<T, Box<EvalAltResult>> {
    convert_to_rhai_error_with_execution_context(error, None)
}

/// Converts a `RustSafeIoError` into a Rhai error result with optional execution context
///
/// This function takes a `RustSafeIoError` and converts it into a Rhai `EvalAltResult`,
/// maintaining the error information in a format that can be handled by Rhai scripts.
/// For critical errors, it will signal termination through the execution context if provided.
///
/// # Examples
///
/// ```
/// use rust_safe_io::errors::RustSafeIoError;
/// use rhai_safe_io::errors::convert_to_rhai_error_with_execution_context;
/// use rex_runner_registrar_utils::execution_context::ExecutionContext;
/// use rhai::EvalAltResult;
///
/// let execution_context = ExecutionContext::default();
/// let io_error = RustSafeIoError::ProcessNamespaceFatalError {
///     reason: "Failed to switch namespace".to_string(),
/// };
/// let rhai_error: Result<(), Box<EvalAltResult>> =
///     convert_to_rhai_error_with_execution_context(&io_error, Some(&execution_context));
/// ```
pub fn convert_to_rhai_error_with_execution_context<T>(
    error: &RustSafeIoError,
    execution_context: Option<&ExecutionContext>,
) -> Result<T, Box<EvalAltResult>> {
    if let Some(ctx) = execution_context
        && matches!(error, RustSafeIoError::ProcessNamespaceFatalError { .. })
    {
        ctx.termination_flag().signal_termination(error.to_string());
    }

    let error_obj = rust_safe_io_errors_to_dynamic(error);
    Err(Box::new(EvalAltResult::ErrorRuntime(
        error_obj,
        Position::NONE,
    )))
}

#[allow(non_upper_case_globals)]
#[allow(unreachable_pub)]
#[allow(clippy::unwrap_used)]
#[export_module]
pub mod error_kind_module {
    use crate::errors::RhaiSafeIoErrorKind;

    pub const InvalidPath: RhaiSafeIoErrorKind = RhaiSafeIoErrorKind::InvalidPath;
    pub const InvalidArguments: RhaiSafeIoErrorKind = RhaiSafeIoErrorKind::InvalidArguments;
    pub const InvalidFileMode: RhaiSafeIoErrorKind = RhaiSafeIoErrorKind::InvalidFileMode;
    pub const ValidationError: RhaiSafeIoErrorKind = RhaiSafeIoErrorKind::ValidationError;
    pub const DirectoryOpenError: RhaiSafeIoErrorKind = RhaiSafeIoErrorKind::DirectoryOpenError;
    pub const DirectoryError: RhaiSafeIoErrorKind = RhaiSafeIoErrorKind::DirectoryError;
    pub const FileError: RhaiSafeIoErrorKind = RhaiSafeIoErrorKind::FileError;
    pub const DestinationFileNotEmptyError: RhaiSafeIoErrorKind =
        RhaiSafeIoErrorKind::DestinationFileNotEmptyError;
    pub const NotFound: RhaiSafeIoErrorKind = RhaiSafeIoErrorKind::NotFound;
    pub const DirectoryNotEmpty: RhaiSafeIoErrorKind = RhaiSafeIoErrorKind::DirectoryNotEmpty;
    pub const PermissionDenied: RhaiSafeIoErrorKind = RhaiSafeIoErrorKind::PermissionDenied;
    pub const AuthorizationError: RhaiSafeIoErrorKind = RhaiSafeIoErrorKind::AuthorizationError;
    pub const IdentityResolutionError: RhaiSafeIoErrorKind =
        RhaiSafeIoErrorKind::IdentityResolutionError;
    pub const UnsupportedOperationError: RhaiSafeIoErrorKind =
        RhaiSafeIoErrorKind::UnsupportedOperationError;
    pub const FileContentTooLargeError: RhaiSafeIoErrorKind =
        RhaiSafeIoErrorKind::FileContentTooLargeError;
    pub const FileCopyError: RhaiSafeIoErrorKind = RhaiSafeIoErrorKind::FileCopyError;
    pub const FileReadError: RhaiSafeIoErrorKind = RhaiSafeIoErrorKind::FileReadError;
    pub const EntryTypeMismatchError: RhaiSafeIoErrorKind =
        RhaiSafeIoErrorKind::EntryTypeMismatchError;
    pub const IoError: RhaiSafeIoErrorKind = RhaiSafeIoErrorKind::IoError;
    pub const TryFromIntError: RhaiSafeIoErrorKind = RhaiSafeIoErrorKind::TryFromIntError;
    pub const RustixError: RhaiSafeIoErrorKind = RhaiSafeIoErrorKind::RustixError;
    pub const Utf8Error: RhaiSafeIoErrorKind = RhaiSafeIoErrorKind::Utf8Error;
    pub const Other: RhaiSafeIoErrorKind = RhaiSafeIoErrorKind::Other;

    #[rhai_fn(global, name = "==", pure)]
    pub fn eq(error_kind: &mut RhaiSafeIoErrorKind, other: RhaiSafeIoErrorKind) -> bool {
        error_kind == &other
    }

    #[rhai_fn(global, name = "!=", pure)]
    pub fn neq(error_kind: &mut RhaiSafeIoErrorKind, other: RhaiSafeIoErrorKind) -> bool {
        error_kind != &other
    }

    #[rhai_fn(global, name = "to_string")]
    pub fn to_string(kind: &mut RhaiSafeIoErrorKind) -> String {
        kind.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Common test path used across all test cases
    const TEST_PATH: &str = "/test/path";
    const EXPECTED_ERR: RhaiSafeIoErrorKind = RhaiSafeIoErrorKind::InvalidPath;

    fn get_error() -> RustSafeIoError {
        RustSafeIoError::InvalidPath {
            reason: "invalid path".to_string(),
            path: PathBuf::from(TEST_PATH),
        }
    }

    /// Helper function to extract kind from the Dynamic result
    fn get_error_kind(error: &RustSafeIoError) -> RhaiSafeIoErrorKind {
        let dynamic = rust_safe_io_errors_to_dynamic(error);
        let map = dynamic.try_cast::<rhai::Map>().unwrap();
        map.get("kind")
            .unwrap()
            .clone()
            .cast::<RhaiSafeIoErrorKind>()
    }

    /// Given: A RustSafeIoError of type InvalidPath
    /// When: Converting it to a Dynamic value
    /// Then: It maps to RhaiSafeIoErrorKind::InvalidPath
    #[test]
    fn test_invalid_path_mapping() {
        let error = get_error();
        assert_eq!(get_error_kind(&error), EXPECTED_ERR);
    }

    /// Given: A RustSafeIoError
    /// When: Converting it to a Dynamic value
    /// Then: It maps successfully to RhaiSafeIoErrorKind
    #[test]
    fn test_successful_mapping() {
        let error = get_error();
        assert_eq!(get_error_kind(&error), EXPECTED_ERR);
    }

    /// Given: A critical error (ProcessNamespaceFatalError)
    /// When: The error occurs within a script with execution context
    /// Then: Check that termination is successful with correct error message
    #[test]
    fn test_critical_error_signals_termination() {
        let execution_context = ExecutionContext::default();
        let namespace_error = RustSafeIoError::ProcessNamespaceFatalError {
            reason: "Failed to switch namespace".to_string(),
        };

        let _result: Result<(), Box<EvalAltResult>> = convert_to_rhai_error_with_execution_context(
            &namespace_error,
            Some(&execution_context),
        );

        assert!(execution_context.termination_flag().should_terminate());
        assert_eq!(
            execution_context.termination_flag().error(),
            Some("Process namespace fatal error: Failed to switch namespace".to_string())
        );
    }
}
