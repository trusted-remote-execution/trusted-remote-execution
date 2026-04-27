//! Error handling for the Rust Systeminfo language module
//!
//! Provides error type conversions between `RustSysinfo` errors and Rhai dynamic values.
//! Defines a simplified error kind enum that maps detailed `RustSysinfo` errors to
//! their basic categories for use in Rhai scripts.

use rex_runner_registrar_utils::execution_context::ExecutionContext;
use rhai::{Dynamic, EvalAltResult, Position};
use rust_safe_system_info::errors::RustSysteminfoError;
use strum_macros::{AsRefStr, Display, EnumString};

pub(crate) const ERROR_MODULE_NAME: &str = "SysteminfoErrorKind";

/// Macro to define both the error kind enum and its conversion from `RustSysteminfoError` and
/// Error categories for Systeminfo operations
///
/// A simplified error classification system that maps detailed `RustSysteminfoError`
/// variants to their basic categories for Rhai script usage.
///
/// # Error Categories
///
/// - `PermissionDenied` - Insufficient permissions for operation
/// - `AuthorizationError` - Failed authorization check
/// - `IoError` - General I/O operation failure
/// - `Other` - Unclassified errors
macro_rules! define_error_kinds {
    ($($variant:ident),* $(,)?) => {
        #[non_exhaustive]
        #[derive(Debug, Clone, Eq, PartialEq, Hash, EnumString, AsRefStr, Display)]
        pub enum RhaiSysteminfoErrorKind {
            $($variant,)*
            CapsError,
            Other,
            #[cfg(target_os = "linux")]
            ProcFsError,
        }

        impl From<&RustSysteminfoError> for RhaiSysteminfoErrorKind {
            fn from(error: &RustSysteminfoError) -> Self {
                match error {

                    $(RustSysteminfoError::$variant { .. } => Self::$variant,)*
                    #[cfg(target_os = "linux")]
                    RustSysteminfoError::CapsError { .. } => Self::CapsError,

                    _ => Self::Other,
                }
            }
        }
    };
}
define_error_kinds! {
    PermissionDenied,
    AuthorizationError,
    IoError,
    InvalidParameter,
    InvalidValue,
    PrivilegeError
}

/// List of critical error kinds that should terminate script execution
const CRITICAL_ERRORS: &[RhaiSysteminfoErrorKind] = &[RhaiSysteminfoErrorKind::PrivilegeError];

fn critical_error(error: &RustSysteminfoError) -> bool {
    let error_kind: RhaiSysteminfoErrorKind = error.into();
    CRITICAL_ERRORS.contains(&error_kind)
}

/// Converts a `RustSysteminfoError` to a Rhai Dynamic value containing error information
///
/// This function creates a map containing the error kind and message, which can be
/// used in Rhai scripts to handle errors.
pub(crate) fn rust_sysinfo_errors_to_dynamic(error: &RustSysteminfoError) -> Dynamic {
    let mut map = rhai::Map::new();
    let kind: RhaiSysteminfoErrorKind = error.into();

    map.insert("kind".into(), Dynamic::from(kind));
    map.insert("message".into(), Dynamic::from(format!("{error}")));
    map.insert(
        "source".into(),
        Dynamic::from(ERROR_MODULE_NAME.to_string()),
    );

    Dynamic::from(map)
}

/// Converts a `RustSysteminfoError` into a Rhai error result with optional execution context
///
/// For critical errors (determined by `critical_error`), it will signal termination through
/// the execution context if provided.
pub fn convert_to_rhai_error_with_execution_context<T>(
    error: &RustSysteminfoError,
    execution_context: Option<&ExecutionContext>,
) -> Result<T, Box<EvalAltResult>> {
    if let Some(ctx) = execution_context
        && critical_error(error)
    {
        ctx.termination_flag().signal_termination(error.to_string());
    }

    let error_obj = rust_sysinfo_errors_to_dynamic(error);
    Err(Box::new(EvalAltResult::ErrorRuntime(
        error_obj,
        Position::NONE,
    )))
}

/// Converts a `RustSysteminfoError` into a Rhai error result
///
/// This function takes a `RustSysteminfoError` and converts it into a Rhai `EvalAltResult`,
/// maintaining the error information in a format that can be handled by Rhai scripts.
pub fn convert_to_rhai_error<T>(error: &RustSysteminfoError) -> Result<T, Box<EvalAltResult>> {
    convert_to_rhai_error_with_execution_context(error, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    fn get_other_error() -> RustSysteminfoError {
        let anyhow_error = anyhow::Error::msg("test other error");
        RustSysteminfoError::Other(anyhow_error)
    }

    /// Helper function to extract kind from the Dynamic result
    fn get_error_kind(error: &RustSysteminfoError) -> RhaiSysteminfoErrorKind {
        let dynamic = rust_sysinfo_errors_to_dynamic(error);
        let map = dynamic.try_cast::<rhai::Map>().unwrap();
        map.get("kind")
            .unwrap()
            .clone()
            .cast::<RhaiSysteminfoErrorKind>()
    }

    /// Given: A RustSysteminfoError of type Other
    /// When: Converting it to a Dynamic value
    /// Then: It maps to RhaiSysteminfoErrorKind::Other
    #[test]
    fn test_other_error_mapping() {
        let error = get_other_error();
        let expected_err = RhaiSysteminfoErrorKind::Other;
        assert_eq!(get_error_kind(&error), expected_err);
    }

    /// Given: Various RustSysteminfoError types
    /// When: critical_error is called
    /// Then: Returns true only for PrivilegeError
    #[test]
    fn test_critical_error() {
        // PrivilegeError should be critical
        let privilege_error = RustSysteminfoError::PrivilegeError {
            message: "test".to_string(),
        };
        assert!(critical_error(&privilege_error));

        // Other errors should not be critical
        let other_error = get_other_error();
        assert!(!critical_error(&other_error));

        let io_error = RustSysteminfoError::IoError(Error::new(ErrorKind::NotFound, "test"));
        assert!(!critical_error(&io_error));
    }

    /// Given: A non-critical error with no execution context
    /// When: convert_to_rhai_error_with_execution_context is called
    /// Then: Returns Rhai error without signaling termination
    #[test]
    fn test_convert_non_critical_error_no_context() {
        let error = get_other_error();
        let result: Result<(), Box<EvalAltResult>> =
            convert_to_rhai_error_with_execution_context(&error, None);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(*err, EvalAltResult::ErrorRuntime(_, _)));
    }

    /// Given: A non-critical error with execution context
    /// When: convert_to_rhai_error_with_execution_context is called
    /// Then: Returns Rhai error without signaling termination
    #[test]
    fn test_convert_non_critical_error_with_context() {
        use rex_runner_registrar_utils::execution_context::ExecutionContext;

        let error = get_other_error();
        let ctx = ExecutionContext::default();
        let result: Result<(), Box<EvalAltResult>> =
            convert_to_rhai_error_with_execution_context(&error, Some(&ctx));

        assert!(result.is_err());
        assert!(!ctx.termination_flag().should_terminate());
    }

    /// Given: A critical error (PrivilegeError) with execution context
    /// When: convert_to_rhai_error_with_execution_context is called
    /// Then: Signals termination through execution context
    #[test]
    fn test_convert_critical_error_signals_termination() {
        use rex_runner_registrar_utils::execution_context::ExecutionContext;

        let error = RustSysteminfoError::PrivilegeError {
            message: "Failed to elevate".to_string(),
        };
        let ctx = ExecutionContext::default();
        let result: Result<(), Box<EvalAltResult>> =
            convert_to_rhai_error_with_execution_context(&error, Some(&ctx));

        assert!(result.is_err());
        assert!(ctx.termination_flag().should_terminate());
        assert_eq!(
            ctx.termination_flag().error(),
            Some("Failed to elevate".to_string())
        );
    }

    /// Given: A critical error (PrivilegeError) with no execution context
    /// When: convert_to_rhai_error_with_execution_context is called
    /// Then: Returns Rhai error without attempting to signal termination
    #[test]
    fn test_convert_critical_error_no_context() {
        let error = RustSysteminfoError::PrivilegeError {
            message: "Failed to elevate".to_string(),
        };
        let result: Result<(), Box<EvalAltResult>> =
            convert_to_rhai_error_with_execution_context(&error, None);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(*err, EvalAltResult::ErrorRuntime(_, _)));
    }
}
