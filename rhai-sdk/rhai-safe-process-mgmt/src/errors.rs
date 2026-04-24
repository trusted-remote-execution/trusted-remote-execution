//! Error handling for the Safe Process Management language module
//!
//! Provides error type conversions between Rust Safe Process Management errors and Rhai dynamic values.
//! Defines a simplified error kind enum that maps detailed Rust Safe Process Management errors to
//! their basic categories for use in Rhai scripts.

use rex_runner_registrar_utils::execution_context::ExecutionContext;
use rhai::{Dynamic, EvalAltResult, Position};
use rust_safe_process_mgmt::errors::RustSafeProcessMgmtError;
use strum_macros::{AsRefStr, Display, EnumString};

pub const ERROR_MODULE_NAME: &str = "ProcessErrorKind";

/// Macro to define both the error kind enum and its conversion from `RustSafeProcessMgmtError`
macro_rules! define_error_kinds {
    ($($variant:ident),* $(,)?) => {
        #[non_exhaustive]
        #[derive(Debug, Clone, Eq, PartialEq, Hash, EnumString, AsRefStr, Display)]
        pub enum RhaiSafeProcessMgmtErrorKind {
            $($variant,)*
            Other,
        }

        impl From<&RustSafeProcessMgmtError> for RhaiSafeProcessMgmtErrorKind {
            fn from(error: &RustSafeProcessMgmtError) -> Self {
                match error {
                    $(RustSafeProcessMgmtError::$variant { .. } => Self::$variant,)*
                    _ => Self::Other,
                }
            }
        }
    };
}

define_error_kinds! {
    ProcessNotFound,
    PidNamespaceOperationError,
    NamespaceOperationError,
    PermissionDenied,
    AuthorizationError,
    ValidationError,
    CallbackExecutionError,
    ProcessEnumerationError,
    DBusError,
    PrivilegeError,
    ServiceNotFound,
}

/// Converts a `RustSafeProcessMgmtError` to a Rhai Dynamic value containing error information
///
/// # Examples
///
/// ```
/// use rust_safe_process_mgmt::errors::RustSafeProcessMgmtError;
/// use rhai_safe_process_mgmt::errors::rust_safe_process_mgmt_errors_to_dynamic;
///
/// let error = RustSafeProcessMgmtError::ProcessNotFound {
///     reason: "Process with specified PID does not exist".to_string(),
///     pid: 1234
/// };
/// let dynamic = rust_safe_process_mgmt_errors_to_dynamic(&error);
/// ```
pub fn rust_safe_process_mgmt_errors_to_dynamic(error: &RustSafeProcessMgmtError) -> Dynamic {
    let mut map = rhai::Map::new();
    let kind: RhaiSafeProcessMgmtErrorKind = error.into();

    map.insert("kind".into(), Dynamic::from(kind));
    map.insert("message".into(), Dynamic::from(format!("{error}")));
    map.insert(
        "source".into(),
        Dynamic::from(ERROR_MODULE_NAME.to_string()),
    );

    Dynamic::from(map)
}

/// List of critical error kinds that should terminate script execution
const CRITICAL_ERRORS: &[RhaiSafeProcessMgmtErrorKind] =
    &[RhaiSafeProcessMgmtErrorKind::PrivilegeError];

fn is_critical_error(error: &RustSafeProcessMgmtError) -> bool {
    let error_kind: RhaiSafeProcessMgmtErrorKind = error.into();
    CRITICAL_ERRORS.contains(&error_kind)
}

/// Converts a `RustSafeProcessMgmtError` into a Rhai error result with optional execution context
///
/// For critical errors (determined by `is_critical_error`), it will signal termination through
/// the execution context if provided.
///
/// # Examples
///
/// ```
/// use rust_safe_process_mgmt::errors::RustSafeProcessMgmtError;
/// use rhai_safe_process_mgmt::errors::convert_to_rhai_error_with_execution_context;
/// use rex_runner_registrar_utils::execution_context::ExecutionContext;
/// use rhai::EvalAltResult;
///
/// let execution_context = ExecutionContext::default();
/// let process_error = RustSafeProcessMgmtError::PrivilegeError {
///     message: "Failed to drop privileges".to_string(),
/// };
/// let rhai_error: Result<(), Box<EvalAltResult>> =
///     convert_to_rhai_error_with_execution_context(&process_error, Some(&execution_context));
/// ```
pub fn convert_to_rhai_error_with_execution_context<T>(
    error: &RustSafeProcessMgmtError,
    execution_context: Option<&ExecutionContext>,
) -> Result<T, Box<EvalAltResult>> {
    if let Some(ctx) = execution_context
        && is_critical_error(error)
    {
        ctx.termination_flag().signal_termination(error.to_string());
    }

    let error_obj = rust_safe_process_mgmt_errors_to_dynamic(error);
    Err(Box::new(EvalAltResult::ErrorRuntime(
        error_obj,
        Position::NONE,
    )))
}

/// Converts a `RustSafeProcessMgmtError` into a Rhai error result
///
/// # Examples
///
/// ```
/// use rust_safe_process_mgmt::errors::RustSafeProcessMgmtError;
/// use rhai_safe_process_mgmt::errors::convert_to_rhai_error;
/// use rhai::EvalAltResult;
///
/// let process_error = RustSafeProcessMgmtError::ProcessNotFound {
///     reason: "Process with specified PID does not exist".to_string(),
///     pid: 1234
/// };
/// let rhai_error: Result<(), Box<EvalAltResult>> = convert_to_rhai_error(&process_error);
/// ```
pub fn convert_to_rhai_error<T>(error: &RustSafeProcessMgmtError) -> Result<T, Box<EvalAltResult>> {
    convert_to_rhai_error_with_execution_context(error, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PID: u32 = 1234;

    fn get_error() -> RustSafeProcessMgmtError {
        RustSafeProcessMgmtError::ProcessNotFound {
            reason: "Process with specified PID does not exist".to_string(),
            pid: TEST_PID,
        }
    }

    /// Given: A RustSafeProcessMgmtError
    /// When: Converting it to a Dynamic value
    /// Then: The resulting map contains both kind and message fields
    #[test]
    fn test_error_dynamic_structure() {
        let error = get_error();
        let dynamic = rust_safe_process_mgmt_errors_to_dynamic(&error);
        let map = dynamic.try_cast::<rhai::Map>().unwrap();

        assert!(map.contains_key("kind"));
        assert!(map.contains_key("message"));

        let message = map.get("message").unwrap().clone().cast::<String>();
        assert!(message.contains("Process not found"));
        assert!(message.contains("1234"));

        let kind = map
            .get("kind")
            .unwrap()
            .clone()
            .cast::<RhaiSafeProcessMgmtErrorKind>();
        assert_eq!(kind, RhaiSafeProcessMgmtErrorKind::ProcessNotFound);
    }

    /// Given: Different RustSafeProcessMgmtError variants
    /// When: Converting them to error kinds
    /// Then: Each maps to the correct RhaiSafeProcessMgmtErrorKind
    #[test]
    fn test_all_error_variant_mappings() {
        let process_not_found = RustSafeProcessMgmtError::ProcessNotFound {
            reason: "test".to_string(),
            pid: 1234,
        };
        assert_eq!(
            RhaiSafeProcessMgmtErrorKind::from(&process_not_found),
            RhaiSafeProcessMgmtErrorKind::ProcessNotFound
        );

        let permission_denied = RustSafeProcessMgmtError::PermissionDenied {
            principal: "user".to_string(),
            action: "nsenter".to_string(),
            resource_type: "process".to_string(),
            resource_id: "1234".to_string(),
        };
        assert_eq!(
            RhaiSafeProcessMgmtErrorKind::from(&permission_denied),
            RhaiSafeProcessMgmtErrorKind::PermissionDenied
        );

        let validation_error = RustSafeProcessMgmtError::ValidationError {
            reason: "test validation".to_string(),
        };
        assert_eq!(
            RhaiSafeProcessMgmtErrorKind::from(&validation_error),
            RhaiSafeProcessMgmtErrorKind::ValidationError
        );
    }

    /// Given: A PrivilegeError
    /// When: Checking if it's a critical error
    /// Then: Returns true
    #[test]
    fn test_is_critical_error_for_privilege_error() {
        let privilege_error = RustSafeProcessMgmtError::PrivilegeError {
            message: "Failed to drop privileges".to_string(),
        };
        assert!(is_critical_error(&privilege_error));
    }

    /// Given: A non-critical error (ProcessNotFound)
    /// When: Checking if it's a critical error
    /// Then: Returns false
    #[test]
    fn test_is_not_critical_error_for_process_not_found() {
        let error = get_error();
        assert!(!is_critical_error(&error));
    }

    /// Given: A critical error (PrivilegeError)
    /// When: The error occurs within a script
    /// Then: Termination flag is set with correct error message
    #[test]
    fn test_critical_error_signals_termination() {
        let execution_context = ExecutionContext::default();
        let privilege_error = RustSafeProcessMgmtError::PrivilegeError {
            message: "Failed to drop privileges".to_string(),
        };

        let _result: Result<(), Box<EvalAltResult>> = convert_to_rhai_error_with_execution_context(
            &privilege_error,
            Some(&execution_context),
        );

        assert!(execution_context.termination_flag().should_terminate());
        assert_eq!(
            execution_context.termination_flag().error(),
            Some("Failed to drop privileges".to_string())
        );
    }
}
