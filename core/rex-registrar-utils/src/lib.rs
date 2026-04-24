//! Macros for registering Rhai translations into REX
//!
//! Type Conversion System
//!
//! Conversion is done in the registration statement with:
//! - `<rhai type> => <rust type>` when converting parameters (data flowing into Rust)
//! - `<rust type> => <rhai type>` when converting returns (data flowing out to Rhai)
//!
//! All conversions use checked `try_from()` and return clear error messages on failure.

pub mod execution_context;
pub mod termination;

/// Registers a free function (no `self` parameter) that requires `CedarAuth` authorization.
/// For functions with signature: `fn(&CedarAuth, args...) -> Result<T, E>`
///
/// Requires `tests:` parameter with positive and negative test function names.
/// The build.rs validation will ensure these test functions exist in the tests/ directory.
///
/// # Usage (without transform):
/// ```js
/// register_fn_with_auth!(
///     engine,
///     "probe_port",
///     rust_network::layer_four::probe_port,
///     cedar_auth,
///     endpoint: &str,
///     port: i64 => u16,
///     protocol: TransportProtocol,
///     -> bool,
///     crate::errors::convert_to_rhai_error;
///     tests: { positive: "test_probe_port_success", negative: "test_probe_port_permission_denied" }
/// );
/// ```
///
/// # Usage (with transform):
/// ```js
/// register_fn_with_auth!(
///     engine,
///     "get_data",
///     my_module::get_data,
///     cedar_auth,
///     id: i64 => u32,
///     -> OutputType,
///     crate::errors::convert_to_rhai_error,
///     transform: |result| Ok(transform_result(result));
///     tests: { positive: "test_get_data_success", negative: "test_get_data_permission_denied" }
/// );
/// ```
#[macro_export]
macro_rules! register_fn_with_auth {
    // Pattern 1: Without transform
    (
        $engine:expr,
        $name:expr,
        $func:path,
        $cedar_auth:expr,
        $($arg:ident : $type:ty $(=> $cast_type:ty)? ,)*
        -> $return_type:ty,
        $error_converter:path;
        tests: { positive: $positive_test:literal, negative: $negative_test:literal }
    ) => {
        // Compile-time check: Enforce that build.rs validation is present
        const _: &str = env!("RHAI_SAFE_FN_VALIDATION_ENABLED", concat!(
            "\n\n",
            "════════════════════════════════════════════════════════════════════════════════\n",
            "ERROR: Using register_fn_with_auth! with 'tests:' parameter requires build.rs validation\n",
            "════════════════════════════════════════════════════════════════════════════════\n",
            "\n",
            "To fix this:\n",
            "\n",
            "1. Add to Cargo.toml [build-dependencies]:\n",
            "   runner-registrar-utils = { version = \"*\", features = [\"build-validation\"] }\n",
            "\n",
            "2. Create build.rs in your package root:\n",
            "\n",
            "   use std::env;\n",
            "   use std::path::Path;\n",
            "\n",
            "   fn main() {\n",
            "       let manifest_dir = env::var(\"CARGO_MANIFEST_DIR\").unwrap();\n",
            "       let registry_file = Path::new(&manifest_dir).join(\"src/registry.rs\");\n",
            "       let tests_dir = Path::new(&manifest_dir).join(\"tests\");\n",
            "       rex_runner_registrar_utils::build_validation::validate_macro_tests(\n",
            "           registry_file.to_str().unwrap(),\n",
            "           tests_dir.to_str().unwrap(),\n",
            "       );\n",
            "   }\n",
            "\n",
            "════════════════════════════════════════════════════════════════════════════════\n"
        ));

        let auth = $cedar_auth.clone();
        $engine.register_fn(
            $name,
            move |context: NativeCallContext $(, $arg: $crate::convert_param_type!($type))*|
                  -> Result<$return_type, Box<rhai::EvalAltResult>> {
                let _guard = get_rhai_context_guard(&context);
                match $func(&auth $(, $crate::convert_param_value!($arg $(=> $cast_type)?))*)  {
                    Ok(result) => Ok(result),
                    Err(e) => $error_converter(&e),
                }
            },
        )
    };

    // Pattern 2: With transform (old syntax - error_converter before transform)
    (
        $engine:expr,
        $name:expr,
        $func:path,
        $cedar_auth:expr,
        $($arg:ident : $type:ty $(=> $cast_type:ty)?),*,
        -> $return_type:ty,
        $error_converter:path,
        transform: $transform_fn:expr;
        tests: { positive: $positive_test:literal, negative: $negative_test:literal }
    ) => {
        // Compile-time check: Enforce that build.rs validation is present
        const _: &str = env!("RHAI_SAFE_FN_VALIDATION_ENABLED", concat!(
            "\n\n",
            "════════════════════════════════════════════════════════════════════════════════\n",
            "ERROR: Using register_fn_with_auth! with 'tests:' parameter requires build.rs validation\n",
            "════════════════════════════════════════════════════════════════════════════════\n",
            "\n",
            "To fix this:\n",
            "\n",
            "1. Add to Cargo.toml [build-dependencies]:\n",
            "   runner-registrar-utils = { version = \"*\", features = [\"build-validation\"] }\n",
            "\n",
            "2. Create build.rs in your package root:\n",
            "\n",
            "   use std::env;\n",
            "   use std::path::Path;\n",
            "\n",
            "   fn main() {\n",
            "       let manifest_dir = env::var(\"CARGO_MANIFEST_DIR\").unwrap();\n",
            "       let registry_file = Path::new(&manifest_dir).join(\"src/registry.rs\");\n",
            "       let tests_dir = Path::new(&manifest_dir).join(\"tests\");\n",
            "       rex_runner_registrar_utils::build_validation::validate_macro_tests(\n",
            "           registry_file.to_str().unwrap(),\n",
            "           tests_dir.to_str().unwrap(),\n",
            "       );\n",
            "   }\n",
            "\n",
            "════════════════════════════════════════════════════════════════════════════════\n"
        ));

        let auth = $cedar_auth.clone();
        $engine.register_fn(
            $name,
            move |context: NativeCallContext $(, $arg: $crate::convert_param_type!($type))*|
                  -> Result<$return_type, Box<rhai::EvalAltResult>> {
                let _guard = get_rhai_context_guard(&context);
                match $func(&auth $(, $crate::convert_param_value!($arg $(=> $cast_type)?))*)  {
                    Ok(result) => ($transform_fn)(result),
                    Err(e) => $error_converter(&e),
                }
            },
        )
    };

    // Pattern 3: With transform (new syntax - transform before error_converter, matching register_direct_safe_fn)
    // Supports Vec<T> transforms for functions returning collections
    // Note: Each argument must have a trailing comma (e.g., `arg1: Type1, arg2: Type2, -> ReturnType`)
    (
        $engine:expr,
        $name:expr,
        $func:path,
        $cedar_auth:expr,
        $($arg:ident : $type:ty $(=> $cast_type:ty)? ,)*
        -> $return_type:ty,
        transform: $transform_fn:expr,
        $error_converter:path;
        tests: { positive: $positive_test:literal, negative: $negative_test:literal }
    ) => {
        // Compile-time check: Enforce that build.rs validation is present
        const _: &str = env!("RHAI_SAFE_FN_VALIDATION_ENABLED", concat!(
            "\n\n",
            "════════════════════════════════════════════════════════════════════════════════\n",
            "ERROR: Using register_fn_with_auth! with 'tests:' parameter requires build.rs validation\n",
            "════════════════════════════════════════════════════════════════════════════════\n",
            "\n",
            "To fix this:\n",
            "\n",
            "1. Add to Cargo.toml [build-dependencies]:\n",
            "   runner-registrar-utils = { version = \"*\", features = [\"build-validation\"] }\n",
            "\n",
            "2. Create build.rs in your package root:\n",
            "\n",
            "   use std::env;\n",
            "   use std::path::Path;\n",
            "\n",
            "   fn main() {\n",
            "       let manifest_dir = env::var(\"CARGO_MANIFEST_DIR\").unwrap();\n",
            "       let registry_file = Path::new(&manifest_dir).join(\"src/registry.rs\");\n",
            "       let tests_dir = Path::new(&manifest_dir).join(\"tests\");\n",
            "       rex_runner_registrar_utils::build_validation::validate_macro_tests(\n",
            "           registry_file.to_str().unwrap(),\n",
            "           tests_dir.to_str().unwrap(),\n",
            "       );\n",
            "   }\n",
            "\n",
            "════════════════════════════════════════════════════════════════════════════════\n"
        ));

        let auth = $cedar_auth.clone();
        $engine.register_fn(
            $name,
            move |context: NativeCallContext $(, $arg: $crate::convert_param_type!($type))*|
                  -> Result<$return_type, Box<rhai::EvalAltResult>> {
                let _guard = get_rhai_context_guard(&context);
                match $func(&auth $(, $crate::convert_param_value!($arg $(=> $cast_type)?))*)  {
                    Ok(result) => ($transform_fn)(result),
                    Err(e) => $error_converter(&e),
                }
            },
        )
    };
}

/// Creates a closure that captures the [`CedarAuth`] when registering functions with the Rhai engine.
#[macro_export]
macro_rules! register_safe_fn {
    ($engine:expr, $name:expr, $func:path, self $(, $arg:ident : $type:ty $(=> $cast_type:ty)?)*) => {
        $engine.register_fn($name, move |context: NativeCallContext, slf: &mut _ $(, $arg: $type)*| {
            let _guard = get_rhai_context_guard(&context);
            $func(slf $(, $crate::convert_param_value!($arg $(=> $cast_type)?))*)
        })
    };

    ($engine:expr, $name:expr, $func:path, $cedar_auth:expr, $($arg:ident : $type:ty $(=> $cast_type:ty)?),*) => {
        let auth = $cedar_auth.clone();
        $engine.register_fn($name, move |context: NativeCallContext $(, $arg: $type)*| {
            let _guard = get_rhai_context_guard(&context);
            $func(&auth $(, $crate::convert_param_value!($arg $(=> $cast_type)?))*)
        })
    };

    ($engine:expr, $name:expr, $func:path, self, $cedar_auth:expr $(, $arg:ident : $type:ty $(=> $cast_type:ty)?)*) => {
        let auth = $cedar_auth.clone();
        $engine.register_fn($name, move |context: NativeCallContext, slf: &mut _ $(, $arg: $type)*| {
            let _guard = get_rhai_context_guard(&context);
            $func(slf, &auth $(, $crate::convert_param_value!($arg $(=> $cast_type)?))*)
        })
    };
}

/// Registers instance methods that don't require Cedar authorization context but add a context guard for
/// logging information. Supports methods with or without additional parameters.
///
/// # Arguments
/// * `engine` - The Rhai engine instance to register the function with
/// * `function_name` - String name for the function in Rhai
/// * `return_type` - The return type
/// * `type` - The type that the method belongs to
/// * `Type::method` - The method path to register
/// * `error_converter` - Function to convert errors to Rhai errors
/// * `param_name: param_type` - Optional additional parameters (zero or more)
#[macro_export]
macro_rules! register_with_no_ctx {
    ($engine:expr, $name:expr, $return_type:ty, $type:ty, $func:path, result, $error_converter:path $(, $arg:ident : $arg_type:ty $(=> $cast_type:ty)?)*) => {
        $engine.register_fn(
            $name,
            move |context: NativeCallContext,
                  slf: &mut $type
                  $(, $arg: $arg_type)*|
                  -> Result<$return_type, Box<rhai::EvalAltResult>> {
                let _guard = get_rhai_context_guard(&context);
                match $func(slf $(, $crate::convert_param_value!($arg $(=> $cast_type)?))*) {
                    Ok(result) => Ok(result),
                    Err(e) => $error_converter(&e),
                }
            },
        )
    };
}

#[macro_export]
/// This macro supports four patterns:
/// 1. With error converter (for functions returning Result)
/// 2. With error converter and execution context (for functions returning Result that need termination signaling)
/// 3. Without error converter (for constructors/static functions)
/// 4. Instance method with 'self' (for methods on &self/&mut self)
macro_rules! register_with_guard {
    // Pattern 1: With error converter - for functions that return Result<T, E>
    ($engine:expr, $name:expr, $return_type:ty, $func:path, $error_converter:path $(, $arg:ident : $type:ty $(=> $cast_type:ty)?)*) => {
        $engine.register_fn(
            $name,
            move |context: NativeCallContext $(, $arg: $type)*|
                  -> Result<$return_type, Box<rhai::EvalAltResult>> {
                let _guard = get_rhai_context_guard(&context);
                match $func($($crate::convert_param_value!($arg $(=> $cast_type)?)),*) {
                    Ok(result) => Ok(result),
                    Err(e) => $error_converter(&e),
                }
            },
        )
    };

    // Pattern 2: With error converter and execution context
    ($engine:expr, $name:expr, $return_type:ty, $func:path, $error_converter:path, execution_context: $execution_context:expr $(, $arg:ident : $type:ty $(=> $cast_type:ty)?)*) => {
        let ctx = $execution_context.clone();
        $engine.register_fn(
            $name,
            move |context: NativeCallContext $(, $arg: $type)*|
                  -> Result<$return_type, Box<rhai::EvalAltResult>> {
                let _guard = get_rhai_context_guard(&context);
                match $func($($crate::convert_param_value!($arg $(=> $cast_type)?)),*) {
                    Ok(result) => Ok(result),
                    Err(e) => $error_converter(&e, ctx.as_ref()),
                }
            },
        )
    };

    // Pattern 3: Without error converter - for static functions (i.e. constructors that return Self directly)
    ($engine:expr, $name:expr, $return_type:ty, $func:path $(, $arg:ident : $type:ty $(=> $cast_type:ty)?)*) => {
        $engine.register_fn(
            $name,
            move |context: NativeCallContext $(, $arg: $type)*|
                  -> Result<$return_type, Box<rhai::EvalAltResult>> {
                let _guard = get_rhai_context_guard(&context);
                Ok($func($($crate::convert_param_value!($arg $(=> $cast_type)?)),*))
            },
        )
    };

    // Pattern 4: Instance method with 'self' marker - for functions on &self/&mut self returning plain values
        ($engine:expr, $name:expr, $return_type:ty, self, $self_type:ty, $method:path $(, $arg:ident : $type:ty $(=> $cast_type:ty)?)*) => {
            $engine.register_fn(
                $name,
                move |context: NativeCallContext, slf: &mut $self_type $(, $arg: $type)*|
                    -> Result<$return_type, Box<rhai::EvalAltResult>> {
                    let _guard = get_rhai_context_guard(&context);
                    Ok($method(slf $(, $crate::convert_param_value!($arg $(=> $cast_type)?))*))
                },
            )
        };

}

/// Helper macro to convert parameter types for Rhai registration.
/// Converts reference types to value types (except &str) so Rhai can accept values from scripts.
#[macro_export]
macro_rules! convert_param_type {
    (&str) => {
        &str
    }; // Keep &str as-is for efficiency
    (&$type:ty) => {
        $type
    }; // Convert &Type to Type for Rhai registration
    ($type:ty) => {
        $type
    }; // Keep other types as-is
}

/// Helper macro to convert parameter values during function calls.
///
/// Enables type conversion when passing parameters from Rhai (i64-based) to Rust functions
/// that may expect different numeric types (u64, u32, etc.).
///
/// # Syntax
/// - `convert_param_value!(arg)` - No conversion
/// - `convert_param_value!(arg => Type)` - Checked conversion using `TryFrom`
/// - `convert_param_value!(arg |> transform_fn)` - Infallible transform function
/// - `convert_param_value!(arg |>? transform_fn)` - Fallible transform function (for complex conversions like Array to Vec)
#[macro_export]
macro_rules! convert_param_value {
    // No conversion
    ($arg:ident) => {
        $arg
    };

    // Checked conversion using TryFrom
    ($arg:ident => $cast_type:ty) => {
        <$cast_type>::try_from($arg).map_err(|e| -> Box<rhai::EvalAltResult> {
            format!("Parameter '{}' conversion failed: {}", stringify!($arg), e).into()
        })?
    };

    // apply custom transformer (infallible). Macro syntax stolen from F#
    ($arg:ident |> $transform:path) => {
        $transform($arg)
    };

    // apply custom transformer (fallible) with `?` for error propagation
    // The transform function must return Result<T, Box<EvalAltResult>>
    ($arg:ident |>? $transform:path) => {
        $transform($arg)?
    };
}

/// Helper macro to convert return values from getters with runtime checking.
///
/// # Syntax
/// - `convert_return_value!(value)` - No conversion
/// - `convert_return_value!(value, Type)` - Checked conversion
#[macro_export]
macro_rules! convert_return_value {
    // No conversion
    ($value:expr) => {
        $value
    };

    // Checked conversion
    ($value:expr, $to_type:ty) => {
        <$to_type>::try_from($value).map_err(|e| -> Box<rhai::EvalAltResult> {
            format!("Return value conversion failed: {}", e).into()
        })?
    };
}

// ============================================================================
// Internal Implementation Helpers
// ============================================================================
// These macros contain the shared implementation logic used by the public
// registration macros. They are not intended to be used directly.

/// Internal helper macro for the method call body.
/// Handles both with-auth and no-auth variants.
#[doc(hidden)]
#[macro_export]
macro_rules! __direct_safe_method_call {
    // With cedar auth - calls method with &auth as first parameter
    (with_auth, $slf:ident, $auth:ident, $method:ident $(, $arg:expr)*) => {
        $slf.$method(&$auth $(, $arg)*)
    };
    // Without cedar auth - calls method directly
    (no_auth, $slf:ident, $method:ident $(, $arg:expr)*) => {
        $slf.$method($($arg),*)
    };
}

/// Internal helper macro for the full registration body.
/// Handles setup, guard, method call, and error conversion.
#[doc(hidden)]
#[macro_export]
macro_rules! __direct_safe_fn_register {
    // Pattern: with cedar auth, no transform
    (with_auth, $engine:expr, $name:expr, $underlying_type:ty, $method:ident,
     $cedar_auth:expr, $return_wrapper:ty, $error_converter:path
     $(, $arg:ident : $type:ty $(=> $cast_type:ty)?)*) => {
        let auth = $cedar_auth.clone();
        $engine.register_fn($name, move |context: NativeCallContext, slf: &mut $underlying_type
            $(, $arg: $crate::convert_param_type!($type))*|
            -> Result<$return_wrapper, Box<rhai::EvalAltResult>> {
            let _guard = get_rhai_context_guard(&context);
            match $crate::__direct_safe_method_call!(with_auth, slf, auth, $method
                $(, $crate::convert_param_value!($arg $(=> $cast_type)?))*)
            {
                Ok(result) => Ok(result),
                Err(e) => $error_converter(&e),
            }
        });
    };

    // Pattern: without cedar auth, no transform (supports |> and |>? for input transforms)
    (no_auth, $engine:expr, $name:expr, $underlying_type:ty, $method:ident,
     $return_wrapper:ty, $error_converter:path
     $(, $arg:ident : $type:ty $(=> $cast_type:ty)? $(|> $transform:path)? $(|>? $fallible_transform:path)?)*) => {
        $engine.register_fn($name, move |context: NativeCallContext, slf: &mut $underlying_type
            $(, $arg: $crate::convert_param_type!($type))*|
            -> Result<$return_wrapper, Box<rhai::EvalAltResult>> {
            let _guard = get_rhai_context_guard(&context);
            match $crate::__direct_safe_method_call!(no_auth, slf, $method
                $(, $crate::convert_param_value!($arg $(=> $cast_type)? $(|> $transform)? $(|>? $fallible_transform)?))*)
            {
                Ok(result) => Ok(result),
                Err(e) => $error_converter(&e),
            }
        });
    };

    // Pattern: with cedar auth, with transform
    (with_auth_transform, $engine:expr, $name:expr, $underlying_type:ty, $method:ident,
     $cedar_auth:expr, $return_wrapper:ty, $transform_fn:expr, $error_converter:path
     $(, $arg:ident : $type:ty $(=> $cast_type:ty)? $(|> $transform:path)?)*) => {
        let auth = $cedar_auth.clone();
        $engine.register_fn($name, move |context: NativeCallContext, slf: &mut $underlying_type
            $(, $arg: $crate::convert_param_type!($type))*|
            -> Result<$return_wrapper, Box<rhai::EvalAltResult>> {
            let _guard = get_rhai_context_guard(&context);
            match $crate::__direct_safe_method_call!(with_auth, slf, auth, $method
                $(, $crate::convert_param_value!($arg $(=> $cast_type)? $(|> $transform)?))*)
            {
                Ok(result) => ($transform_fn)(result),
                Err(e) => $error_converter(&e),
            }
        });
    };

    // Pattern: without cedar auth, with transform
    (no_auth_transform, $engine:expr, $name:expr, $underlying_type:ty, $method:ident,
     $return_wrapper:ty, $transform_fn:expr, $error_converter:path
     $(, $arg:ident : $type:ty $(=> $cast_type:ty)? $(|> $transform:path)?)*) => {
        $engine.register_fn($name, move |context: NativeCallContext, slf: &mut $underlying_type
            $(, $arg: $crate::convert_param_type!($type))*|
            -> Result<$return_wrapper, Box<rhai::EvalAltResult>> {
            let _guard = get_rhai_context_guard(&context);
            match $crate::__direct_safe_method_call!(no_auth, slf, $method
                $(, $crate::convert_param_value!($arg $(=> $cast_type)? $(|> $transform)?))*)
            {
                Ok(result) => ($transform_fn)(result),
                Err(e) => $error_converter(&e),
            }
        });
    };
}

/// Simplified macro for registering Rhai functions with correct argument passing.
/// Supports flexible patterns with proper reference/value handling through helpers.
///
/// This macro automatically converts reference parameter types (except &str) to value types
/// for Rhai registration while keeping the underlying method call unchanged.
///
/// # Execution Context
///
/// The optional `execution_context` parameter enables critical error handling. When provided,
/// the error converter can signal script termination through the shared termination flag for
/// critical errors (e.g., `PrivilegeError` during privilege operations).
///
/// # Example Usage
///
/// Basic without execution context:
/// ```ignore
/// register_direct_safe_fn!(
///     engine,
///     "iostat",
///     Filesystems,
///     iostat,
///     cedar_auth,
///     -> IoStatSnapshot,
///     crate::errors::convert_to_rhai_error;
///     tests: { positive: "test_get_iostat_success", negative: "test_iostat_permission_denied" }
/// );
/// ```
///
/// With transform, without execution context:
/// ```ignore
/// register_direct_safe_fn!(
///     engine,
///     "processes",
///     RcProcessManager,
///     safe_processes,
///     cedar_auth,
///     -> Array,
///     transform: |processes: Vec<ProcessInfo>| -> Result<Array, Box<EvalAltResult>> {
///         Ok(processes.into_iter().map(Dynamic::from).collect())
///     },
///     crate::errors::convert_to_rhai_error;
///     tests: { positive: "test_get_processes_success", negative: "test_get_processes_unauthorized" }
/// );
/// ```
///
/// With execution context:
/// ```ignore
/// register_direct_safe_fn!(
///     engine,
///     "read",
///     SysctlManager,
///     read,
///     cedar_auth,
///     -> String,
///     crate::errors::convert_to_rhai_error_with_execution_context,
///     execution_context: execution_context.cloned(),
///     key: &str;
///     tests: { positive: "test_read_success", negative: "test_read_unauthorized" }
/// );
/// ```
///
/// With transform + execution context:
/// ```ignore
/// register_direct_safe_fn!(
///     engine,
///     "find",
///     SysctlManager,
///     find,
///     cedar_auth,
///     -> Array,
///     transform: |entries: Vec<SysctlEntry>| -> Result<Array, Box<EvalAltResult>> {
///         Ok(entries.into_iter().map(Dynamic::from).collect())
///     },
///     crate::errors::convert_to_rhai_error_with_execution_context,
///     execution_context: execution_context.cloned(),
///     pattern: &str;
///     tests: { positive: "test_find_success", negative: "test_find_unauthorized" }
/// );
/// ```
#[macro_export]
macro_rules! register_direct_safe_fn {
    // Register with configurable error converter
    (
        $engine:expr,
        $name:expr,
        $underlying_type:ty,
        $method:ident,
        $cedar_auth:expr,
        -> $return_wrapper:ty,
        $error_converter:path
        $(, $arg:ident : $type:ty $(=> $cast_type:ty)?)*;
        tests: { positive: $positive_test:literal, negative: $negative_test:literal }
    ) => {
        $crate::__direct_safe_fn_register!(with_auth, $engine, $name, $underlying_type, $method,
            $cedar_auth, $return_wrapper, $error_converter
            $(, $arg : $type $(=> $cast_type)?)*);
    };

    // Register with execution context
    (
        $engine:expr,
        $name:expr,
        $underlying_type:ty,
        $method:ident,
        $cedar_auth:expr,
        -> $return_wrapper:ty,
        $error_converter:path,
        execution_context: $execution_context:expr
        $(, $arg:ident : $type:ty)*;
        tests: { positive: $positive_test:literal, negative: $negative_test:literal }
    ) => {
        let auth = $cedar_auth.clone();
        let ctx = $execution_context.clone();
        $engine.register_fn($name, move |context: NativeCallContext, slf: &mut $underlying_type $(, $arg: $crate::convert_param_type!($type))*| -> Result<$return_wrapper, Box<rhai::EvalAltResult>> {
            let _guard = get_rhai_context_guard(&context);
            match slf.$method(&auth $(, $arg)*) {
                Ok(result) => Ok(result),
                Err(e) => $error_converter(&e, ctx.as_ref()),
            }
        });
    };

     // For transformations with configurable error converter
    (
        $engine:expr,
        $name:expr,
        $underlying_type:ty,
        $method:ident,
        $cedar_auth:expr,
        -> $return_wrapper:ty,
        transform: $transform_fn:expr,
        $error_converter:path
        $(, $arg:ident : $type:ty $(=> $cast_type:ty)? $(|> $transform:path)?)*;
        tests: { positive: $positive_test:literal, negative: $negative_test:literal }
    ) => {
        // Compile-time check: Enforce that build.rs validation is present
        const _: &str = env!("RHAI_SAFE_FN_VALIDATION_ENABLED", concat!(
            "\n\n",
            "════════════════════════════════════════════════════════════════════════════════\n",
            "ERROR: Using register_direct_safe_fn! with 'tests:' parameter requires build.rs validation\n",
            "════════════════════════════════════════════════════════════════════════════════\n",
            "\n",
            "To fix this:\n",
            "\n",
            "1. Add to Cargo.toml [build-dependencies]:\n",
            "   runner-registrar-utils = { version = \"*\", features = [\"build-validation\"] }\n",
            "\n",
            "2. Create build.rs in your package root:\n",
            "\n",
            "   use std::env;\n",
            "   use std::path::Path;\n",
            "\n",
            "   fn main() {\n",
            "       let manifest_dir = env::var(\"CARGO_MANIFEST_DIR\").unwrap();\n",
            "       let registry_file = Path::new(&manifest_dir).join(\"src/registry.rs\");\n",
            "       let tests_dir = Path::new(&manifest_dir).join(\"tests\");\n",
            "       rex_runner_registrar_utils::build_validation::validate_macro_tests(\n",
            "           registry_file.to_str().unwrap(),\n",
            "           tests_dir.to_str().unwrap(),\n",
            "       );\n",
            "   }\n",
            "\n",
            "════════════════════════════════════════════════════════════════════════════════\n"
        ));

        $crate::__direct_safe_fn_register!(with_auth_transform, $engine, $name, $underlying_type, $method,
            $cedar_auth, $return_wrapper, $transform_fn, $error_converter
            $(, $arg : $type $(=> $cast_type)? $(|> $transform)?)*);
    };

    // For transformations with execution context
    (
        $engine:expr,
        $name:expr,
        $underlying_type:ty,
        $method:ident,
        $cedar_auth:expr,
        -> $return_wrapper:ty,
        transform: $transform_fn:expr,
        $error_converter:path,
        execution_context: $execution_context:expr
        $(, $arg:ident : $type:ty $(=> $cast_type:ty)? $(|> $transform:path)?)*;
        tests: { positive: $positive_test:literal, negative: $negative_test:literal }
    ) => {
        let auth = $cedar_auth.clone();
        let ctx = $execution_context.clone();
        $engine.register_fn($name, move |context: NativeCallContext, slf: &mut $underlying_type $(, $arg: $crate::convert_param_type!($type))*| -> Result<$return_wrapper, Box<rhai::EvalAltResult>> {
            let _guard = get_rhai_context_guard(&context);
            match slf.$method(&auth $(, $arg)*) {
                Ok(result) => match $transform_fn(result) {
                    Ok(transformed) => Ok(transformed),
                    Err(e) => Err(e),
                },
                Err(e) => $error_converter(&e, ctx.as_ref()),
            }
        });
    };
}

/// Registers instance methods that don't require Cedar authorization.
/// Similar to `register_direct_safe_fn!` but without `CedarAuth` parameter.
///
/// For methods with signature: `fn(&self, args...) -> Result<T, E>`
///
/// # Usage (without transform):
/// ```js
/// register_direct_safe_no_cedar_fn!(
///     engine,
///     "verify_cert_chain",
///     RcFileHandle,
///     verify_cert_chain,
///     -> (),
///     crate::errors::convert_to_rhai_error,
///     root_ca_fh: RcFileHandle,
///     intermediate_ca_fh: RcFileHandle;
///     tests: { positive: "test_verify_success", negative: "test_verify_fails" }
/// );
/// ```
#[macro_export]
macro_rules! register_direct_safe_no_cedar_fn {
    // Register without cedar auth, no transform (supports |> and |>? for input transforms)
    (
        $engine:expr,
        $name:expr,
        $underlying_type:ty,
        $method:ident,
        -> $return_wrapper:ty,
        $error_converter:path
        $(, $arg:ident : $type:ty $(=> $cast_type:ty)? $(|> $transform:path)? $(|>? $fallible_transform:path)?)*;
        tests: { positive: $positive_test:literal, negative: $negative_test:literal }
    ) => {
        $crate::__direct_safe_fn_register!(no_auth, $engine, $name, $underlying_type, $method,
            $return_wrapper, $error_converter
            $(, $arg : $type $(=> $cast_type)? $(|> $transform)? $(|>? $fallible_transform)?)*);
    };

    // Register without cedar auth, with transform
    (
        $engine:expr,
        $name:expr,
        $underlying_type:ty,
        $method:ident,
        -> $return_wrapper:ty,
        transform: $transform_fn:expr,
        $error_converter:path
        $(, $arg:ident : $type:ty $(=> $cast_type:ty)? $(|> $transform:path)?)*;
        tests: { positive: $positive_test:literal, negative: $negative_test:literal }
    ) => {
        // Compile-time check: Enforce that build.rs validation is present
        const _: &str = env!("RHAI_SAFE_FN_VALIDATION_ENABLED", concat!(
            "\n\n",
            "════════════════════════════════════════════════════════════════════════════════\n",
            "ERROR: Using register_direct_safe_no_cedar_fn! with 'tests:' parameter requires build.rs validation\n",
            "════════════════════════════════════════════════════════════════════════════════\n",
            "\n",
            "To fix this:\n",
            "\n",
            "1. Add to Cargo.toml [build-dependencies]:\n",
            "   runner-registrar-utils = { version = \"*\", features = [\"build-validation\"] }\n",
            "\n",
            "2. Create build.rs in your package root:\n",
            "\n",
            "   use std::env;\n",
            "   use std::path::Path;\n",
            "\n",
            "   fn main() {\n",
            "       let manifest_dir = env::var(\"CARGO_MANIFEST_DIR\").unwrap();\n",
            "       let registry_file = Path::new(&manifest_dir).join(\"src/registry.rs\");\n",
            "       let tests_dir = Path::new(&manifest_dir).join(\"tests\");\n",
            "       rex_runner_registrar_utils::build_validation::validate_macro_tests(\n",
            "           registry_file.to_str().unwrap(),\n",
            "           tests_dir.to_str().unwrap(),\n",
            "       );\n",
            "   }\n",
            "\n",
            "════════════════════════════════════════════════════════════════════════════════\n"
        ));

        $crate::__direct_safe_fn_register!(no_auth_transform, $engine, $name, $underlying_type, $method,
            $return_wrapper, $transform_fn, $error_converter
            $(, $arg : $type $(=> $cast_type)? $(|> $transform)?)*);
    };
}

/// Registers `derive_builder` setter methods that clone and return the builder for method chaining.
/// This handles the pattern where builder methods modify the builder and return a clone for chaining.
///
/// # Arguments
/// * `engine` - The Rhai engine instance to register the setter function with
/// * `method_name` - Identifier for the setter method name (e.g., `size`, `format`)
/// * `builder_type` - The derive builder type that contains the setter method
/// * `param_type` - The parameter type accepted by the setter method
/// * `transform` - Optional closure to transform the parameter before passing to the setter
#[macro_export]
macro_rules! register_derive_builder_setter {
    // Pattern 1: With checked type conversion
    ($engine:expr, $method_name:ident, $builder_type:ty, $param_type:ty => $cast_type:ty) => {
        $engine.register_fn(
            stringify!($method_name),
            |builder: &mut $builder_type,
             param: $param_type|
             -> Result<$builder_type, Box<rhai::EvalAltResult>> {
                let converted =
                    <$cast_type>::try_from(param).map_err(|e| -> Box<rhai::EvalAltResult> {
                        format!(
                            "Parameter conversion failed for {}: {}",
                            stringify!($method_name),
                            e
                        )
                        .into()
                    })?;
                builder.$method_name(converted);
                Ok(builder.clone())
            },
        );
    };

    // Pattern 2: Setter without transform (direct pass-through)
    ($engine:expr, $method_name:ident, $builder_type:ty, $param_type:ty) => {
        $engine.register_fn(
            stringify!($method_name),
            |builder: &mut $builder_type, param: $param_type| -> $builder_type {
                builder.$method_name(param);
                builder.clone()
            },
        );
    };

    // Pattern 3: Setter with transform closure
    ($engine:expr, $method_name:ident, $builder_type:ty, $param_type:ty, $transform:expr) => {
        $engine.register_fn(
            stringify!($method_name),
            |builder: &mut $builder_type, param: $param_type| -> $builder_type {
                let transformed = ($transform)(param);
                builder.$method_name(transformed);
                builder.clone()
            },
        );
    };

    // Setter with result returning transform closure
    ($engine:expr, $method_name:ident, $builder_type:ty, $param_type:ty, transform: $transform:expr) => {
        $engine.register_fn(
            stringify!($method_name),
            |builder: &mut $builder_type,
             param: $param_type|
             -> Result<$builder_type, Box<rhai::EvalAltResult>> {
                let transformed = ($transform)(param)?;
                builder.$method_name(transformed);
                Ok(builder.clone())
            },
        );
    };
}

/// Registers a derive builder with type, constructor, setters, and build method
/// for options provided to Rhai APIs.
/// This macro handles the full registration pattern for derive builders.
///
/// # Arguments
/// * `engine` - The Rhai engine instance to register the builder with
/// * `builder_type` - The derive builder type (e.g., `TruncateOptionsBuilder`)
/// * `constructor_name` - String name for the constructor function in Rhai (e.g., `"TruncateOptions"`)
/// * `build_return_type` - The type returned by the `build()` method (e.g., `TruncateOptions`)
/// * `setters` - Array of tuples containing setter method identifiers and their parameter types, with optional transform closures
///   - Simple: `(setter_name, param_type)` - Direct pass-through
///   - With transform: `(setter_name, param_type, transform: |param: RhaiType| -> RustType { /* code */ })`
/// * `enums` - Optional array of enum types to register with their modules
#[macro_export]
macro_rules! register_derive_builder_options {
    (
        $engine:expr,
        $builder_type:ty,
        $constructor_name:expr,
        $build_return_type:ty,
        setters: [$($setter:tt),*]
        $(, enums: [$(($enum_type:ty, $enum_name:expr, $enum_module:path)),*])?
    ) => {
        // Register the builder type and constructor
        $engine.register_type::<$builder_type>();
        $engine.register_fn($constructor_name, <$builder_type>::default);

        // Register all setter methods - supporting both simple and transform patterns
        $(
            $crate::register_derive_builder_options!(@setter $engine, $builder_type, $setter);
        )*

        $engine.register_fn(
            "build",
            |builder: &mut $builder_type| -> Result<$build_return_type, Box<rhai::EvalAltResult>> {
                builder.build().map_err(|e| format!("{e:#}").into())
            },
        );
    };

    // setter with => conversion
    (@setter $engine:expr, $builder_type:ty, ($setter_name:ident, $param_type:ty => $cast_type:ty)) => {
        $crate::register_derive_builder_setter!($engine, $setter_name, $builder_type, $param_type => $cast_type);
    };

    // setter without transform
    (@setter $engine:expr, $builder_type:ty, ($setter_name:ident, $param_type:ty)) => {
        $crate::register_derive_builder_setter!($engine, $setter_name, $builder_type, $param_type);
    };

    // setter with transform closure
    (@setter $engine:expr, $builder_type:ty, ($setter_name:ident, $param_type:ty, transform: $transform:expr)) => {
        $crate::register_derive_builder_setter!($engine, $setter_name, $builder_type, $param_type, $transform);
    };
}

/// Registers multiple Rhai getters with logging guards (batch registration)
/// All getters use their Rust method name as the Rhai function name
///
/// This handles Option<T> extraction for Rhai as well. If a getter returns Some
/// value, then the value is returned. Otherwise none is returned.
///
/// # Supported Patterns
///
/// 1. Simple getter (no conversion):
/// ```js
/// register_getters_with_guard!(engine, MyType, [field_name]);
/// ```
///
/// 2. Option<T> with conversion:
/// ```js
/// register_getters_with_guard!(engine, ElfInfo, [(execfn, Option<String> => String)]);
/// ```
///
/// 3. Type conversion:
/// ```js
/// register_getters_with_guard!(engine, MyType, [(field_name, u64 => i64)]);
/// ```
///
/// 4. Vec<T> to Array conversion (automatic):
/// ```js
/// register_getters_with_guard!(engine, Network, [(addresses, Vec<String> => Array)]);
/// ```
/// This automatically converts `Vec<T>` to Rhai `Array` by mapping each element to `Dynamic`.
///
/// # Example Usage
///
/// To register:
/// ```js
/// register_getters_with_guard!(engine, Network, [
///     interface_name,
///     (addresses, Vec<String> => Array)
/// ]);
/// ```
///
/// To use in Rhai Script:
/// ```js
/// let network = system.ip_addresses()[0];
/// let name = network.interface_name;      // String
/// let addrs = network.addresses;          // Array of strings
///
/// for addr in addrs {
///     print(addr);  // Each address is a string
/// }
///
/// // For Option<T> types:
/// if elf_info.execfn != () {
///     // this means it's not None and a String
/// }
/// ```
#[macro_export]
macro_rules! register_getters_with_guard {
    // Main pattern - delegates to @single
    ($engine:expr, $type:ty, [$($item:tt),* $(,)?]) => {
        $(
            $crate::register_getters_with_guard!(@single $engine, $type, $item);
        )*
    };

    // Helper: getter without conversion
    (@single $engine:expr, $type:ty, $getter:ident) => {
        $engine.register_get(stringify!($getter), move |context: NativeCallContext, obj: &mut $type| {
            let _guard = get_rhai_context_guard(&context);
            <$type>::$getter(obj).clone()
        });
    };

    // Helper: Vec<T> to Array conversion (automatic transformation)
    (@single $engine:expr, $type:ty, ($getter:ident, Vec<$inner_type:ty> => Array)) => {
        $engine.register_get(stringify!($getter), move |context: NativeCallContext, obj: &mut $type|
            -> Result<rhai::Array, Box<rhai::EvalAltResult>> {
            let _guard = get_rhai_context_guard(&context);
            let result: Vec<$inner_type> = <$type>::$getter(obj).clone();
            Ok(result.into_iter().map(rhai::Dynamic::from).collect())
        });
    };

    // Helper: Option<T> getter with conversion to Dynamic (returns UNIT for None or conversion failure)
    (@single $engine:expr, $type:ty, ($getter:ident, Option<$inner_from:ty> => $to_type:ty)) => {
        $engine.register_get(stringify!($getter), move |context: NativeCallContext, obj: &mut $type| -> rhai::Dynamic {
            let _guard = get_rhai_context_guard(&context);
            let result: Option<$inner_from> = <$type>::$getter(obj).clone();
            result.and_then(|v| <$to_type>::try_from(v).ok())
                .map_or(rhai::Dynamic::UNIT, |v| rhai::Dynamic::from(v))
        });
    };

    // Helper: getter with conversion (non-Option types)
    (@single $engine:expr, $type:ty, ($getter:ident, $from_type:ty => $to_type:ty)) => {
        $engine.register_get(stringify!($getter), move |context: NativeCallContext, obj: &mut $type|
            -> Result<$to_type, Box<rhai::EvalAltResult>> {
            let _guard = get_rhai_context_guard(&context);
            let result = <$type>::$getter(obj).clone();
            Ok($crate::convert_return_value!(result, $to_type))
        });
    };
}

/// Registers a `to_string` function for a type using `serde_json` serialization
#[macro_export]
macro_rules! register_to_string_with_json {
    ($engine:expr, $type:ty) => {
        $engine.register_fn("to_string", |obj: &mut $type| -> String {
            serde_json::to_string_pretty(obj)
                .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize: {}\"}}", e))
        });
    };
}

/// Registers a Rhai getter with a logging guard
/// Supports optional transform functions to convert the result before returning to Rhai
#[macro_export]
macro_rules! register_getter_with_guard {
    // Pattern 1: Explicit name with transform
    ($engine:expr, $name:expr, $type:ty, $method:ident, transform: $transform_fn:expr) => {
        $engine.register_get($name, move |context: NativeCallContext, obj: &mut $type| {
            let _guard = get_rhai_context_guard(&context);
            let result = <$type>::$method(obj).clone();
            ($transform_fn)(result)
        });
    };

    // Pattern 2: Inferred name with transform
    ($engine:expr, $type:ty, $method:ident, transform: $transform_fn:expr) => {
        $engine.register_get(
            stringify!($method),
            move |context: NativeCallContext, obj: &mut $type| {
                let _guard = get_rhai_context_guard(&context);
                let result = <$type>::$method(obj).clone();
                ($transform_fn)(result)
            },
        );
    };

    // Pattern 3: Explicit name (existing - no transform)
    ($engine:expr, $name:expr, $type:ty, $method:ident) => {
        $engine.register_get($name, move |context: NativeCallContext, obj: &mut $type| {
            let _guard = get_rhai_context_guard(&context);
            <$type>::$method(obj).clone()
        });
    };

    // Pattern 4: Inferred name (existing - no transform)
    ($engine:expr, $type:ty, $method:ident) => {
        $engine.register_get(
            stringify!($method),
            move |context: NativeCallContext, obj: &mut $type| {
                let _guard = get_rhai_context_guard(&context);
                <$type>::$method(obj).clone()
            },
        );
    };

    // Pattern 5: Simple conversion with explicit name, using `=>` syntax
    ($engine:expr, $name:expr, $type:ty, $method:ident, $from_type:ty => $to_type:ty) => {
        $engine.register_get(
            $name,
            move |context: NativeCallContext,
                  obj: &mut $type|
                  -> Result<$to_type, Box<rhai::EvalAltResult>> {
                let _guard = get_rhai_context_guard(&context);
                let result = <$type>::$method(obj).clone();
                Ok($crate::convert_return_value!(result, $to_type))
            },
        );
    };

    // Pattern 6: Simple conversion with inferred name, using `=>` syntax
    ($engine:expr, $type:ty, $method:ident, $from_type:ty => $to_type:ty) => {
        $engine.register_get(
            stringify!($method),
            move |context: NativeCallContext,
                  obj: &mut $type|
                  -> Result<$to_type, Box<rhai::EvalAltResult>> {
                let _guard = get_rhai_context_guard(&context);
                let result = <$type>::$method(obj).clone();
                Ok($crate::convert_return_value!(result, $to_type))
            },
        );
    };
}

/// Register the `to_map` function in Rhai for multiple input types that converts objects to Rhai Maps.
/// The input types must implement the Serialize trait.
/// NB: We use `to_dynamic` instead of `Dynamic::from` because it converts all int types to i64.
/// Otherwise, we'd have to do that conversion manually.
#[macro_export]
macro_rules! register_map_serializers {
    ($engine:expr, [$($type:ty),* $(,)?]) => {
        $(
            $crate::register_map_serializers!(@single $engine, $type);
        )*
    };

    (@single $engine:expr, $type:ty) => {
        $engine.register_fn("to_map", move |_ctx: NativeCallContext, slf: &mut $type| -> Result<Dynamic, Box<EvalAltResult>> {
            to_dynamic(&slf)
        });
    };
}

// ============================================================================
// Build-Time Validation Utilities
// ============================================================================
// This module is only available when the "build-validation" feature is enabled
// and is intended to be used from build.rs scripts.

/// Registers a method that returns `Option<T>` as a Rhai function that returns `Dynamic`.
/// Returns `Dynamic::UNIT` for `None`, or `Dynamic::from(value)` for `Some(value)`.
///
/// # Usage
/// ```ignore
/// register_option_as_dynamic!(engine, "method_name", OwnerType, method_name);
/// ```
#[macro_export]
macro_rules! register_option_as_dynamic {
    ($engine:expr, $fn_name:expr, $owner_type:ty, $method:ident) => {
        $engine.register_fn($fn_name, |owner: &mut $owner_type| -> rhai::Dynamic {
            owner
                .$method()
                .map_or(rhai::Dynamic::UNIT, rhai::Dynamic::from)
        });
    };
}

#[cfg(feature = "build-validation")]
pub mod build_validation {
    use std::fs;
    use std::path::Path;
    use std::process;

    /// Validates that all test functions declared in registry files exist in test files.
    ///
    /// This function is designed to be called from build.rs scripts to verify that
    /// test function names specified in the `register_direct_safe_fn!` macro's
    /// `tests:` parameter actually exist in the package's test files.
    pub fn validate_macro_tests(registry_file_path: &str, tests_dir_path: &str) {
        println!("cargo:rerun-if-changed={tests_dir_path}");
        println!("cargo:rerun-if-changed={registry_file_path}");

        // Set a compile-time environment variable to indicate validation has run
        // This allows the macro to enforce that build.rs validation exists
        println!("cargo:rustc-env=RHAI_SAFE_FN_VALIDATION_ENABLED=1");

        // Read the registry file
        let registry_content = match fs::read_to_string(registry_file_path) {
            Ok(content) => content,
            Err(e) => {
                eprintln!("Failed to read {registry_file_path}: {e}");
                process::exit(1);
            }
        };

        // Read all test files
        let test_content = read_all_test_files(Path::new(tests_dir_path));

        // Extract and validate test function declarations
        validate_test_functions(&registry_content, &test_content);
    }

    /// Reads all .rs files in the tests directory and combines their content.
    ///
    /// This function recursively reads only the top-level .rs files in the tests directory.
    /// It does not traverse subdirectories.
    fn read_all_test_files(tests_dir: &Path) -> String {
        let mut combined_content = String::new();

        if !tests_dir.exists() {
            eprintln!("Tests directory does not exist: {}", tests_dir.display());
            process::exit(1);
        }

        let entries = match fs::read_dir(tests_dir) {
            Ok(entries) => entries,
            Err(e) => {
                eprintln!("Failed to read tests directory: {e}");
                process::exit(1);
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && path.extension().is_some_and(|ext| ext == "rs") {
                match fs::read_to_string(&path) {
                    Ok(content) => {
                        combined_content.push_str(&content);
                        combined_content.push('\n');
                    }
                    Err(e) => {
                        eprintln!("Failed to read test file {}: {}", path.display(), e);
                        process::exit(1);
                    }
                }
            }
        }

        combined_content
    }

    /// Validates that all test functions declared in macro calls exist in the test files.
    ///
    /// This function looks for patterns like:
    /// ```text
    /// tests: { positive: "test_function_name", negative: "test_other_function" }
    /// ```
    ///
    /// It then verifies that both test functions are defined somewhere in the test files.
    fn validate_test_functions(registry_content: &str, test_content: &str) {
        // Filter out comment lines before regex matching
        let non_comment_content: String = registry_content
            .lines()
            .filter(|line| {
                let trimmed = line.trim_start();
                !trimmed.starts_with("///") && !trimmed.starts_with("//")
            })
            .collect::<Vec<_>>()
            .join("\n");

        // Find all test declarations in the format:
        // tests: { positive: "test_name", negative: "test_name" }
        let test_pattern = match regex::Regex::new(
            r#"tests:\s*\{\s*positive:\s*"([^"]+)"\s*,\s*negative:\s*"([^"]+)"\s*\}"#,
        ) {
            Ok(pattern) => pattern,
            Err(e) => {
                eprintln!("Failed to compile regex pattern: {e}");
                process::exit(1);
            }
        };

        for capture in test_pattern.captures_iter(&non_comment_content) {
            let positive_test = &capture[1];
            let negative_test = &capture[2];

            // Check if positive test function exists
            let positive_pattern = format!("fn {positive_test}(");
            assert!(
                test_content.contains(&positive_pattern),
                "Missing positive test function '{positive_test}' in tests/. Please ensure this test function exists."
            );

            // Check if negative test function exists
            let negative_pattern = format!("fn {negative_test}(");
            assert!(
                test_content.contains(&negative_pattern),
                "Missing negative test function '{negative_test}' in tests/. Please ensure this test function exists."
            );

            println!("✓ Validated test functions: {positive_test} and {negative_test}");
        }
    }
}
