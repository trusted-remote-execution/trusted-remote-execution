#![deny(missing_docs)]
//! This module provides documentation for utility functions for generating random values exposed to Rhai scripts.

#![allow(
    unused_variables,
    unreachable_code,
    clippy::unreachable,
    unused_mut,
    clippy::needless_pass_by_value,
    clippy::too_many_arguments
)]

/// Generates a random alphanumeric string of the specified length.
///
/// # Example
///
/// ```
/// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
/// # let (mut scope, engine) = create_temp_test_env();
/// # let result = engine.eval_with_scope::<()>(
/// #     &mut scope,
/// #     r#"
/// // Generate a random 10-character string for a temp file name
/// let tmp_filename = "tmp." + random_alphanumeric(10); // "tmp.WksppE3et4"
/// #     "#);
/// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
/// ```
pub fn random_alphanumeric(length: i64) -> String {
    unreachable!("This function exists only for documentation.")
}
