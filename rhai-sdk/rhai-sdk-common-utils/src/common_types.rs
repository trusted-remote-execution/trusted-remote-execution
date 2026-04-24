#![deny(missing_docs)]
//! Common types and documentation for Rhai SDK utilities.
//!
//! This module provides wrapper types and documentation for exposing
//! `SDKCommonUtils` types to Rhai scripts.

#![allow(
    unused_variables,
    unreachable_code,
    clippy::unreachable,
    unused_mut,
    clippy::needless_pass_by_value,
    clippy::too_many_arguments,
    clippy::return_self_not_must_use
)]

use rhai::EvalAltResult;

/// A wrapper around [`DateTime`] for use with Rhai.
/// This struct represents [`DateTime`] in a format that is compatible with expected Rhai
/// function signature.
///
/// # Operators
/// [`DateTime`] supports the following operators:
/// - Arithmetic: `+`, `-` (with i64 seconds)
/// - Comparison: `==`, `!=`, `<`, `<=`, `>`, `>=`
/// - Subtraction: `DateTime - DateTime` returns i64 (seconds difference)
#[derive(Debug, Clone, Copy)]
pub struct DateTime;

/// A wrapper around [`DateTimeFormat`] for use with Rhai.
/// This struct represents [`DateTimeFormat`] in a format that is compatible with expected Rhai
/// function signature.
#[derive(Debug, Clone, Copy)]
pub struct DateTimeFormat;

impl DateTime {
    /// Creates a new [`DateTime`] from individual date and time components.
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// #     &mut scope,
    /// #     r#"
    /// let dt = DateTime(2025, 10, 21, 14, 30, 0, 0);
    /// print("Year: " + dt.year);
    /// print("Month: " + dt.month_str());
    ///
    /// // Operators work as expected
    /// let later = dt + 3600;  // Add 1 hour
    /// let earlier = dt - 1800; // Subtract 30 minutes
    /// #     "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[allow(non_snake_case)]
    pub fn new(
        year: i64,
        month: u64,
        day: u64,
        hour: u64,
        minute: u64,
        second: u64,
        nanosecond: i64,
    ) -> Self {
        unreachable!("This method exists only for documentation.")
    }

    /// Creates a [`DateTime`] from Unix epoch seconds.
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// #     &mut scope,
    /// #     r#"
    /// // Unix epoch (January 1, 1970)
    /// let dt = from_epoch_seconds(0);
    /// #     "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    pub fn from_epoch_seconds(
        &mut self,
        epoch_seconds: i64,
    ) -> Result<DateTime, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Creates a [`DateTime`] from epoch time split into seconds and nanoseconds.
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// #     &mut scope,
    /// #     r#"
    /// // 1 second + 500 million nanoseconds (0.5 seconds)
    /// let dt = from_epoch_nanos(1, 500_000_000);
    /// #     "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    pub fn from_epoch_nanos(
        &mut self,
        seconds_portion: i64,
        nanos_portion: i64,
    ) -> Result<DateTime, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Returns the current [`DateTime`] in UTC truncated to seconds.
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// #     &mut scope,
    /// #     r#"
    /// let current_time = now();
    /// #     "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    pub fn now(&mut self) -> Result<DateTime, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Returns the current [`DateTime`] in UTC to the nearest nanosecond.
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// #     &mut scope,
    /// #     r#"
    /// let current_time = now_nanos();
    /// #     "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    pub fn now_nanos(&mut self) -> DateTime {
        unreachable!("This method exists only for documentation.")
    }

    /// Parses a [`DateTime`] from string using the specified format.
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// #     &mut scope,
    /// #     r#"
    /// let dt = parse_datetime("2025-10-21T14:30:00Z", DateTimeFormat::RFC3339);
    /// #     "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    pub fn parse(
        &mut self,
        s: &str,
        format: DateTimeFormat,
    ) -> Result<DateTime, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Returns this [`DateTime`] in seconds since Unix epoch.
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// #     &mut scope,
    /// #     r#"
    /// let dt = DateTime(2025, 1, 1, 0, 0, 0, 0);
    /// let epoch = dt.epoch_seconds();
    /// #     "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    pub fn epoch_seconds(&mut self) -> Result<i64, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Returns the subsecond component in nanoseconds.
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// #     &mut scope,
    /// #     r#"
    /// let dt = from_epoch_nanos(1, 500_000_000);
    /// let nanos = dt.nanos();
    /// #     "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    pub fn nanos(&mut self) -> i64 {
        unreachable!("This method exists only for documentation.")
    }

    /// Formats [`DateTime`] as a string.
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// #     &mut scope,
    /// #     r#"
    /// let dt = DateTime(2025, 10, 21, 14, 30, 0, 0);
    /// let formatted = dt.to_string(DateTimeFormat::RFC3339);
    /// #     "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    pub fn to_string(&mut self, format: DateTimeFormat) -> Result<String, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Returns the month name as a string `(i.e. October)`
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// #     &mut scope,
    /// #     r#"
    /// let dt = DateTime(2025, 10, 21, 14, 30, 0, 0);
    /// info("Month: " + dt.month_str());
    /// #     "#);
    /// ```
    pub fn month_str(&mut self) -> Result<String, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Returns the month name in short from as a string `(i.e. Oct)`
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// #     &mut scope,
    /// #     r#"
    /// let dt = DateTime(2025, 10, 21, 14, 30, 0, 0);
    /// info("Month: " + dt.month_str_short());
    /// #     "#);
    /// ```
    pub fn month_str_short(&mut self) -> Result<String, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }
}
