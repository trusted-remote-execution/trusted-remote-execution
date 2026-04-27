//! Registration functions for `SDKCommonUtils` types in Rhai.
//!
//! This module provides the registration logic to expose utility functions for use in Rhai scripts.
use rex_logger::push_rhai_context_with_guard;
use rex_runner_registrar_utils::{
    register_getters_with_guard, register_with_guard, register_with_no_ctx,
};
use rust_sdk_common_utils::random::random_alphanumeric;
use rust_sdk_common_utils::types::datetime::{DateTime, DateTimeFormat};

use crate::errors::{ERROR_MODULE_NAME, RhaiCommonUtilsErrorKind, convert_to_rhai_error};
use rhai::plugin::{
    Engine, FnNamespace, FuncRegistration, Module, NativeCallContext, PluginFunc, RhaiResult,
    TypeId, export_module, exported_module, mem,
};
use rhai::{Dynamic, Map, format_map_as_json};

#[allow(non_upper_case_globals)]
#[allow(unreachable_pub)]
#[allow(clippy::unwrap_used)]
#[export_module]
mod error_kind_module {
    use super::Module;

    pub const InvalidArguments: RhaiCommonUtilsErrorKind =
        RhaiCommonUtilsErrorKind::InvalidArguments;
    pub const ParseError: RhaiCommonUtilsErrorKind = RhaiCommonUtilsErrorKind::ParseError;
    pub const FormatError: RhaiCommonUtilsErrorKind = RhaiCommonUtilsErrorKind::FormatError;
    pub const Other: RhaiCommonUtilsErrorKind = RhaiCommonUtilsErrorKind::Other;

    #[rhai_fn(global, name = "==", pure)]
    pub fn eq(error_kind: &mut RhaiCommonUtilsErrorKind, other: RhaiCommonUtilsErrorKind) -> bool {
        error_kind == &other
    }

    #[rhai_fn(global, name = "!=", pure)]
    pub fn neq(error_kind: &mut RhaiCommonUtilsErrorKind, other: RhaiCommonUtilsErrorKind) -> bool {
        error_kind != &other
    }

    #[rhai_fn(global, name = "to_string")]
    pub fn to_string(kind: &mut RhaiCommonUtilsErrorKind) -> String {
        kind.to_string()
    }
}

/// Helper to get Rhai context guard for logging
fn get_rhai_context_guard(context: &NativeCallContext) -> impl Drop {
    let line_number = context
        .call_position()
        .line()
        .map_or(0, |l| u32::try_from(l).unwrap_or(0));

    push_rhai_context_with_guard(Some(context.fn_name()), line_number)
}

/// [`DateTimeFormat`] module for Rhai - provides constants for format types
#[export_module]
pub mod datetime_format_module {
    use super::DateTimeFormat;

    /// RFC3339 format constant
    pub const RFC3339: DateTimeFormat = DateTimeFormat::Rfc3339;

    /// RFC2822 format constant
    pub const RFC2822: DateTimeFormat = DateTimeFormat::Rfc2822;
}

/// [`DateTime`] module for Rhai - provides methods for arithmetic operations on [`DateTime`] objects
#[export_module]
pub mod datetime_operations_module {
    use super::DateTime;

    #[rhai_fn(global, name = "+")]
    pub fn add_seconds(dt: DateTime, seconds: i64) -> DateTime {
        dt + seconds
    }

    #[rhai_fn(global, name = "-")]
    pub fn sub_seconds(dt: DateTime, seconds: i64) -> DateTime {
        dt - seconds
    }

    #[rhai_fn(global, name = "-")]
    pub fn duration(dt1: DateTime, dt2: DateTime) -> i64 {
        dt1 - dt2
    }

    #[rhai_fn(global, name = "==")]
    pub fn eq(dt1: DateTime, dt2: DateTime) -> bool {
        dt1 == dt2
    }

    #[rhai_fn(global, name = "!=")]
    pub fn neq(dt1: DateTime, dt2: DateTime) -> bool {
        dt1 != dt2
    }

    #[rhai_fn(global, name = "<")]
    pub fn lt(dt1: DateTime, dt2: DateTime) -> bool {
        dt1 < dt2
    }

    #[rhai_fn(global, name = "<=")]
    pub fn lte(dt1: DateTime, dt2: DateTime) -> bool {
        dt1 <= dt2
    }

    #[rhai_fn(global, name = ">")]
    pub fn gt(dt1: DateTime, dt2: DateTime) -> bool {
        dt1 > dt2
    }

    #[rhai_fn(global, name = ">=")]
    pub fn gte(dt1: DateTime, dt2: DateTime) -> bool {
        dt1 >= dt2
    }
}

fn register_common_types(engine: &mut Engine) {
    engine
        .register_type_with_name::<RhaiCommonUtilsErrorKind>("RhaiCommonUtilsErrorKind")
        .register_static_module(
            ERROR_MODULE_NAME,
            exported_module!(error_kind_module).into(),
        );

    register_datetime_functions(engine);
}

/// Registers [`DateTime`] and [`DateTimeFormat`] types and functions with the Rhai engine.
#[allow(clippy::cast_sign_loss)]
#[allow(clippy::cast_possible_wrap)]
#[allow(clippy::too_many_lines)]
fn register_datetime_functions(engine: &mut Engine) {
    engine.register_type::<DateTime>();
    engine.register_static_module(
        "datetime_operations",
        exported_module!(datetime_operations_module).into(),
    );

    engine.register_type::<DateTimeFormat>();
    engine.register_static_module(
        "DateTimeFormat",
        exported_module!(datetime_format_module).into(),
    );

    register_with_guard!(
        engine,
        "DateTime",
        DateTime,
        DateTime::new,
        year: i64,
        month: i64 => u64,
        day: i64 => u64,
        hour: i64 => u64,
        minute: i64 => u64,
        second: i64 => u64,
        nanosecond: i64
    );

    register_with_guard!(
        engine,
        "from_epoch_seconds",
        DateTime,
        DateTime::from_epoch_seconds,
        convert_to_rhai_error,
        epoch_seconds: i64
    );

    register_with_guard!(
        engine,
        "from_epoch_nanos",
        DateTime,
        DateTime::from_epoch_nanos,
        convert_to_rhai_error,
        seconds_portion: i64,
        nanos_portion: i64
    );

    register_with_guard!(
        engine,
        "now",
        DateTime,
        DateTime::now,
        convert_to_rhai_error
    );

    register_with_guard!(engine, "now_nanos", DateTime, DateTime::now_nanos);

    register_with_guard!(
        engine,
        "parse_datetime",
        DateTime,
        DateTime::parse,
        convert_to_rhai_error,
        s: &str,
        format: DateTimeFormat
    );

    register_with_no_ctx!(
        engine,
        "epoch_seconds",
        i64,
        DateTime,
        DateTime::epoch_seconds,
        result,
        convert_to_rhai_error
    );

    register_with_guard!(engine, "nanos", i64, self, DateTime, DateTime::nanos);

    register_with_no_ctx!(engine, "to_string", String, DateTime, DateTime::to_string, result, convert_to_rhai_error, format: DateTimeFormat);

    register_with_no_ctx!(
        engine,
        "month_str",
        String,
        DateTime,
        DateTime::month_str,
        result,
        convert_to_rhai_error
    );

    register_with_no_ctx!(
        engine,
        "month_str_short",
        String,
        DateTime,
        DateTime::month_str_short,
        result,
        convert_to_rhai_error
    );

    register_getters_with_guard!(engine, DateTime, [year, (month, u64 => i64),(day, u64 => i64), (hour, u64 => i64), (minute, u64 => i64), (second, u64 => i64), nanosecond]);
}

pub fn register(engine: &mut Engine) {
    register_common_types(engine);
    register_with_guard!(engine, "random_alphanumeric", String, random_alphanumeric, length: i64);

    // Override for Map's to_json function that enforces one implementation instead of being dependent on the Rhai metadata feature.
    // Under the hood this will delegate writing a value to its to_string implementation. The `serde_json` version by contrast would just print
    // the type name for any custom type, which is not useful.
    // Original to_json code: https://github.com/rhaiscript/rhai/blob/954abdc40dd2cb647221e827642c3ca4c360983c/src/packages/map_basic.rs#L536
    engine.register_fn("to_json", |map: &mut Map| -> String {
        format_map_as_json(map)
    });
}

#[cfg(test)]
mod tests {
    use rex_test_utils::rhai::common::create_test_engine_and_register;
    use rhai::Scope;

    /// Given: Two identical RhaiCommonUtilsErrorKind values
    /// When: Comparing them for equality in the Rhai engine
    /// Then: They should be equal
    #[test]
    fn test_error_kind_equality_same_type() {
        let engine = create_test_engine_and_register();
        let result = engine
            .eval::<bool>(
                r#"
                let a = CommonUtilsErrorKind::InvalidArguments;
                let b = CommonUtilsErrorKind::InvalidArguments;
                a == b
            "#,
            )
            .unwrap();
        assert!(result);
    }

    /// Given: A Rhai map with a u64 value
    /// When: Converting it to JSON
    /// Then: It should render as a number instead of the string "u64"
    #[test]
    fn test_to_json_serializes_correctly() {
        let engine = create_test_engine_and_register();
        let mut scope = Scope::new();
        scope.push("v", 10u64);

        let result = engine
            .eval_with_scope::<String>(
                &mut scope,
                r#"
                #{
                    "v": v
                }.to_json()
            "#,
            )
            .unwrap();
        assert_eq!(result, r#"{"v":10}"#);
    }

    /// Given: Two identical RhaiCommonUtilsErrorKind values
    /// When: Comparing them for inequality in the Rhai engine
    /// Then: They should not be unequal
    #[test]
    fn test_error_kind_inequality_same_type() {
        let engine = create_test_engine_and_register();
        let result = engine
            .eval::<bool>(
                r#"
                let a = CommonUtilsErrorKind::InvalidArguments;
                let b = CommonUtilsErrorKind::InvalidArguments;
                a != b
            "#,
            )
            .unwrap();
        assert!(!result);
    }

    /// Given: Two different RhaiCommonUtilsErrorKind values
    /// When: Comparing them for inequality in the Rhai engine
    /// Then: They should be unequal
    #[test]
    fn test_error_kind_inequality_different_types() {
        let engine = create_test_engine_and_register();
        let result = engine
            .eval::<bool>(
                r#"
                let a = CommonUtilsErrorKind::FormatError;
                let b = CommonUtilsErrorKind::InvalidArguments;
                a != b
            "#,
            )
            .unwrap();
        assert!(result);
    }

    /// Given: Two different RhaiCommonUtilsErrorKind values
    /// When: Comparing them for equality in the Rhai engine
    /// Then: They should not be equal
    #[test]
    fn test_error_kind_equality_different_types() {
        let engine = create_test_engine_and_register();
        let result = engine
            .eval::<bool>(
                r#"
                let a = CommonUtilsErrorKind::FormatError;
                let b = CommonUtilsErrorKind::ParseError;
                a == b
            "#,
            )
            .unwrap();
        assert!(!result);
    }

    /// Given: A RhaiCommonUtilsErrorKind value
    /// When: Converting it to a string in the Rhai engine
    /// Then: It should return the correct string representation
    #[test]
    fn test_error_kind_to_string() {
        let engine = create_test_engine_and_register();

        let result = engine
            .eval::<String>(
                r#"
                let kind = CommonUtilsErrorKind::FormatError;
                kind.to_string()
                "#,
            )
            .unwrap();

        assert_eq!(result, "FormatError");
    }
}
