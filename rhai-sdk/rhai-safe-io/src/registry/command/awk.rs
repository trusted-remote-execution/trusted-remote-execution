//! Rhai registration for `awk` sub-functions

use crate::command;
use crate::registry::common::get_rhai_context_guard;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::plugin::Engine;
use rhai::{Array, Dynamic, EvalAltResult, Map, NativeCallContext};
use std::rc::Rc;

pub(super) fn register(engine: &mut Engine, cedar_auth: &Rc<CedarAuth>) {
    register_functions(engine, cedar_auth);
}

#[allow(clippy::too_many_lines)]
fn register_functions(engine: &mut Engine, cedar_auth: &Rc<CedarAuth>) {
    // awk_split(text, delimiter) — pure computation, no cedar_auth needed
    engine.register_fn("awk_split", {
        move |ctx: NativeCallContext,
              text: &str,
              delimiter: &str|
              -> Result<Array, Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            Ok(command::awk_split(text, delimiter)
                .into_iter()
                .map(Dynamic::from)
                .collect())
        }
    });

    // awk_field(field_num, delimiter, path)
    engine.register_fn("awk_field", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext,
              field_num: i64,
              delimiter: &str,
              path: &str|
              -> Result<Array, Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match command::awk_field(field_num, delimiter, path, &cedar_auth) {
                Ok(fields) => Ok(fields.into_iter().map(Dynamic::from).collect()),
                Err(e) => crate::errors::convert_to_rhai_error(&e),
            }
        }
    });

    // awk_filter(pattern, path)
    engine.register_fn("awk_filter", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext,
              pattern: &str,
              path: &str|
              -> Result<Array, Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match command::awk_filter(pattern, path, &cedar_auth) {
                Ok(lines) => Ok(lines.into_iter().map(Dynamic::from).collect()),
                Err(e) => crate::errors::convert_to_rhai_error(&e),
            }
        }
    });

    // awk_filter_field(field_num, delimiter, pattern, path)
    engine.register_fn("awk_filter_field", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext,
              field_num: i64,
              delimiter: &str,
              pattern: &str,
              path: &str|
              -> Result<Array, Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match command::awk_filter_field(field_num, delimiter, pattern, path, &cedar_auth) {
                Ok(lines) => Ok(lines.into_iter().map(Dynamic::from).collect()),
                Err(e) => crate::errors::convert_to_rhai_error(&e),
            }
        }
    });

    // awk_sum(field_num, delimiter, path)
    engine.register_fn("awk_sum", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext,
              field_num: i64,
              delimiter: &str,
              path: &str|
              -> Result<f64, Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match command::awk_sum(field_num, delimiter, path, &cedar_auth) {
                Ok(total) => Ok(total),
                Err(e) => crate::errors::convert_to_rhai_error(&e),
            }
        }
    });

    // awk_count_unique(field_num, delimiter, path)
    engine.register_fn("awk_count_unique", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext,
              field_num: i64,
              delimiter: &str,
              path: &str|
              -> Result<Map, Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match command::awk_count_unique(field_num, delimiter, path, &cedar_auth) {
                Ok(counts) => {
                    let map: Map = counts
                        .into_iter()
                        .map(|(k, v)| (k.into(), Dynamic::from(v)))
                        .collect();
                    Ok(map)
                }
                Err(e) => crate::errors::convert_to_rhai_error(&e),
            }
        }
    });

    // awk_filter_range(start, end, path)
    engine.register_fn("awk_filter_range", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext,
              start: i64,
              end: i64,
              path: &str|
              -> Result<Array, Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match command::awk_filter_range(start, end, path, &cedar_auth) {
                Ok(lines) => Ok(lines.into_iter().map(Dynamic::from).collect()),
                Err(e) => crate::errors::convert_to_rhai_error(&e),
            }
        }
    });
}
