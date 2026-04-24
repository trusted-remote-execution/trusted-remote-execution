//! Rhai registration for the `grep` command

use crate::command;
use crate::command::GrepFlag;
use crate::registry::common::get_rhai_context_guard;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::plugin::Engine;
use rhai::{Array, EvalAltResult, Module, NativeCallContext};
use std::rc::Rc;

pub(super) fn register(engine: &mut Engine, cedar_auth: &Rc<CedarAuth>) {
    register_types(engine);
    register_functions(engine, cedar_auth);
}

fn register_types(engine: &mut Engine) {
    engine.register_type_with_name::<GrepFlag>("GrepFlag");
    engine.register_static_module("grep", {
        let mut module = Module::new();
        module.set_var("ignore_case", GrepFlag::IgnoreCase);
        module.set_var("i", GrepFlag::IgnoreCase);
        module.set_var("count", GrepFlag::Count);
        module.set_var("c", GrepFlag::Count);
        module.set_var("invert", GrepFlag::Invert);
        module.set_var("v", GrepFlag::Invert);
        module.set_var("line_number", GrepFlag::LineNumber);
        module.set_var("n", GrepFlag::LineNumber);
        module.set_native_fn("max_count", |n: i64| Ok(GrepFlag::MaxCount(n)));
        module.set_native_fn("m", |n: i64| Ok(GrepFlag::MaxCount(n)));
        module.into()
    });
}

fn register_functions(engine: &mut Engine, cedar_auth: &Rc<CedarAuth>) {
    // grep(pattern, path)
    engine.register_fn("grep", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext,
              pattern: &str,
              path: &str|
              -> Result<Array, Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match command::grep(pattern, path, &cedar_auth) {
                Ok(lines) => Ok(lines.into_iter().map(rhai::Dynamic::from).collect()),
                Err(e) => crate::errors::convert_to_rhai_error(&e),
            }
        }
    });

    // grep(flags, pattern, path)
    engine.register_fn("grep", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext,
              flags: Array,
              pattern: &str,
              path: &str|
              -> Result<Array, Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match command::grep_with_flags(pattern, path, &flags, &cedar_auth) {
                Ok(lines) => Ok(lines.into_iter().map(rhai::Dynamic::from).collect()),
                Err(e) => crate::errors::convert_to_rhai_error(&e),
            }
        }
    });
}
