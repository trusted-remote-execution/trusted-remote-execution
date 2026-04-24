//! Rhai registration for the `tail` command

use crate::command;
use crate::command::TailFlag;
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
    engine.register_type_with_name::<TailFlag>("TailFlag");
    engine.register_static_module("tail", {
        let mut module = Module::new();
        module.set_native_fn("n", |count: i64| Ok(TailFlag::Count(count)));
        module.set_native_fn("from", |line: i64| Ok(TailFlag::From(line)));
        module.set_native_fn("range", |start: i64, end: i64| {
            Ok(TailFlag::Range(start, end))
        });
        module.into()
    });
}

fn register_functions(engine: &mut Engine, cedar_auth: &Rc<CedarAuth>) {
    // tail(path)
    engine.register_fn("tail", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext, path: &str| -> Result<Array, Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match command::tail(path, &cedar_auth) {
                Ok(lines) => Ok(lines.into_iter().map(rhai::Dynamic::from).collect()),
                Err(e) => crate::errors::convert_to_rhai_error(&e),
            }
        }
    });

    // tail(flags, path)
    engine.register_fn("tail", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext,
              flags: Array,
              path: &str|
              -> Result<Array, Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match command::tail_with_flags(path, &flags, &cedar_auth) {
                Ok(lines) => Ok(lines.into_iter().map(rhai::Dynamic::from).collect()),
                Err(e) => crate::errors::convert_to_rhai_error(&e),
            }
        }
    });
}
