//! Rhai registration for the `wc` command

use crate::command;
use crate::command::WcFlag;
use crate::registry::common::get_rhai_context_guard;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::plugin::Engine;
use rhai::{Array, EvalAltResult, Map, Module, NativeCallContext};
use std::rc::Rc;

pub(super) fn register(engine: &mut Engine, cedar_auth: &Rc<CedarAuth>) {
    register_types(engine);
    register_functions(engine, cedar_auth);
}

fn register_types(engine: &mut Engine) {
    engine.register_type_with_name::<WcFlag>("WcFlag");
    engine.register_static_module("wc", {
        let mut module = Module::new();
        module.set_var("lines", WcFlag::Lines);
        module.set_var("l", WcFlag::Lines);
        module.set_var("words", WcFlag::Words);
        module.set_var("w", WcFlag::Words);
        module.set_var("bytes", WcFlag::Bytes);
        module.set_var("c", WcFlag::Bytes);
        module.into()
    });
}

fn register_functions(engine: &mut Engine, cedar_auth: &Rc<CedarAuth>) {
    // wc(path)
    engine.register_fn("wc", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext, path: &str| -> Result<Map, Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match command::wc(path, &cedar_auth) {
                Ok(map) => Ok(map),
                Err(e) => crate::errors::convert_to_rhai_error(&e),
            }
        }
    });

    // wc(flags, path)
    engine.register_fn("wc", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext, flags: Array, path: &str| -> Result<Map, Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match command::wc_with_flags(path, &flags, &cedar_auth) {
                Ok(map) => Ok(map),
                Err(e) => crate::errors::convert_to_rhai_error(&e),
            }
        }
    });
}
