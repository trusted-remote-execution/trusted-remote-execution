//! Rhai registration for the `cat` command

use crate::command;
use crate::command::CatFlag;
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
    engine.register_type_with_name::<CatFlag>("CatFlag");
    engine.register_static_module("cat", {
        let mut module = Module::new();
        module.set_var("number", CatFlag::Number);
        module.set_var("n", CatFlag::Number);
        module.into()
    });
}

fn register_functions(engine: &mut Engine, cedar_auth: &Rc<CedarAuth>) {
    engine.register_fn("cat", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext, path: &str| -> Result<String, Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match command::cat(path, &cedar_auth) {
                Ok(result) => Ok(result),
                Err(e) => crate::errors::convert_to_rhai_error(&e),
            }
        }
    });

    engine.register_fn("cat", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext,
              flags: Array,
              path: &str|
              -> Result<String, Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match command::cat_with_flags(path, &flags, &cedar_auth) {
                Ok(result) => Ok(result),
                Err(e) => crate::errors::convert_to_rhai_error(&e),
            }
        }
    });
}
