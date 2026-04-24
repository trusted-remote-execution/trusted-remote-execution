//! Rhai registration for the `ls` command

use crate::command;
use crate::command::LsFlag;
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
    engine.register_type_with_name::<LsFlag>("LsFlag");
    engine.register_static_module("ls", {
        let mut module = Module::new();
        module.set_var("all", LsFlag::All);
        module.set_var("a", LsFlag::All);
        module.set_var("long", LsFlag::Long);
        module.set_var("l", LsFlag::Long);
        module.set_var("recursive", LsFlag::Recursive);
        module.set_var("R", LsFlag::Recursive);
        module.into()
    });
}

fn register_functions(engine: &mut Engine, cedar_auth: &Rc<CedarAuth>) {
    engine.register_fn("ls", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext, path: &str| -> Result<rhai::Map, Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match command::ls_rhai(path, &cedar_auth) {
                Ok(result) => Ok(result),
                Err(e) => crate::errors::convert_to_rhai_error(&e),
            }
        }
    });

    engine.register_fn("ls", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext,
              flags: Array,
              path: &str|
              -> Result<rhai::Map, Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match command::ls_rhai_with_flags(path, &flags, &cedar_auth) {
                Ok(result) => Ok(result),
                Err(e) => crate::errors::convert_to_rhai_error(&e),
            }
        }
    });
}
