//! Rhai registration for the `mkdir` command

use crate::command;
use crate::command::MkdirFlag;
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
    engine.register_type_with_name::<MkdirFlag>("MkdirFlag");
    engine.register_static_module("mkdir", {
        let mut module = Module::new();
        module.set_var("parents", MkdirFlag::Parents);
        module.set_var("p", MkdirFlag::Parents);
        module.into()
    });
}

fn register_functions(engine: &mut Engine, cedar_auth: &Rc<CedarAuth>) {
    // mkdir(path)
    engine.register_fn("mkdir", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext, path: &str| -> Result<(), Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match command::mkdir(path, &cedar_auth) {
                Ok(()) => Ok(()),
                Err(e) => crate::errors::convert_to_rhai_error(&e),
            }
        }
    });

    // mkdir(flags, path)
    engine.register_fn("mkdir", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext, flags: Array, path: &str| -> Result<(), Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match command::mkdir_with_flags(path, &flags, &cedar_auth) {
                Ok(()) => Ok(()),
                Err(e) => crate::errors::convert_to_rhai_error(&e),
            }
        }
    });
}
