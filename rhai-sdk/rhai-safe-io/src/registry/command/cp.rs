//! Rhai registration for the `cp` command

use crate::command;
use crate::command::CpFlag;
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
    engine.register_type_with_name::<CpFlag>("CpFlag");
    engine.register_static_module("cp", {
        let mut module = Module::new();
        module.set_var("force", CpFlag::Force);
        module.set_var("f", CpFlag::Force);
        module.set_var("preserve", CpFlag::Preserve);
        module.set_var("p", CpFlag::Preserve);
        module.into()
    });
}

fn register_functions(engine: &mut Engine, cedar_auth: &Rc<CedarAuth>) {
    // cp(src, dst)
    engine.register_fn("cp", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext, src: &str, dst: &str| -> Result<(), Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match command::cp(src, dst, &cedar_auth) {
                Ok(()) => Ok(()),
                Err(e) => crate::errors::convert_to_rhai_error(&e),
            }
        }
    });

    // cp(flags, src, dst)
    engine.register_fn("cp", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext,
              flags: Array,
              src: &str,
              dst: &str|
              -> Result<(), Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match command::cp_with_flags(src, dst, &flags, &cedar_auth) {
                Ok(()) => Ok(()),
                Err(e) => crate::errors::convert_to_rhai_error(&e),
            }
        }
    });
}
