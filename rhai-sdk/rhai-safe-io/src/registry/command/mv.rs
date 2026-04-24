//! Rhai registration for the `mv` command

use crate::command;
use crate::command::MvFlag;
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
    engine.register_type_with_name::<MvFlag>("MvFlag");
    engine.register_static_module("mv", {
        let mut module = Module::new();
        module.set_var("backup", MvFlag::Backup);
        module.set_var("b", MvFlag::Backup);
        module.set_var("verbose", MvFlag::Verbose);
        module.set_var("v", MvFlag::Verbose);
        module.into()
    });
}

fn register_functions(engine: &mut Engine, cedar_auth: &Rc<CedarAuth>) {
    // mv(src, dst)
    engine.register_fn("mv", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext, src: &str, dst: &str| -> Result<(), Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match command::mv(src, dst, &cedar_auth) {
                Ok(()) => Ok(()),
                Err(e) => crate::errors::convert_to_rhai_error(&e),
            }
        }
    });

    // mv(flags, src, dst)
    engine.register_fn("mv", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext,
              flags: Array,
              src: &str,
              dst: &str|
              -> Result<(), Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match command::mv_with_flags(src, dst, &flags, &cedar_auth) {
                Ok(()) => Ok(()),
                Err(e) => crate::errors::convert_to_rhai_error(&e),
            }
        }
    });
}
