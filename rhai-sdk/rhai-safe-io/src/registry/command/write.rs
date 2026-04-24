//! Rhai registration for the `write` command

use crate::command;
use crate::command::WriteFlag;
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
    engine.register_type_with_name::<WriteFlag>("WriteFlag");
    engine.register_static_module("write", {
        let mut module = Module::new();
        module.set_var("append", WriteFlag::Append);
        module.set_var("a", WriteFlag::Append);
        module.set_var("replace", WriteFlag::Replace);
        module.set_var("r", WriteFlag::Replace);
        module.into()
    });
}

fn register_functions(engine: &mut Engine, cedar_auth: &Rc<CedarAuth>) {
    // write(path, content) — default append
    engine.register_fn("write", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext, path: &str, content: &str| -> Result<(), Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match command::write(path, content, &cedar_auth) {
                Ok(()) => Ok(()),
                Err(e) => crate::errors::convert_to_rhai_error(&e),
            }
        }
    });

    // write(flags, path, content)
    engine.register_fn("write", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext,
              flags: Array,
              path: &str,
              content: &str|
              -> Result<(), Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match command::write_with_flags(path, content, &flags, &cedar_auth) {
                Ok(()) => Ok(()),
                Err(e) => crate::errors::convert_to_rhai_error(&e),
            }
        }
    });
}
