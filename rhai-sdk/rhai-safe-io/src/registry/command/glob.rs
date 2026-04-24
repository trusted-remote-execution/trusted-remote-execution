//! Rhai registration for the `glob` command

use crate::command;
use crate::command::GlobFlag;
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
    engine.register_type_with_name::<GlobFlag>("GlobFlag");
    engine.register_static_module("glob", {
        let mut module = Module::new();
        module.set_var("recursive", GlobFlag::Recursive);
        module.set_var("r", GlobFlag::Recursive);
        module.into()
    });
}

fn register_functions(engine: &mut Engine, cedar_auth: &Rc<CedarAuth>) {
    // glob(pattern, path) — note: "glob" as function name conflicts with module name,
    // so we register as "find_files" to avoid ambiguity
    engine.register_fn("find_files", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext,
              pattern: &str,
              path: &str|
              -> Result<Array, Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match command::glob(pattern, path, &cedar_auth) {
                Ok(files) => Ok(files.into_iter().map(rhai::Dynamic::from).collect()),
                Err(e) => crate::errors::convert_to_rhai_error(&e),
            }
        }
    });

    // find_files(flags, pattern, path)
    engine.register_fn("find_files", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext,
              flags: Array,
              pattern: &str,
              path: &str|
              -> Result<Array, Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match command::glob_with_flags(pattern, path, &flags, &cedar_auth) {
                Ok(files) => Ok(files.into_iter().map(rhai::Dynamic::from).collect()),
                Err(e) => crate::errors::convert_to_rhai_error(&e),
            }
        }
    });
}
