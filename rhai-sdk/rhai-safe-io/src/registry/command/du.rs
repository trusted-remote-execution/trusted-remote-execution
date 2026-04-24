//! Rhai registration for the `du` command

use crate::command;
use crate::command::DuFlag;
use crate::registry::common::get_rhai_context_guard;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::plugin::Engine;
use rhai::{Array, Dynamic, EvalAltResult, Map, Module, NativeCallContext};
use std::rc::Rc;

pub(super) fn register(engine: &mut Engine, cedar_auth: &Rc<CedarAuth>) {
    register_types(engine);
    register_functions(engine, cedar_auth);
}

fn register_types(engine: &mut Engine) {
    engine.register_type_with_name::<DuFlag>("DuFlag");
    engine.register_static_module("du", {
        let mut module = Module::new();
        module.set_var("summarize", DuFlag::Summarize);
        module.set_var("s", DuFlag::Summarize);
        module.set_var("all_files", DuFlag::AllFiles);
        module.set_var("a", DuFlag::AllFiles);
        module.set_var("apparent_size", DuFlag::ApparentSize);
        module.set_native_fn("max_depth", |n: i64| Ok(DuFlag::MaxDepth(n)));
        module.set_native_fn("d", |n: i64| Ok(DuFlag::MaxDepth(n)));
        module.into()
    });
}

fn register_functions(engine: &mut Engine, cedar_auth: &Rc<CedarAuth>) {
    // du(path)
    engine.register_fn("du", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext, path: &str| -> Result<Map, Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            command::du(path, &cedar_auth).map_err(|e| {
                Box::new(EvalAltResult::ErrorRuntime(
                    Dynamic::from(e),
                    rhai::Position::NONE,
                ))
            })
        }
    });

    // du(flags, path)
    engine.register_fn("du", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext, flags: Array, path: &str| -> Result<Map, Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            command::du_with_flags(path, &flags, &cedar_auth).map_err(|e| {
                Box::new(EvalAltResult::ErrorRuntime(
                    Dynamic::from(e),
                    rhai::Position::NONE,
                ))
            })
        }
    });
}
