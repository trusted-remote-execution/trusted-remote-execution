//! Rhai registration for the `hostname` command

use crate::registry::get_rhai_context_guard;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::plugin::Engine;
use rhai::{EvalAltResult, NativeCallContext};
use std::rc::Rc;

pub(super) fn register(engine: &mut Engine, cedar_auth: &Rc<CedarAuth>) {
    engine.register_fn("hostname", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext| -> Result<String, Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match crate::command::hostname(&cedar_auth) {
                Ok(name) => Ok(name),
                Err(e) => Err(e.into()),
            }
        }
    });
}
