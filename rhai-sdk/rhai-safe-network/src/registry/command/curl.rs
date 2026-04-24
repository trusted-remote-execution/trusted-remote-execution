//! Rhai registration for the `curl` command

use crate::registry::get_rhai_context_guard;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::plugin::Engine;
use rhai::{Dynamic, EvalAltResult, NativeCallContext};
use std::rc::Rc;

pub(super) fn register(engine: &mut Engine, cedar_auth: &Rc<CedarAuth>) {
    engine.register_fn("curl", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext, url: &str| -> Result<Dynamic, Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match crate::command::curl(url, &cedar_auth) {
                Ok(response) => Ok(response),
                Err(e) => Err(e.into()),
            }
        }
    });
}
