//! Rhai registration for the `lsblk` command

use crate::registry::get_rhai_context_guard;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::plugin::Engine;
use rhai::{EvalAltResult, Map, NativeCallContext};
use std::rc::Rc;

pub(super) fn register(engine: &mut Engine, cedar_auth: &Rc<CedarAuth>) {
    engine.register_fn("lsblk", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext| -> Result<Map, Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match crate::command::lsblk(&cedar_auth) {
                Ok(map) => Ok(map),
                Err(e) => Err(e.to_string().into()),
            }
        }
    });
}
