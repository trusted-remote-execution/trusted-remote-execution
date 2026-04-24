//! Rhai registration for the `iostat` command

use crate::registry::get_rhai_context_guard;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::{Dynamic, Engine, EvalAltResult, NativeCallContext};
use std::rc::Rc;

pub(super) fn register(engine: &mut Engine, cedar_auth: &Rc<CedarAuth>) {
    engine.register_fn("iostat", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext| -> Result<Dynamic, Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match crate::command::iostat(&cedar_auth) {
                Ok(snapshot) => Ok(snapshot),
                Err(e) => Err(e.into()),
            }
        }
    });
}
