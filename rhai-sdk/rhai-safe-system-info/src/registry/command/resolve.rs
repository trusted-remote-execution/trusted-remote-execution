//! Rhai registration for the `resolve` command

use crate::command::resolve;
use crate::registry::get_rhai_context_guard;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::plugin::Engine;
use rhai::{Array, EvalAltResult, NativeCallContext};
use std::rc::Rc;

pub(super) fn register(engine: &mut Engine, cedar_auth: &Rc<CedarAuth>) {
    engine.register_fn("resolve", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext, hostname: &str| -> Result<Array, Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match resolve::resolve(hostname, &cedar_auth) {
                Ok(arr) => Ok(arr),
                Err(e) => Err(e.into()),
            }
        }
    });
}
