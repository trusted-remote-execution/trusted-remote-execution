//! Rhai registration for the `uname` command

use crate::command::uname;
use crate::registry::get_rhai_context_guard;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::plugin::Engine;
use rhai::{Dynamic, EvalAltResult, NativeCallContext};
use std::rc::Rc;

pub(super) fn register(engine: &mut Engine, cedar_auth: &Rc<CedarAuth>) {
    engine.register_fn("uname", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext| -> Result<Dynamic, Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match uname::uname(&cedar_auth) {
                Ok(info) => Ok(info),
                Err(e) => Err(e.into()),
            }
        }
    });
}
