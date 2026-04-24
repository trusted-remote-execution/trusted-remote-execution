//! Rhai registration for the `nproc` command

use crate::command::nproc;
use crate::registry::get_rhai_context_guard;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::plugin::Engine;
use rhai::{EvalAltResult, NativeCallContext};
use std::rc::Rc;

pub(super) fn register(engine: &mut Engine, cedar_auth: &Rc<CedarAuth>) {
    engine.register_fn("nproc", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext| -> Result<i64, Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match nproc::nproc(&cedar_auth) {
                Ok(count) => Ok(count),
                Err(e) => Err(e.into()),
            }
        }
    });
}
