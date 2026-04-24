//! Rhai registration for the `sysctl` commands

use crate::command::sysctl;
use crate::registry::get_rhai_context_guard;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::plugin::Engine;
use rhai::{Array, EvalAltResult, NativeCallContext};
use std::rc::Rc;

pub(super) fn register(engine: &mut Engine, cedar_auth: &Rc<CedarAuth>) {
    engine.register_fn("sysctl_read", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext, key: &str| -> Result<String, Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match sysctl::sysctl_read(key, &cedar_auth) {
                Ok(val) => Ok(val),
                Err(e) => Err(e.into()),
            }
        }
    });

    engine.register_fn("sysctl_find", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext, pattern: &str| -> Result<Array, Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match sysctl::sysctl_find(pattern, &cedar_auth) {
                Ok(arr) => Ok(arr),
                Err(e) => Err(e.into()),
            }
        }
    });

    engine.register_fn("sysctl_write", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext, key: &str, value: &str| -> Result<(), Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match sysctl::sysctl_write(key, value, &cedar_auth) {
                Ok(()) => Ok(()),
                Err(e) => Err(e.into()),
            }
        }
    });
}
