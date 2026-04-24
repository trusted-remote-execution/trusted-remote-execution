//! Rhai registration for the `kill` command

use crate::command::kill;
use crate::registry::get_rhai_context_guard;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::plugin::Engine;
use rhai::{Array, EvalAltResult, NativeCallContext};
use std::rc::Rc;

pub(super) fn register(engine: &mut Engine, cedar_auth: &Rc<CedarAuth>) {
    // kill(pid)
    engine.register_fn("kill", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext, pid: i64| -> Result<Array, Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match kill::kill(pid, &cedar_auth) {
                Ok(pairs) => Ok(pairs
                    .into_iter()
                    .map(|(name, pid)| {
                        let mut map = rhai::Map::new();
                        map.insert("name".into(), rhai::Dynamic::from(name));
                        map.insert("pid".into(), rhai::Dynamic::from(pid));
                        rhai::Dynamic::from(map)
                    })
                    .collect()),
                Err(e) => crate::errors::convert_to_rhai_error(&e),
            }
        }
    });

    // kill(flags, pid)
    engine.register_fn("kill", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext, flags: Array, pid: i64| -> Result<Array, Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);
            match kill::kill_with_flags(pid, &flags, &cedar_auth) {
                Ok(pairs) => Ok(pairs
                    .into_iter()
                    .map(|(name, pid)| {
                        let mut map = rhai::Map::new();
                        map.insert("name".into(), rhai::Dynamic::from(name));
                        map.insert("pid".into(), rhai::Dynamic::from(pid));
                        rhai::Dynamic::from(map)
                    })
                    .collect()),
                Err(e) => crate::errors::convert_to_rhai_error(&e),
            }
        }
    });
}
