mod command;
mod common;

pub(crate) use common::get_rhai_context_guard;

use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::plugin::Engine;
use std::rc::Rc;

/// Registers disk info functions with the Rhai engine for use in scripts.
pub fn register(engine: &mut Engine, cedar_auth: &Rc<CedarAuth>) {
    common::register(engine, cedar_auth);
    command::register_command_functions(engine, cedar_auth);
}
