mod command;
mod common;

pub(crate) use common::get_rhai_context_guard;

use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_runner_registrar_utils::execution_context::ExecutionContext;
use rhai::plugin::Engine;
use std::rc::Rc;

/// Registers system info functions with the Rhai engine for use in scripts.
pub fn register(
    engine: &mut Engine,
    cedar_auth: &Rc<CedarAuth>,
    execution_context: Option<&ExecutionContext>,
) {
    common::register(engine, cedar_auth, execution_context);
    command::register_command_functions(engine, cedar_auth);
}
