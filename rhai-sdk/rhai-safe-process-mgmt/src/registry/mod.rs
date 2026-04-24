mod command;
mod common;

pub(crate) use common::get_rhai_context_guard;

use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_runner_registrar_utils::execution_context::ExecutionContext;
use rhai::Engine;
use std::rc::Rc;

/// Registers safe process management functions with the Rhai engine for use in scripts.
pub fn register_safe_process_functions(
    engine: &mut Engine,
    cedar_auth: &Rc<CedarAuth>,
    execution_context: Option<&ExecutionContext>,
) {
    common::register_safe_process_functions(engine, cedar_auth, execution_context);
    command::register_command_functions(engine, cedar_auth);
}
