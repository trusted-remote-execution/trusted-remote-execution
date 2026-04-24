//! Safe I/O registry module
//!
//! This module contains the registry implementations for registering safe I/O functions
//! with the Rhai engine, organized by platform.

use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_runner_registrar_utils::execution_context::ExecutionContext;
use rhai::plugin::Engine;
use std::rc::Rc;

mod command;
mod common;

#[cfg(unix)]
mod unix;

#[cfg(target_os = "linux")]
mod linux;

/// Registers safe I/O functions with the Rhai engine for use in scripts.
#[allow(clippy::too_many_lines)]
pub fn register_safe_io_functions(
    engine: &mut Engine,
    cedar_auth: &Rc<CedarAuth>,
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))] execution_context: Option<
        &ExecutionContext,
    >,
) {
    register_builders(engine);

    register_types_and_modules(engine);

    register_getters(engine);

    #[cfg(target_os = "linux")]
    linux::register_linux_functions(engine, cedar_auth, execution_context);

    #[cfg(unix)]
    unix::register_unix_functions(engine, cedar_auth);

    common::register_platform_agnostic_functions(engine, cedar_auth);

    command::register_command_functions(engine, cedar_auth);
}

fn register_builders(engine: &mut Engine) {
    #[cfg(target_os = "linux")]
    linux::register_linux_builders(engine);

    #[cfg(unix)]
    unix::register_unix_builders(engine);

    common::register_common_builders(engine);
}

fn register_types_and_modules(engine: &mut Engine) {
    #[cfg(target_os = "linux")]
    linux::register_linux_types(engine);

    #[cfg(unix)]
    unix::register_unix_types(engine);

    common::register_common_types_and_modules(engine);
}

fn register_getters(engine: &mut Engine) {
    common::register_common_getters(engine);
}
