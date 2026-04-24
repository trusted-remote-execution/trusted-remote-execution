//! Command registry implementations
//!
//! This module registers command functions and their flag enums with the Rhai engine.
//! Each command has its own submodule handling type registration and function binding.
//!
//! # Available Commands
//!
//! | Command | Description | Example |
//! |---------|-------------|---------|
//! | `kill(pid)` | Send signal to process | `kill(1234)` |
//! | `ps()` | List processes | `ps()` |
//!
//! # Flag Modules
//!
//! | Module | Flags | Short Forms |
//! |--------|-------|-------------|
//! | `kill` | `SIGTERM`, `SIGKILL`, `SIGHUP`, `SIGQUIT`, `signal(n)` | — |

mod kill;
mod ps;

use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::plugin::Engine;
use std::rc::Rc;

pub(in crate::registry) fn register_command_functions(
    engine: &mut Engine,
    cedar_auth: &Rc<CedarAuth>,
) {
    kill::register(engine, cedar_auth);
    ps::register(engine, cedar_auth);
}
