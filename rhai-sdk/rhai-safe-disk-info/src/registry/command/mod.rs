//! Command registry implementations
//!
//! This module registers command functions and their flag enums with the Rhai engine.
//! Each command has its own submodule handling type registration and function binding.
//!
//! # Available Commands
//!
//! | Command | Description | Example |
//! |---------|-------------|---------|
//! | `df()` | Filesystem disk usage | `df()` |
//! | `iostat()` | I/O statistics | `iostat()` |
//! | `lsblk()` | List block devices | `lsblk()` |

mod df;
mod iostat;
mod lsblk;

use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::plugin::Engine;
use std::rc::Rc;

pub(in crate::registry) fn register_command_functions(
    engine: &mut Engine,
    cedar_auth: &Rc<CedarAuth>,
) {
    df::register(engine, cedar_auth);
    iostat::register(engine, cedar_auth);
    lsblk::register(engine, cedar_auth);
}
