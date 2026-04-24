//! Command registry implementations
//!
//! This module registers command functions and their flag enums with the Rhai engine.
//! Each command has its own submodule handling type registration and function binding.
//!
//! # Available Commands
//!
//! | Command | Description | Example |
//! |---------|-------------|---------|
//! | `curl(url)` | HTTP GET | `curl("https://example.com")` |
//! | `hostname()` | System hostname | `hostname()` |
//! | `ip_addr()` | Network interfaces | `ip_addr()` |
//! | `netstat()` | Network stats (Linux) | `netstat()` |

mod curl;
mod hostname;
mod ip_addr;
mod netstat;

use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::plugin::Engine;
use std::rc::Rc;

pub(in crate::registry) fn register_command_functions(
    engine: &mut Engine,
    cedar_auth: &Rc<CedarAuth>,
) {
    curl::register(engine, cedar_auth);
    hostname::register(engine, cedar_auth);
    ip_addr::register(engine, cedar_auth);
    netstat::register(engine, cedar_auth);
}
