//! Command registry implementations
//!
//! This module registers command functions and their flag enums with the Rhai engine.
//! Each command has its own submodule handling type registration and function binding.
//!
//! # Available Commands
//!
//! | Command | Description | Example |
//! |---------|-------------|---------|
//! | `uname()` | System info (Linux) | `uname()` |
//! | `nproc()` | CPU count | `nproc()` |
//! | `free()` | Memory/swap usage | `free()` |
//! | `dmesg()` | Kernel log (Linux) | `dmesg()` |
//! | `sysctl_read(key)` | Read kernel param | `sysctl_read("kernel.hostname")` |
//! | `sysctl_find(pat)` | Find kernel params | `sysctl_find("net.ipv4")` |
//! | `sysctl_write(k, v)` | Write kernel param | `sysctl_write("net.ipv4.ip_forward", "1")` |
//! | `resolve(host)` | DNS resolution | `resolve("example.com")` |

mod dmesg;
mod free;
mod nproc;
mod resolve;
mod sysctl;
mod uname;

use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::plugin::Engine;
use std::rc::Rc;

pub(in crate::registry) fn register_command_functions(
    engine: &mut Engine,
    cedar_auth: &Rc<CedarAuth>,
) {
    uname::register(engine, cedar_auth);
    nproc::register(engine, cedar_auth);
    free::register(engine, cedar_auth);
    dmesg::register(engine, cedar_auth);
    sysctl::register(engine, cedar_auth);
    resolve::register(engine, cedar_auth);
}
