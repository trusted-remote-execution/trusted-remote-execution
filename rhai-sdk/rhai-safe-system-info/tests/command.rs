#![cfg(target_os = "linux")]
//! Integration tests for system info command functions

#[path = "command/dmesg.rs"]
mod dmesg;
#[path = "command/free.rs"]
mod free;
#[path = "command/nproc.rs"]
mod nproc;
#[path = "command/resolve.rs"]
mod resolve;
#[path = "command/sysctl.rs"]
mod sysctl;
#[path = "command/uname.rs"]
mod uname;
