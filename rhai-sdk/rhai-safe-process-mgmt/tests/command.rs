#![cfg(target_os = "linux")]
//! Integration tests for process management command functions

#[path = "command/kill.rs"]
mod kill;
#[path = "command/ps.rs"]
mod ps;
