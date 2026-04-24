#![cfg(target_os = "linux")]
//! Integration tests for disk info command functions

#[path = "command/df.rs"]
mod df;
#[path = "command/iostat.rs"]
mod iostat;
#[path = "command/lsblk.rs"]
mod lsblk;
