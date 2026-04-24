#![cfg(target_os = "linux")]
//! Integration tests for network command functions

#[path = "command/curl.rs"]
mod curl;
#[path = "command/hostname.rs"]
mod hostname;
#[path = "command/ip_addr.rs"]
mod ip_addr;
#[path = "command/netstat.rs"]
mod netstat;
