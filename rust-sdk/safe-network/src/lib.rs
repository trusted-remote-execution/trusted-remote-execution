//! The Rust network crate provides APIs related to networking.

#![forbid(unsafe_code)]
// Common/utility exports
mod auth;

pub mod errors;
pub use errors::RustNetworkError;

// Feature exports
pub mod client;
pub use client::{Client, Request, Response};

pub mod network;
pub use network::{Connection, Network, connect};

pub mod netstat;
pub use netstat::{
    InternetConnection, NetworkProtocol, NetworkStats, ProcessInfo, TcpState, UnixProtocol,
    UnixSocket, UnixSocketState,
};
