#![cfg(target_os = "linux")]
//! # Rhai Safe Process Management
//!
//! This crate provides a safe interface for process management operations in Rhai scripts.
//! It wraps the Rust safe process management functionality and exposes it to Rhai scripts.
//!
//! Since this crate has not been tested on Windows, we currently only
//! support Linux and guard this crate as such.

// Vendor-facing API
pub use process::ProcessManager;
pub use systemctl::SystemctlManager;
pub mod errors;
pub mod signal;
pub mod state;

// Internal (private modules are hidden from rustdoc)
pub(crate) mod command;
mod process;
mod systemctl;

// Consumed by other crates, hidden from vendor docs
#[doc(hidden)]
pub mod registry;
#[doc(hidden)]
pub use registry::register_safe_process_functions;
