//! Signal handling utilities for REX components
//!
//! This module provides thread-safe signal handling using signal-hook, designed
//! to be used across multiple REX packages without circular dependencies.

pub mod sigterm_handler;

pub use sigterm_handler::SigtermHandler;
