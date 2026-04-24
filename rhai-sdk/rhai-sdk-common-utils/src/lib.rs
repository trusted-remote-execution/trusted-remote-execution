//! Common utilities for the Rex SDK.
//!
//! This crate exposes common utility types and functions to Rhai scripts,
//! enabling script authors to work with utilities and other common
//! functionality within the Rex scripting environment.
//!
//! Utility functions perform standalone computations (such as [`DateTime`]
//! operations) that do not require cedar permission validation.

pub mod common_types;
pub mod duration;
pub mod random;
pub use common_types::{DateTime, DateTimeFormat};
pub mod args;
pub mod errors;
pub mod registry;
pub use registry::register;
