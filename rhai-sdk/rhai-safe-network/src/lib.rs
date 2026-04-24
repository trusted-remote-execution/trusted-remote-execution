// Vendor-facing API
pub mod client;
pub mod errors;
pub mod netstat_types;
pub mod network;

pub(crate) mod command;

// Consumed by other crates, hidden from vendor docs
#[doc(hidden)]
mod registry;
#[doc(hidden)]
pub use registry::register;
