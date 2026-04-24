// Vendor-facing API
pub use sysctl::SysctlManager;
pub use system_info::SystemInfo;
pub mod errors;
pub mod kernel_stats;
pub mod transport_protocol;

// Internal (private modules are hidden from rustdoc)
pub(crate) mod command;
mod sysctl;
mod system_info;

// Consumed by other crates, hidden from vendor docs
#[doc(hidden)]
mod registry;
#[doc(hidden)]
pub use registry::register;
