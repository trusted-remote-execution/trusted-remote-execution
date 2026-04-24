// Vendor-facing API
pub use filesystems::Filesystems;
#[cfg(target_os = "linux")]
pub use filesystems::unmount;
pub mod errors;

// Internal (private modules are hidden from rustdoc)
pub(crate) mod command;
mod filesystems;

// Consumed by other crates, hidden from vendor docs
#[doc(hidden)]
mod registry;
#[doc(hidden)]
pub use registry::register;
