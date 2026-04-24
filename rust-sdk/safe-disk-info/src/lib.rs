//! The Rust diskinfo crate provides disk information functionality similar to the Unix `df` command.

#![forbid(unsafe_code)]
// Common/utility exports
pub mod auth;
#[cfg(target_os = "linux")]
pub(crate) use auth::is_authorized;

pub mod utils;

pub mod errors;
pub use errors::RustDiskinfoError;

pub mod constants;
pub use constants::Unit;

pub mod options;
pub use options::{
    FilesystemOptions, FilesystemOptionsBuilder, UnmountOptions, UnmountOptionsBuilder,
};

// Feature exports
mod diskinfo;
pub use diskinfo::Filesystems;

pub mod df;
pub use df::Filesystem;

pub mod iostat;
pub use iostat::{CpuStats, DeviceStats, IoStatSnapshot};

pub mod unmount;
pub use unmount::unmount;
