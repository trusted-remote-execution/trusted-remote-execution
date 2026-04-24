//! # `RhaiSafeIOLanguage`
//!
//! Safe file system operations for Rhai scripts. This crate wraps the `rust-safe-io`
//! library and exposes it to the Rhai scripting engine.

use cfg_if::cfg_if;

// Vendor-facing API
pub use safe_io::{DirConfig, DirHandle, FileHandle, SymlinkHandle, replace_text};
pub mod dir_entry;
pub mod errors;

// Internal (private modules are hidden from rustdoc)
pub(crate) mod command;
#[cfg(target_os = "linux")]
mod elf_info;
#[cfg(target_os = "linux")]
mod execute;
mod gzip;
mod safe_io;
#[cfg(target_os = "linux")]
mod truncate;
#[cfg(target_os = "linux")]
mod utils;

// Consumed by other crates, hidden from vendor docs
#[doc(hidden)]
pub mod registry;
#[doc(hidden)]
pub use registry::register_safe_io_functions;

cfg_if! {
    if #[cfg(target_os = "linux")] {
        mod core_dump_analysis;
        pub use core_dump_analysis::docs::CoreDump;
        #[doc(hidden)]
        pub use core_dump_analysis::register_core_dump_analysis_functions;
    }
}
