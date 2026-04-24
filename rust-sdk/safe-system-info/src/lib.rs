//! The Rust systeminfo crate provides information about system resource usage, such as memory and CPU usage.

#![forbid(unsafe_code)]
// Common/utility exports
pub mod auth;

pub mod errors;
pub use errors::RustSysteminfoError;

pub mod options;
pub use options::{
    DmesgOptions, DmesgOptionsBuilder, DnsResolver, ResolveConfig, ResolveConfigBuilder,
    TransportProtocol,
};

// Feature exports
mod system;
pub use system::{SysctlManager, SystemInfo, open_proc_fd};

mod memory;
pub use memory::{Meminfo, Swapinfo};

mod slab;
#[cfg(target_os = "linux")]
pub use slab::{SlabEntry, SlabInfo, SlabSummary};

pub mod dmesg;
pub use dmesg::DmesgEntry;

pub mod uname;
pub use uname::UnameInfo;

mod sysctl;
pub use sysctl::SysctlEntry;

mod dns;
use dns::DNSInfo;
