//! # Kernel Ring Buffer (dmesg) Access
//!
//! Provides access to Linux kernel messages through the kernel ring buffer.
//! The kernel ring buffer contains boot messages, driver events, hardware
//! detection, and system warnings that help with troubleshooting and monitoring.

use cfg_if::cfg_if;

mod common;

pub use common::DmesgEntry;

#[cfg(target_os = "linux")]
pub(crate) use common::DmesgProvider;

cfg_if! {
    if #[cfg(target_os = "linux")] {
        mod linux;

        pub(crate) use linux::Dmesg;
    } else {
        mod nonlinux;

        pub(crate) use nonlinux::Dmesg;
    }
}
