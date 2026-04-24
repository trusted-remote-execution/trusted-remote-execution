//! System information about the OS and kernel version
//!
//! Provides access to kernel version similar to `uname` command.

use cfg_if::cfg_if;

mod common;

pub use common::UnameInfo;

#[cfg(target_os = "linux")]
pub(crate) use common::UnameProvider;

cfg_if! {
    if #[cfg(target_os = "linux")] {
        mod linux;
        pub(crate) use linux::Uname;
    } else {
        mod nonlinux;
        pub(crate) use nonlinux::Uname;
    }
}
