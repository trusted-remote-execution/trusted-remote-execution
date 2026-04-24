//! Internal sysctl implementation

mod common;
pub use common::SysctlEntry;
pub(crate) use common::SysctlProvider;

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(target_os = "linux")] {
        mod linux;
        pub(crate) use linux::Sysctl;
    } else {
        mod nonlinux;
        pub(crate) use nonlinux::Sysctl;
    }
}
