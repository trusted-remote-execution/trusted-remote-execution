use cfg_if::cfg_if;

mod common;
pub use common::{CpuStats, DeviceStats, IoStatProvider, IoStatSnapshot};

cfg_if! {
    if #[cfg(target_os = "linux")] {
        mod linux;
        pub use linux::IoStat;
    } else {
        mod nonlinux;
        pub use nonlinux::IoStat;
    }
}
