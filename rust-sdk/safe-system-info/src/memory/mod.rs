use cfg_if::cfg_if;

mod common;

// public re-exports
pub use common::{Meminfo, Swapinfo};

// pub(crate) re-exports
pub(crate) use common::MeminfoProvider;

cfg_if! {
    if #[cfg(target_os = "linux")] {
        mod linux;

        // pub(crate) re-exports
        pub(crate) use linux::Memory;

        // private re-exports
        use linux::MeminfoExt;
    } else {
        mod nonlinux;

        // pub(crate) re-exports
        pub(crate) use nonlinux::Memory;

        // private re-exports
        use nonlinux::MeminfoExt;
    }
}
