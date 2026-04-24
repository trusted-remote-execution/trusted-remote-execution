use cfg_if::cfg_if;

mod common;
pub use common::{Filesystem, FilesystemProvider};

cfg_if! {
    if #[cfg(target_os = "linux")] {
        mod linux;
        pub use linux::Df;
    } else {
        mod nonlinux;
        pub use nonlinux::Df;
    }
}
