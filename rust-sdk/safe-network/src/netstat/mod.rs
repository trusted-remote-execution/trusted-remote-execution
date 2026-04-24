//! Network statistics and connection information
//!
//! Provides access to network connection information similar to `netstat` command.

use cfg_if::cfg_if;

mod common;

pub use common::{
    InternetConnection, NetworkProtocol, NetworkStats, ProcessInfo, TcpState, UnixProtocol,
    UnixSocket, UnixSocketState,
};

cfg_if! {
    if #[cfg(target_os = "linux")] {
        mod linux;
        pub use linux::network_stats;
    } else {
        mod nonlinux;
        pub use nonlinux::network_stats;
    }
}
