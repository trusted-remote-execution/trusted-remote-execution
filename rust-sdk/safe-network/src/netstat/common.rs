use derive_getters::Getters;
#[cfg(target_os = "linux")]
use procfs::net::{TcpNetEntry, TcpState as Proc_TCP_State, UdpNetEntry, UnixNetEntry, UnixState};
#[cfg(target_os = "linux")]
use rex_logger::warn;
use serde::Serialize;
use std::net::SocketAddr;

// https://github.com/torvalds/linux/blob/master/include/linux/net.h
#[cfg(target_os = "linux")]
const SOCK_STREAM: u16 = 1;
#[cfg(target_os = "linux")]
const SOCK_DGRAM: u16 = 2;
#[cfg(target_os = "linux")]
const SOCK_SEQPACKET: u16 = 5;

#[derive(Debug, Clone, Getters, Serialize)]
pub struct NetworkStats {
    /// Active Internet connections (TCP/UDP)
    pub internet_connections: Vec<InternetConnection>,

    /// Active UNIX domain sockets
    pub unix_sockets: Vec<UnixSocket>,
}

impl NetworkStats {
    pub const fn new(
        internet_connections: Vec<InternetConnection>,
        unix_sockets: Vec<UnixSocket>,
    ) -> NetworkStats {
        NetworkStats {
            internet_connections,
            unix_sockets,
        }
    }
}

/// Represents an active Internet connection (TCP or UDP)
#[derive(Debug, Clone, Getters, Serialize)]
pub struct InternetConnection {
    pub protocol: NetworkProtocol,
    pub recv_queue: u32,
    pub send_queue: u32,
    pub local_address: SocketAddr,
    pub remote_address: SocketAddr,
    pub state: TcpState,
    pub inode: u64,
    pub process_info: Option<ProcessInfo>,
}

impl InternetConnection {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        protocol: NetworkProtocol,
        recv_queue: u32,
        send_queue: u32,
        local_address: SocketAddr,
        remote_address: SocketAddr,
        state: TcpState,
        inode: u64,
        process_info: Option<ProcessInfo>,
    ) -> Self {
        InternetConnection {
            protocol,
            recv_queue,
            send_queue,
            local_address,
            remote_address,
            state,
            inode,
            process_info,
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) const fn from_tcp_net_entry(entry: &TcpNetEntry, is_ipv6: bool) -> Self {
        let protocol = if is_ipv6 {
            NetworkProtocol::Tcp6
        } else {
            NetworkProtocol::Tcp
        };

        InternetConnection::new(
            protocol,
            entry.rx_queue,
            entry.tx_queue,
            entry.local_address,
            entry.remote_address,
            convert_tcp_state(&entry.state),
            entry.inode,
            None,
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) const fn from_udp_net_entry(entry: &UdpNetEntry, is_ipv6: bool) -> Self {
        let protocol = if is_ipv6 {
            NetworkProtocol::Udp6
        } else {
            NetworkProtocol::Udp
        };

        InternetConnection::new(
            protocol,
            entry.rx_queue,
            entry.tx_queue,
            entry.local_address,
            entry.remote_address,
            TcpState::None, // UDP has no state
            entry.inode,
            None,
        )
    }
}

#[derive(Debug, Clone, Getters, Serialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub process_name: String,
}

/// Represents an active UNIX domain socket
#[derive(Debug, Clone, Getters, Serialize)]
pub struct UnixSocket {
    pub protocol: UnixProtocol,
    pub ref_count: u32,
    pub state: UnixSocketState,
    pub inode: u64,
    pub path: String,
    pub process_info: Option<ProcessInfo>,
}

impl UnixSocket {
    pub const fn new(
        protocol: UnixProtocol,
        ref_count: u32,
        state: UnixSocketState,
        inode: u64,
        path: String,
        process_info: Option<ProcessInfo>,
    ) -> Self {
        UnixSocket {
            protocol,
            ref_count,
            state,
            inode,
            path,
            process_info,
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn from_unix_net_entry(entry: &UnixNetEntry) -> Self {
        UnixSocket::new(
            convert_unix_type(entry.socket_type),
            entry.ref_count,
            // Skip flags
            convert_unix_state(&entry.state),
            entry.inode,
            entry
                .path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default(),
            None,
        )
    }
}

/// Protocol for network connections
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum NetworkProtocol {
    Tcp,
    Tcp6,
    Udp,
    Udp6,
}

/// TCP connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum TcpState {
    Established,
    SynSent,
    SynRecv,
    FinWait1,
    FinWait2,
    TimeWait,
    Close,
    CloseWait,
    LastAck,
    Listen,
    Closing,
    NewSynRecv,
    None,
}

/// UNIX domain socket protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum UnixProtocol {
    Stream,
    Dgram,
    Seqpacket,
}

/// UNIX domain socket state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum UnixSocketState {
    Unconnected,
    Connecting,
    Connected,
    Disconnecting,
}

/// Convert procfs `TcpState` to our `TcpState` enum
#[cfg(target_os = "linux")]
const fn convert_tcp_state(state: &Proc_TCP_State) -> TcpState {
    match state {
        Proc_TCP_State::Established => TcpState::Established,
        Proc_TCP_State::SynSent => TcpState::SynSent,
        Proc_TCP_State::SynRecv => TcpState::SynRecv,
        Proc_TCP_State::FinWait1 => TcpState::FinWait1,
        Proc_TCP_State::FinWait2 => TcpState::FinWait2,
        Proc_TCP_State::TimeWait => TcpState::TimeWait,
        Proc_TCP_State::Close => TcpState::Close,
        Proc_TCP_State::CloseWait => TcpState::CloseWait,
        Proc_TCP_State::LastAck => TcpState::LastAck,
        Proc_TCP_State::Listen => TcpState::Listen,
        Proc_TCP_State::Closing => TcpState::Closing,
        Proc_TCP_State::NewSynRecv => TcpState::NewSynRecv,
    }
}

/// Convert procfs `UnixType` to our `UnixProtocol` enum
#[cfg(target_os = "linux")]
fn convert_unix_type(socket_type: u16) -> UnixProtocol {
    match socket_type {
        SOCK_STREAM => UnixProtocol::Stream,
        SOCK_DGRAM => UnixProtocol::Dgram,
        SOCK_SEQPACKET => UnixProtocol::Seqpacket,
        _ => {
            warn!("Invalid UNIX socket type. Defaulting to STREAM");
            UnixProtocol::Stream
        }
    }
}

/// Convert procfs `UnixState` to our `UnixSocketState` enum
#[cfg(target_os = "linux")]
const fn convert_unix_state(state: &UnixState) -> UnixSocketState {
    match state {
        UnixState::UNCONNECTED => UnixSocketState::Unconnected,
        UnixState::CONNECTING => UnixSocketState::Connecting,
        UnixState::CONNECTED => UnixSocketState::Connected,
        UnixState::DISCONNECTING => UnixSocketState::Disconnecting,
    }
}
