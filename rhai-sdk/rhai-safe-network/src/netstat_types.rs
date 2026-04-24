//! Network statistics types for use in Rhai scripts
//!
//! This module re-exports network protocol and state types from [`rust_network`] for use in Rhai,
//! providing constants and comparison operators for network statistics operations.
use rhai::plugin::{
    Dynamic, FnNamespace, FuncRegistration, Module, NativeCallContext, PluginFunc, RhaiResult,
    TypeId, export_module, mem,
};
use rust_network::{NetworkProtocol, TcpState, UnixProtocol, UnixSocketState};

#[allow(non_upper_case_globals)]
#[allow(unreachable_pub)]
#[allow(clippy::unwrap_used)]
#[export_module]
pub(crate) mod network_protocol_module {
    use super::{Module, NetworkProtocol};

    pub const TCP: NetworkProtocol = NetworkProtocol::Tcp;
    pub const TCP6: NetworkProtocol = NetworkProtocol::Tcp6;
    pub const UDP: NetworkProtocol = NetworkProtocol::Udp;
    pub const UDP6: NetworkProtocol = NetworkProtocol::Udp6;

    #[rhai_fn(global, name = "==", pure)]
    pub fn eq(protocol: &mut NetworkProtocol, other: NetworkProtocol) -> bool {
        protocol == &other
    }

    #[rhai_fn(global, name = "!=", pure)]
    pub fn neq(protocol: &mut NetworkProtocol, other: NetworkProtocol) -> bool {
        protocol != &other
    }

    #[rhai_fn(global, name = "to_string")]
    pub fn to_string(protocol: &mut NetworkProtocol) -> String {
        format!("{protocol:?}")
    }
}

#[allow(non_upper_case_globals)]
#[allow(unreachable_pub)]
#[allow(clippy::unwrap_used)]
#[export_module]
pub(crate) mod tcp_state_module {
    use super::TcpState;

    pub const ESTABLISHED: TcpState = TcpState::Established;
    pub const SYN_SENT: TcpState = TcpState::SynSent;
    pub const SYN_RECV: TcpState = TcpState::SynRecv;
    pub const FIN_WAIT1: TcpState = TcpState::FinWait1;
    pub const FIN_WAIT2: TcpState = TcpState::FinWait2;
    pub const TIME_WAIT: TcpState = TcpState::TimeWait;
    pub const CLOSE: TcpState = TcpState::Close;
    pub const CLOSE_WAIT: TcpState = TcpState::CloseWait;
    pub const LAST_ACK: TcpState = TcpState::LastAck;
    pub const LISTEN: TcpState = TcpState::Listen;
    pub const CLOSING: TcpState = TcpState::Closing;
    pub const NEW_SYN_RECV: TcpState = TcpState::NewSynRecv;
    pub const NONE: TcpState = TcpState::None;

    #[rhai_fn(global, name = "==", pure)]
    pub fn eq(state: &mut TcpState, other: TcpState) -> bool {
        state == &other
    }

    #[rhai_fn(global, name = "!=", pure)]
    pub fn neq(state: &mut TcpState, other: TcpState) -> bool {
        state != &other
    }

    #[rhai_fn(global, name = "to_string")]
    pub fn to_string(state: &mut TcpState) -> String {
        format!("{state:?}")
    }
}

#[allow(non_upper_case_globals)]
#[allow(unreachable_pub)]
#[allow(clippy::unwrap_used)]
#[export_module]
pub(crate) mod unix_protocol_module {
    use super::{Module, UnixProtocol};

    pub const STREAM: UnixProtocol = UnixProtocol::Stream;
    pub const DGRAM: UnixProtocol = UnixProtocol::Dgram;
    pub const SEQPACKET: UnixProtocol = UnixProtocol::Seqpacket;

    #[rhai_fn(global, name = "==", pure)]
    pub fn eq(protocol: &mut UnixProtocol, other: UnixProtocol) -> bool {
        protocol == &other
    }

    #[rhai_fn(global, name = "!=", pure)]
    pub fn neq(protocol: &mut UnixProtocol, other: UnixProtocol) -> bool {
        protocol != &other
    }

    #[rhai_fn(global, name = "to_string")]
    pub fn to_string(protocol: &mut UnixProtocol) -> String {
        format!("{protocol:?}")
    }
}

#[allow(non_upper_case_globals)]
#[allow(unreachable_pub)]
#[allow(clippy::unwrap_used)]
#[export_module]
pub(crate) mod unix_socket_state_module {
    use super::{Module, UnixSocketState};

    pub const UNCONNECTED: UnixSocketState = UnixSocketState::Unconnected;
    pub const CONNECTING: UnixSocketState = UnixSocketState::Connecting;
    pub const CONNECTED: UnixSocketState = UnixSocketState::Connected;
    pub const DISCONNECTING: UnixSocketState = UnixSocketState::Disconnecting;

    #[rhai_fn(global, name = "==", pure)]
    pub fn eq(state: &mut UnixSocketState, other: UnixSocketState) -> bool {
        state == &other
    }

    #[rhai_fn(global, name = "!=", pure)]
    pub fn neq(state: &mut UnixSocketState, other: UnixSocketState) -> bool {
        state != &other
    }

    #[rhai_fn(global, name = "to_string")]
    pub fn to_string(state: &mut UnixSocketState) -> String {
        format!("{state:?}")
    }
}
