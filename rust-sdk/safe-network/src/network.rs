//! Network operations in Rust
//!
//! This module provides network operations such as `nc` equivalents.

use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use crate::RustNetworkError;
use crate::auth::is_authorized_url;
use derive_getters::Getters;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::network::actions::NetworkAction;
use rust_safe_system_info::auth::is_authorized_sysinfo;
use rust_safe_system_info::{RustSysteminfoError, TransportProtocol};
use serde::Serialize;
use sysinfo::Networks;

/// Default timeout for port checking operations (in seconds)
const PORT_CHECK_TIMEOUT_SECS: u64 = 5;
const DEFAULT_BIND_ADDRESS: &str = "0.0.0.0:0";

#[derive(Debug, Clone, Getters, Serialize)]
pub struct Network {
    interface_name: String,
    addresses: Vec<String>,
}

/// Represents a connection, either TCP or UDP
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum Connection {
    /// A connected TCP stream
    Tcp(Arc<TcpStream>),
    /// A connected UDP socket
    Udp(Arc<UdpSocket>),
}

/// Connects to the given endpoint using the specified protocol and returns a socket/stream
/// for sending and receiving data. Defaults timeout to 5 seconds.
pub fn connect(
    cedar_auth: &CedarAuth,
    endpoint: &str,
    port: u16,
    protocol: TransportProtocol,
) -> Result<Connection, RustNetworkError> {
    is_authorized_url(cedar_auth, NetworkAction::Connect, endpoint)?;
    match protocol {
        TransportProtocol::TCP => Ok(Connection::Tcp(Arc::new(connect_tcp(endpoint, port)?))),
        TransportProtocol::UDP => Ok(Connection::Udp(Arc::new(connect_udp(endpoint, port)?))),
        TransportProtocol::Auto => {
            // Try TCP first, fall back to UDP on failure
            match connect_tcp(endpoint, port) {
                Ok(stream) => Ok(Connection::Tcp(Arc::new(stream))),
                Err(_) => Ok(Connection::Udp(Arc::new(connect_udp(endpoint, port)?))),
            }
        }

        _ => Err(RustNetworkError::UnsupportedProtocol {
            protocol: format!("{protocol:?}"),
        }),
    }
}

/// Returns networks which contain interfaces and IP addresses of the host
pub fn ip_addresses(cedar_auth: &CedarAuth) -> Result<Vec<Network>, RustSysteminfoError> {
    is_authorized_sysinfo(cedar_auth)?;
    let networks = Networks::new_with_refreshed_list();
    Ok(networks
        .iter()
        .map(|(name, data)| Network {
            interface_name: name.clone(),
            addresses: data
                .ip_networks()
                .iter()
                .map(|ip_net| ip_net.addr.to_string())
                .collect::<Vec<String>>(),
        })
        .collect())
}

fn parse_socket_address(endpoint: &str, port: u16) -> Result<SocketAddr, RustNetworkError> {
    let addr_str = format!("{endpoint}:{port}");
    addr_str
        .to_socket_addrs()
        .map_err(|_| RustNetworkError::AddressParseError {
            address: addr_str.clone(),
        })?
        .next()
        .ok_or_else(|| RustNetworkError::AddressParseError { address: addr_str })
}

fn connect_tcp(endpoint: &str, port: u16) -> Result<TcpStream, RustNetworkError> {
    let addr = parse_socket_address(endpoint, port)?;
    Ok(TcpStream::connect_timeout(
        &addr,
        Duration::from_secs(PORT_CHECK_TIMEOUT_SECS),
    )?)
}

fn connect_udp(endpoint: &str, port: u16) -> Result<UdpSocket, RustNetworkError> {
    let addr = parse_socket_address(endpoint, port)?;
    let socket = UdpSocket::bind(DEFAULT_BIND_ADDRESS)?;
    socket.set_read_timeout(Some(Duration::from_secs(PORT_CHECK_TIMEOUT_SECS)))?;
    socket.connect(addr)?;
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use rex_cedar_auth::{
        cedar_auth::CedarAuth,
        network::actions::NetworkAction,
        sysinfo::actions::SysinfoAction,
        test_utils::{TestCedarAuthBuilder, get_test_rex_principal},
    };
    use rex_test_utils::assertions::assert_error_contains;
    use rstest::rstest;
    use rust_safe_system_info::TransportProtocol;
    use std::net::TcpListener;

    use crate::network::ip_addresses;

    use super::{connect, connect_tcp, connect_udp};

    fn setup_policy(forbid_policy: bool) -> (CedarAuth, String) {
        let principal = get_test_rex_principal();
        let endpoint = "127.0.0.1";

        let policy = if forbid_policy {
            format!(
                r#"
            permit(
                principal == User::"{}",
                action == {},
                resource == network::url::"foo.com/is/allowed"
            );"#,
                principal,
                NetworkAction::Connect,
            )
        } else {
            format!(
                r#"
            permit(
                principal == User::"{}",
                action == {},
                resource == network::url::"{}"
            );"#,
                principal,
                NetworkAction::Connect,
                endpoint
            )
        };

        let cedar_auth = TestCedarAuthBuilder::default()
            .policy(policy)
            .build()
            .unwrap()
            .create();

        (cedar_auth, endpoint.to_string())
    }

    /// Given: A policy that allows access
    /// When: All protocols are attempted
    /// Then: It returns a connected socket
    #[rstest]
    #[case(TransportProtocol::TCP, false)]
    #[case(TransportProtocol::UDP, false)]
    #[case(TransportProtocol::Auto, true)]
    #[case(TransportProtocol::Auto, false)]
    fn test_check_port_open(#[case] protocol: TransportProtocol, #[case] fallback_to_udp: bool) {
        use super::Connection;

        let (cedar_auth, endpoint) = setup_policy(false);
        let mut tcp_listener: Option<TcpListener> = None;

        let port = if protocol == TransportProtocol::UDP || fallback_to_udp {
            8080
        } else {
            let listener = TcpListener::bind(format!("{endpoint}:0")).unwrap();
            let port = listener.local_addr().unwrap().port();
            tcp_listener = Some(listener);
            port
        };

        let result = connect(&cedar_auth, &endpoint, port, protocol).unwrap();
        match (protocol, fallback_to_udp) {
            (TransportProtocol::TCP, _) => assert!(matches!(result, Connection::Tcp(_))),
            (TransportProtocol::UDP, _) => assert!(matches!(result, Connection::Udp(_))),
            (TransportProtocol::Auto, true) => assert!(matches!(result, Connection::Udp(_))),
            (TransportProtocol::Auto, false) => assert!(matches!(result, Connection::Tcp(_))),
            _ => {}
        }

        drop(tcp_listener);
    }

    /// Given: A policy that does not allow access
    /// When: port is checked
    /// Then: Permission denied error is returned
    #[test]
    fn test_permission_denied() {
        let (cedar_auth, endpoint) = setup_policy(true);
        let listener = TcpListener::bind(format!("{endpoint}:0")).unwrap();
        let port = listener.local_addr().unwrap().port();
        let principal = get_test_rex_principal();

        let result = connect(&cedar_auth, &endpoint, port, TransportProtocol::TCP);
        let expected_error = format!("Permission denied: {principal} unauthorized to perform");
        assert_error_contains(result, &expected_error);
    }

    /// Given: An invalid hostname that cannot be resolved
    /// When: connect_tcp is called with this hostname
    /// Then: It returns an AddressParseError
    #[test]
    fn test_connect_tcp_invalid_hostname() {
        let result = connect_tcp("this.hostname.definitely.does.not.exist.invalid", 80);
        assert!(result.is_err(), "Invalid hostname should return error");
    }

    /// Given: An invalid hostname that cannot be resolved
    /// When: connect_udp is called with this hostname
    /// Then: It returns an AddressParseError
    #[test]
    fn test_connect_udp_invalid_hostname() {
        let result = connect_udp("this.hostname.definitely.does.not.exist.invalid", 53);
        assert!(result.is_err(), "Invalid hostname should return error");
    }

    /// Given: An invalid IP
    /// When: check_udp_port is called with this hostname
    /// Then: It returns an error
    #[test]
    fn test_check_udp_port_invalid_endpoint() {
        let result = connect_udp("1.1.1.1.1.1", 0);
        assert!(result.is_err(), "Invalid hostname should return error");
    }

    /// Given: A call to ip_addresses()
    /// When: The function is called
    /// Then: All networks and IPs are returned, including loopback with at least one IP
    #[test]
    fn test_ipaddresses() {
        let cedar_auth = TestCedarAuthBuilder::default().build().unwrap().create();

        let result = ip_addresses(&cedar_auth).unwrap();

        let loopback = result.iter().find(|network| {
            let name = network.interface_name().to_lowercase();
            name == "lo" || name.starts_with("lo") || name.contains("loopback")
        });

        assert!(
            loopback.is_some(),
            "Loopback interface not found in network interfaces"
        );

        let loopback = loopback.unwrap();
        assert!(
            !loopback.addresses().is_empty(),
            "Loopback interface has no IP addresses"
        );
    }

    /// Given: A policy that allows getting IP addresses
    /// When: getting IP addresses
    /// Then: Call succeeds
    #[test]
    fn test_ipaddresses_authz() {
        let principal = get_test_rex_principal();
        let test_policy = format!(
            r#"
            permit (
                principal == User::"{principal}",
                action == {},
                resource
            );"#,
            SysinfoAction::List,
        );

        let cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy)
            .build()
            .unwrap()
            .create();

        let result = ip_addresses(&cedar_auth);
        assert!(result.is_ok(), "getting ip addresses should succeed",);
    }

    /// Given: a restrictive policy
    /// When: getting ip_addresses
    /// Then: an authorization error is returned
    #[test]
    fn test_ipaddresses_unauthz() {
        let principal = get_test_rex_principal();
        let test_policy = format!(
            r#"
            permit (
                principal == User::"randouser",
                action == {},
                resource
            );"#,
            SysinfoAction::List
        );

        let cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy)
            .build()
            .unwrap()
            .create();

        let result = ip_addresses(&cedar_auth);

        let expected_error = format!(
            "Permission denied: {principal} unauthorized to perform {}",
            SysinfoAction::List
        );
        assert_error_contains(result, &expected_error);
    }
}
