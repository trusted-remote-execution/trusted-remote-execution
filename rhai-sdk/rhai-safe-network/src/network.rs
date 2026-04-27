#![deny(missing_docs)]
#![allow(
    unused_variables,
    unreachable_code,
    clippy::unreachable,
    unused_mut,
    clippy::needless_pass_by_value,
    dead_code,
    clippy::unused_self,
    clippy::trivially_copy_pass_by_ref
)]
//! The functions used here are declared in the `rust-network` crate.

use anyhow::Result;
use rhai::EvalAltResult;
use rust_safe_network::netstat::NetworkStats;
use rust_safe_network::{Connection, Network};
use rust_safe_system_info::TransportProtocol;

/// Connects to an endpoint. Currently no other actions are supported on the connection besides
/// opening a new connection.
///
/// # Cedar Permissions
///
/// | Action | Resource |
/// |--------|----------|
/// | `network::Action::"connect"` | [`network::Network`](cedar_auth::network::entities::NetworkEntity) |
///
/// NB: Resource is the endpoint passed to `connect()`.
///
/// # Example
///
/// ```
/// # use rex_test_utils::rhai::sysinfo::create_temp_test_env;
/// # let (mut scope, engine) = create_temp_test_env();
/// # let result = engine.eval_with_scope::<()>(
/// #     &mut scope,
/// #     r#"
/// let connection = connect("127.0.0.1", 8080, TransportProtocol::UDP);
/// # "#);
/// #
/// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
/// ```
#[doc(alias = "nc")]
pub fn connect(
    endpoint: &str,
    port: i64,
    protocol: TransportProtocol,
) -> Result<Connection, Box<EvalAltResult>> {
    unreachable!("This method exists only for documentation.")
}

/// Gets network interface information including IP addresses
///
/// Note: This API always returns global host interfaces, even when called inside an `nsenter` callback.
///
/// # Cedar Permissions
///
/// | Action | Resource |
/// |--------|----------|
/// | `sysinfo::Action::"list"` | [`sysinfo::Sysinfo`](cedar_auth::sysinfo::entities::SysinfoEntity) |
///
/// # Example
///
/// ```ignore
/// # use rex_test_utils::rhai::sysinfo::create_temp_test_env;
/// # let (mut scope, engine) = create_temp_test_env();
/// # let result = engine.eval_with_scope::<()>(
/// #     &mut scope,
/// #     r#"
/// let addresses = ip_addresses();
/// let found_interface = false;
/// let found_ip = false;
///
/// for address in addresses {
///     if address.interface_name == "lo" {
///         found_interface = true;
///
///         for ip in address.addresses {
///             if ip.contains("127.0.0.1") {
///                 found_ip = true;
///                 break;
///             }
///         }
///
///         break;
///     }
/// }
///
/// if !found_interface {
///     throw "failed to get loopback"
/// }
/// if !found_ip {
///     throw "failed to get loopback IP"
/// }
/// #     "#);
/// #
/// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
/// ```
#[doc(alias = "ip")]
pub fn ip_addresses() -> Result<Vec<Network>, Box<EvalAltResult>> {
    unreachable!("This method exists only for documentation.")
}

/// Gets network statistics including active connections and sockets
///
/// Returns information about active Internet connections (TCP/UDP) and UNIX domain sockets,
/// similar to the `netstat` command.
///
/// # Cedar Permissions
///
/// | Action | Resource |
/// |--------|----------|
/// | `file_system::Action::"open"` | [`file_system::File`](cedar_auth::fs::entities::FileEntity) |
/// | `file_system::Action::"read"` | [`file_system::File`](cedar_auth::fs::entities::FileEntity) |
///
/// NB: Files are `/proc`, `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6`, `/proc/net/unix`.
///
/// # Example
///
/// ```ignore
/// # use rex_test_utils::rhai::sysinfo::create_temp_test_env;
/// # let (mut scope, engine) = create_temp_test_env();
/// # let result = engine.eval_with_scope::<()>(
/// #     &mut scope,
/// #     r#"
/// let stats = network_stats();
///
/// // Access internet connections
/// for conn in stats.internet_connections {
///     print(`${conn.protocol} ${conn.local_address} -> ${conn.remote_address}`);
///     
///     let proc = conn.process_info;
///     if conn.protocol == NetworkProtocol::TCP && proc != () {
///         print("Process: " + proc.process_name + " PID: " + proc.pid);
///     }
/// }
///
/// // Access unix sockets
/// for socket in stats.unix_sockets {
///     print(socket.protocol + " inode: " + socket.inode);
///     if socket.path != "" {
///         print("Path: " + socket.path);
///     }
/// }
/// #     "#);
/// #
/// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
/// ```
#[doc(alias = "netstat")]
pub fn network_stats() -> Result<NetworkStats, Box<EvalAltResult>> {
    unreachable!("This method exists only for documentation.")
}
