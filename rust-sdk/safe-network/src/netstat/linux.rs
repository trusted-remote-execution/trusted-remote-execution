//! Linux-specific implementation of netstat functionality

use super::common::{InternetConnection, NetworkStats, ProcessInfo, UnixSocket};
use crate::auth::is_authorized_file;
use crate::errors::RustNetworkError;
use procfs::net::{tcp, tcp6, udp, udp6, unix};
use procfs::process::{FDTarget, all_processes};
use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_logger::warn;
use std::collections::HashMap;

const PROC_UDP: &str = "/proc/net/udp";
const PROC_UDP6: &str = "/proc/net/udp6";
const PROC_TCP: &str = "/proc/net/tcp";
const PROC_TCP6: &str = "/proc/net/tcp6";
const PROC_UNIX: &str = "/proc/net/unix";

/// Get network statistics on Linux
///
/// This function reads network connection information from /proc/net/[protocol]
/// then maps sockets to their owning processes.
///
/// /// # Examples
///
/// ```no_run
/// # use rust_network::netstat;
/// # use rex_cedar_auth::cedar_auth::CedarAuth;
/// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
/// #
/// # let cedar_auth = CedarAuth::new(
/// #     &get_default_test_rex_policy(),
/// #     get_default_test_rex_schema(),
/// #     "[]"
/// # ).unwrap().0;
///
/// let stats = netstat::network_stats(&cedar_auth).unwrap();
///
/// // Print connection counts
/// println!("Internet Connections: {}", stats.internet_connections.len());
/// println!("Unix Sockets: {}", stats.unix_sockets.len());
///
/// // Iterate through connections
/// for conn in &stats.internet_connections {
///     println!("{:?} {} -> {} (State: {:?})",
///         conn.protocol, conn.local_address, conn.remote_address, conn.state);
///     if let Some(proc) = &conn.process_info {
///         println!("  Process: {} (PID: {})", proc.process_name, proc.pid);
///     }
/// }
///
/// // Iterate through unix sockets
/// for socket in &stats.unix_sockets {
///     println!("{:?} inode: {} path: {}",
///         socket.protocol, socket.inode, socket.path);
/// }
/// ```
///
/// # Note
///
/// Processes can exit and sockets can close between reading /proc/net/[protocol] and
/// /proc/[pid]/fd. This is acceptable since netstat provides a point-in-time snapshot
/// rather than a consistent view, and this matches the unix netstat behaviour.
pub fn network_stats(cedar_auth: &CedarAuth) -> Result<NetworkStats, RustNetworkError> {
    let mut internet_connections = get_internet_connections(cedar_auth)?;
    let mut unix_sockets = get_unix_sockets(cedar_auth)?;

    let inode_map = map_sockets_to_processes(cedar_auth)?;

    // Map connections to processes
    for connection in &mut internet_connections {
        connection.process_info = inode_map.get(&connection.inode).cloned();
    }

    // Map sockets to processes
    for socket in &mut unix_sockets {
        socket.process_info = inode_map.get(&socket.inode).cloned();
    }

    Ok(NetworkStats::new(internet_connections, unix_sockets))
}

/// Maps socket inodes to process information
#[allow(clippy::cast_sign_loss)]
fn map_sockets_to_processes(
    cedar_auth: &CedarAuth,
) -> Result<HashMap<u64, ProcessInfo>, RustNetworkError> {
    is_authorized_file(cedar_auth, FilesystemAction::Open, "/proc")?;
    is_authorized_file(cedar_auth, FilesystemAction::Read, "/proc")?;

    let mut inode_map = HashMap::new();
    for proc_result in all_processes().map_err(|e| RustNetworkError::ProcessEnumerationError {
        message: format!("Failed to enumerate processes: {e}"),
    })? {
        match proc_result {
            Ok(process) => {
                // Get process name from /proc/[pid]/stat
                let process_name = process
                    .stat()
                    .map_or_else(|_| String::from("unknown"), |stat| stat.comm);

                let pid = process.pid as u32;

                // Scan file descriptors for socket inodes
                if let Ok(fds) = process.fd() {
                    for fd_info in fds.flatten() {
                        if let FDTarget::Socket(inode) = fd_info.target {
                            let process_info = ProcessInfo {
                                pid,
                                process_name: process_name.clone(),
                            };
                            inode_map.insert(inode, process_info);
                        }
                    }
                }
            }
            Err(e) => warn!("Process could not be read: {e}"), // Skip processes we can't read
        }
    }

    Ok(inode_map)
}

/// Get all Internet connections (TCP and UDP, both IPv4 and IPv6)
fn get_internet_connections(
    cedar_auth: &CedarAuth,
) -> Result<Vec<InternetConnection>, RustNetworkError> {
    let mut connections = Vec::new();

    is_authorized_file(cedar_auth, FilesystemAction::Open, PROC_TCP)?;
    is_authorized_file(cedar_auth, FilesystemAction::Read, PROC_TCP)?;
    for tcp_entry in tcp().map_err(|e| RustNetworkError::Other(e.into()))? {
        connections.push(InternetConnection::from_tcp_net_entry(&tcp_entry, false));
    }

    is_authorized_file(cedar_auth, FilesystemAction::Open, PROC_TCP6)?;
    is_authorized_file(cedar_auth, FilesystemAction::Read, PROC_TCP6)?;
    for tcp6_entry in tcp6().map_err(|e| RustNetworkError::Other(e.into()))? {
        connections.push(InternetConnection::from_tcp_net_entry(&tcp6_entry, true));
    }

    is_authorized_file(cedar_auth, FilesystemAction::Open, PROC_UDP)?;
    is_authorized_file(cedar_auth, FilesystemAction::Read, PROC_UDP)?;
    for udp_entry in udp().map_err(|e| RustNetworkError::Other(e.into()))? {
        connections.push(InternetConnection::from_udp_net_entry(&udp_entry, false));
    }

    is_authorized_file(cedar_auth, FilesystemAction::Open, PROC_UDP6)?;
    is_authorized_file(cedar_auth, FilesystemAction::Read, PROC_UDP6)?;
    for udp6_entry in udp6().map_err(|e| RustNetworkError::Other(e.into()))? {
        connections.push(InternetConnection::from_udp_net_entry(&udp6_entry, true));
    }

    Ok(connections)
}

fn get_unix_sockets(cedar_auth: &CedarAuth) -> Result<Vec<UnixSocket>, RustNetworkError> {
    is_authorized_file(cedar_auth, FilesystemAction::Open, PROC_UNIX)?;
    is_authorized_file(cedar_auth, FilesystemAction::Read, PROC_UNIX)?;

    let mut sockets = Vec::new();

    for unix_entry in unix().map_err(|e| RustNetworkError::Other(e.into()))? {
        sockets.push(UnixSocket::from_unix_net_entry(&unix_entry));
    }

    Ok(sockets)
}
