use anyhow::Result;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rex_test_utils::assertions::assert_error_contains;
use rust_safe_network::netstat;
use rust_safe_network::netstat::{InternetConnection, NetworkProtocol, TcpState, UnixSocket};
use std::collections::HashSet;
use std::net::TcpListener;

fn validate_internet_connections(connections: &[InternetConnection]) -> Result<()> {
    assert!(
        !connections.is_empty(),
        "Expected at least some internet connections"
    );

    let mut seen_inodes = HashSet::new();

    for conn in connections {
        if conn.inode != 0 {
            assert!(
                seen_inodes.insert(conn.inode),
                "Duplicate inode {}",
                conn.inode
            );
        }

        match conn.protocol {
            NetworkProtocol::Tcp | NetworkProtocol::Tcp6 => {
                assert!(
                    conn.state != TcpState::None,
                    "TCP connection missing state (inode {})",
                    conn.inode
                );
            }
            NetworkProtocol::Udp | NetworkProtocol::Udp6 => {
                assert!(
                    conn.state == TcpState::None,
                    "UDP connection should not have state (inode {})",
                    conn.inode
                );
            }
            _ => {}
        }

        if let Some(proc) = &conn.process_info {
            assert!(proc.pid > 0, "Invalid PID for inode {}", conn.inode);
            assert!(
                !proc.process_name.is_empty(),
                "Empty process name for PID {}",
                proc.pid
            );
        }
    }

    Ok(())
}

fn validate_unix_sockets(sockets: &[UnixSocket]) -> Result<()> {
    assert!(!sockets.is_empty(), "Expected at least some unix sockets");

    let mut seen_inodes = HashSet::new();

    for socket in sockets {
        assert!(
            seen_inodes.insert(socket.inode),
            "Duplicate inode {}",
            socket.inode
        );

        if let Some(proc) = &socket.process_info {
            assert!(proc.pid > 0, "Invalid PID for inode {}", socket.inode);
            assert!(
                !proc.process_name.is_empty(),
                "Empty process name for PID {}",
                proc.pid
            );
        }
    }

    Ok(())
}

/// Given: A Linux system with network connections including a manually created test socket
/// When: network_stats is called
/// Then: Returns NetworkStats with valid connections and sockets, including the test socket we created
#[test]
#[cfg(target_os = "linux")]
fn test_network_stats_success() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let test_local_addr = listener.local_addr()?;

    let stats = netstat::network_stats(&DEFAULT_TEST_CEDAR_AUTH)?;

    let our_socket = stats
        .internet_connections
        .iter()
        .find(|conn| conn.local_address == test_local_addr)
        .expect("Should find our test socket in results");

    assert_eq!(our_socket.protocol, NetworkProtocol::Tcp);
    assert_eq!(our_socket.local_address, test_local_addr);
    assert_eq!(our_socket.remote_address.ip().to_string(), "0.0.0.0");
    assert_eq!(our_socket.remote_address.port(), 0);
    assert_eq!(our_socket.state, TcpState::Listen);
    assert!(our_socket.inode > 0);

    validate_internet_connections(&stats.internet_connections)?;
    validate_unix_sockets(&stats.unix_sockets)?;

    Ok(())
}

/// Given: A Linux system with network connections
/// When: network_stats() is called with a policy that fordbids access to /proc/
/// Then: Cedar auth check fails and an error is returned
#[test]
#[cfg(target_os = "linux")]
fn test_unauthorized_network_stats() -> Result<()> {
    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"/proc/"
        );"#,
        FilesystemAction::Read.to_string()
    );
    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let result = netstat::network_stats(&test_cedar_auth);

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Open
    );
    assert_error_contains(result, &expected_error);

    Ok(())
}
