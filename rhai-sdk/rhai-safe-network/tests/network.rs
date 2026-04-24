use std::net::TcpListener;

use rex_cedar_auth::{
    fs::actions::FilesystemAction, sysinfo::actions::SysinfoAction,
    test_utils::get_test_rex_principal,
};
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::rhai::common::create_test_engine_and_register;

mod common;
use common::create_test_engine_and_register_with_policy;
use rhai::{EvalAltResult, Map, Scope};

/// Given: An attempt to connect
/// When: The request is made
/// Then: The connection succeeds
#[test]
fn test_connect_success() -> Result<(), Box<EvalAltResult>> {
    let endpoint = "127.0.0.1";
    let listener = TcpListener::bind(format!("{endpoint}:0")).unwrap();
    let port = listener.local_addr().unwrap().port();

    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();
    scope.push_constant("endpoint", endpoint);
    scope.push_constant("port", port as i64);

    let script = format!(
        r#"
            let connection = connect(endpoint, port, TransportProtocol::TCP);
        "#
    );

    let result = engine.eval_with_scope::<()>(&mut scope, &script);

    assert!(result.is_ok(), "Expected connection to succeed: {result:?}");
    Ok(())
}

/// Given: A Cedar policy that denies network connect operations
/// When: Attempting to connect
/// Then: The operation fails with a PermissionDenied error
#[test]
fn test_connect_permission_denied() {
    let principal = rex_cedar_auth::test_utils::get_test_rex_principal();
    let deny_policy = format!(
        r#"
        forbid(
            principal == User::"{principal}",
            action == network::Action::"GET", // note that connect is not allowed
            resource
        );"#
    );
    let engine = create_test_engine_and_register_with_policy(&deny_policy);

    let result = engine.eval::<()>(
        r#"
        connect("127.0.0.1", 53, TransportProtocol::UDP)
    "#,
    );

    let expected_error = format!("Permission denied: {principal} unauthorized to perform");
    assert_error_contains(result, &expected_error);
}

/// Given: an unauthorized user and a SystemInfo object
/// When: resolve method is called
/// Then: an authorization error is returned
#[test]
fn test_ip_addresses_unauthorized() {
    let principal = get_test_rex_principal();
    let restrictive_policy = format!(
        r#"
            permit (
                principal,  
                action == {},
                resource
            );

            forbid (
                principal,  
                action,
                resource
            );
        "#,
        SysinfoAction::List
    );

    let engine = create_test_engine_and_register_with_policy(&restrictive_policy);
    let result = engine.eval::<()>(
        r#"
                ip_addresses();
            "#,
    );

    assert!(
        result.is_err(),
        "Unauthorized user should not be able to get ip addresses"
    );

    let expected_error = format!("Permission denied: {principal} unauthorized to perform");
    assert_error_contains(result, &expected_error);
}

/// Given: A policy that allows access
/// When: ip_addresses is called in Sysinfo
/// Then: at least loopback is reported
#[test]
#[cfg(target_os = "linux")]
fn test_ip_addresses_success() {
    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"
            permit (
                principal == User::"{principal}",
                action == {},
                resource
            );"#,
        SysinfoAction::List
    );

    let engine = create_test_engine_and_register_with_policy(&test_policy);
    let result = engine.eval::<()>(
        r#"
            let addresses = ip_addresses();
            let found_interface = false;
            let found_ip = false;

            for address in addresses {
                if address.interface_name == "lo" {
                    found_interface = true;

                    for ip in address.addresses {
                        if ip.contains("127.0.0.1") {
                            found_ip = true;
                            break;
                        }
                    }

                    break;
                }
            }

            if !found_interface {
                throw "failed to get loopback"
            }
            if !found_ip {
                throw "failed to get loopback IP"
            }
        "#,
    );

    assert!(
        result.is_ok(),
        "Getting IP Addresses should succeed: {}",
        result.unwrap_err()
    );
}

/// Given: A network object
/// When: to_map is called
/// Then: the map is equal to expected
#[test]
fn test_network_protocol_to_map() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();

    let result = engine.eval::<Map>(
        r#"
            let network = ip_addresses()[0];
            let expected = #{
                "interface_name": network.interface_name,
                "addresses": network.addresses
            };

            #{
                "expected": expected.to_json(),
                "actual": network.to_map().to_json()
            }
        "#,
    )?;

    let expected: String = result.get("expected").unwrap().clone().into_string()?;
    let actual: String = result.get("actual").unwrap().clone().into_string()?;
    assert_eq!(expected, actual);

    Ok(())
}

/// Given: A Linux system with network connections including a manually created test socket
/// When: network_stats is called with proper authorization
/// Then: Returns NetworkStats with valid connections and sockets, including the test socket
#[test]
#[cfg(target_os = "linux")]
fn test_network_stats_success() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let test_local_addr = listener.local_addr().unwrap();

    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();
    scope.push_constant("test_port", test_local_addr.port() as i64);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let stats = network_stats();
            
            // Verify we got some connections
            if stats.internet_connections.len() == 0 {
                throw "Expected at least some internet connections";
            }
            
            // Verify we got some unix sockets
            if stats.unix_sockets.len() == 0 {
                throw "Expected at least some unix sockets";
            }
            
            // Find our test socket
            let found_test_socket = false;
            for conn in stats.internet_connections {
                if conn.local_address.to_string().contains(test_port.to_string()) {
                    found_test_socket = true;
                    
                    // Verify connection properties
                    if conn.protocol != NetworkProtocol::TCP {
                        throw "Expected TCP protocol";
                    }
                    if conn.state != TcpState::LISTEN {
                        throw "Expected Listen state";
                    }
                    
                    break;
                }
            }
            
            if !found_test_socket {
                throw "Failed to find our test socket in results";
            }
            
            // Verify we can access connection fields
            let first_conn = stats.internet_connections[0];
            let protocol = first_conn.protocol;
            let recv_queue = first_conn.recv_queue;
            let send_queue = first_conn.send_queue;
            let local_addr = first_conn.local_address;
            let remote_addr = first_conn.remote_address;
            let state = first_conn.state;
            let inode = first_conn.inode;
            
            // Verify process_info handling (returns () if None, ProcessInfo if Some)
            let proc = first_conn.process_info;
            if proc != () {
                // If process_info exists, we should be able to access its fields
                let pid = proc.pid;
                let process_name = proc.process_name;
            }
            
            // Verify we can access unix socket fields
            let first_socket = stats.unix_sockets[0];
            let protocol = first_socket.protocol;
            let count = first_socket.ref_count;
            let state = first_socket.state;
            let inode = first_socket.inode;
            let path = first_socket.path;
            
            // Verify process_info handling for unix sockets
            let proc = first_socket.process_info;
            if proc != () {
                // If process_info exists, we should be able to access its fields
                let pid = proc.pid;
                let process_name = proc.process_name;
            }
        "#,
    );

    assert!(result.is_ok(), "network_stats() should succeed");
}

/// Given: A Linux system with network connections including a manually created test socket
/// When: network_stats.to_map is called
/// Then: the map has the correct values compared to the expected value
#[test]
#[cfg(target_os = "linux")]
fn test_network_stats_to_map() -> Result<(), Box<EvalAltResult>> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let test_local_addr = listener.local_addr().unwrap();

    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();
    scope.push_constant("test_port", test_local_addr.port() as i64);

    let result = engine.eval_with_scope::<Map>(
        &mut scope,
        r#"
            let stats = network_stats();
            let stats_map = stats.to_map();

            // First validate that all internal structs have a to_map method and that it's consistent with the network_stats map
            let conn_map = stats.internet_connections[0].to_map();
            let process_info_map = ();
            if stats.internet_connections[0].process_info != () {
                process_info_map = stats.internet_connections[0].process_info.to_map();
            }
            let unix_socket_map = stats.unix_sockets[0].to_map();

            if conn_map != stats_map["internet_connections"][0] {
                throw "conn_map != stats_map[\"internet_connections\"][0]";
            }

            if process_info_map != stats_map["internet_connections"][0]["process_info"] {
                throw "process_info_map != stats_map[\"internet_connections\"][0][\"process_info\"]";
            }

            if unix_socket_map != stats_map["unix_sockets"][0] {
                throw "unix_socket_map != stats_map[\"unix_sockets\"][0]";
            }

            // Next compare the whole internet connections map against the expected value
            let expected = #{
                "internet_connections": stats.internet_connections.map(|conn| {
                    let process_info = ();
                    if conn.process_info != () {
                        process_info = #{
                            "pid": conn.process_info.pid,
                            "process_name": conn.process_info.process_name,
                        };
                    }

                    return #{
                        "protocol": conn.protocol.to_string(),
                        "recv_queue": conn.recv_queue,
                        "send_queue": conn.send_queue,
                        "local_address": conn.local_address.to_string(),
                        "remote_address": conn.remote_address.to_string(),
                        "state": conn.state.to_string(),
                        "inode": conn.inode,
                        "process_info": process_info
                    };
                }),
                "unix_sockets": stats.unix_sockets.map(|sock| {
                    let process_info = ();
                    if sock.process_info != () {
                        process_info = #{
                            "pid": sock.process_info.pid,
                            "process_name": sock.process_info.process_name,
                        };
                    }

                    return #{
                        "protocol": sock.protocol.to_string(),
                        "ref_count": sock.ref_count,
                        "state": sock.state.to_string(),
                        "inode": sock.inode,
                        "path": sock.path,
                        "process_info": process_info
                    };
                })
            };

            #{
                "expected": expected.to_json(),
                "actual": stats_map.to_json()
            }
        "#,
    )?;

    let expected: String = result.get("expected").unwrap().clone().into_string()?;
    let actual: String = result.get("actual").unwrap().clone().into_string()?;
    assert_eq!(expected, actual);

    Ok(())
}

/// Given: A Cedar policy that forbids access to /proc/
/// When: network_stats is called
/// Then: Cedar auth check fails and an error is returned
#[test]
#[cfg(target_os = "linux")]
fn test_network_stats_unauthorized() {
    let principal = get_test_rex_principal();
    let deny_policy = format!(
        r#"
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"/proc/"
        );"#,
        FilesystemAction::Read
    );

    let engine = create_test_engine_and_register_with_policy(&deny_policy);
    let result = engine.eval::<()>(
        r#"
            network_stats();
        "#,
    );

    assert!(
        result.is_err(),
        "Unauthorized user should not be able to get network stats"
    );

    let expected_error = format!("Permission denied: {principal} unauthorized to perform");
    assert_error_contains(result, &expected_error);
}
