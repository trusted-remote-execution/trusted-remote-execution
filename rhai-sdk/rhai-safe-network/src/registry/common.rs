use crate::netstat_types::{
    network_protocol_module, tcp_state_module, unix_protocol_module, unix_socket_state_module,
};
use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::network::actions::NetworkAction;
use rex_logger::{error, push_rhai_context_with_guard};
use rex_runner_registrar_utils::{
    register_direct_safe_fn, register_fn_with_auth, register_getter_with_guard,
    register_getters_with_guard, register_map_serializers, register_with_guard,
};
use rhai::serde::to_dynamic;
use rhai::{Array, Dynamic, EvalAltResult};
use rust_safe_network::{
    Client, Connection, Network, Request, Response,
    netstat::{
        InternetConnection, NetworkProtocol, NetworkStats, ProcessInfo, TcpState, UnixProtocol,
        UnixSocket, UnixSocketState, network_stats,
    },
    network::{connect, ip_addresses},
};
use rust_safe_system_info::TransportProtocol;
use std::net::SocketAddr;
use std::rc::Rc;

use crate::errors::{ERROR_MODULE_NAME, RhaiNetworkErrorKind, convert_to_rhai_error};
use rhai::plugin::{
    Engine, FnNamespace, FuncRegistration, Module, NativeCallContext, PluginFunc, RhaiResult,
    TypeId, export_module, exported_module, mem,
};

#[allow(non_upper_case_globals)]
#[allow(unreachable_pub)]
#[allow(clippy::unwrap_used)]
#[export_module]
mod error_kind_module {
    use super::Module;

    pub const AuthorizationError: RhaiNetworkErrorKind = RhaiNetworkErrorKind::AuthorizationError;
    pub const PermissionDenied: RhaiNetworkErrorKind = RhaiNetworkErrorKind::PermissionDenied;
    pub const RequestError: RhaiNetworkErrorKind = RhaiNetworkErrorKind::RequestError;
    pub const Other: RhaiNetworkErrorKind = RhaiNetworkErrorKind::Other;

    #[rhai_fn(global, name = "==", pure)]
    pub fn eq(error_kind: &mut RhaiNetworkErrorKind, other: RhaiNetworkErrorKind) -> bool {
        error_kind == &other
    }

    #[rhai_fn(global, name = "!=", pure)]
    pub fn neq(error_kind: &mut RhaiNetworkErrorKind, other: RhaiNetworkErrorKind) -> bool {
        error_kind != &other
    }

    #[rhai_fn(global, name = "to_string")]
    pub fn to_string(kind: &mut RhaiNetworkErrorKind) -> String {
        kind.to_string()
    }
}

pub(crate) fn get_rhai_context_guard(context: &NativeCallContext) -> impl Drop {
    let line_number = context
        .call_position()
        .line()
        .map_or(0, |l| u32::try_from(l).unwrap_or(0));

    push_rhai_context_with_guard(Some(context.fn_name()), line_number)
}

/// Registers network functions with the Rhai engine.
#[allow(clippy::cast_possible_wrap)]
#[allow(clippy::cast_sign_loss)]
#[allow(clippy::too_many_lines)]
fn register_network_functions(engine: &mut Engine, cedar_auth: &Rc<CedarAuth>) {
    // Register error kinds
    engine
        .register_type_with_name::<RhaiNetworkErrorKind>("RhaiNetworkErrorKind")
        .register_static_module(
            ERROR_MODULE_NAME,
            exported_module!(error_kind_module).into(),
        );

    register_with_guard!(engine, "Client", Client, Client::new);
    register_with_guard!(engine, "max_text_bytes", Client, self, Client, Client::max_text_bytes, size: i64 => u64);
    register_with_guard!(engine, "get", Request, self, Client, Client::get, url: String);

    register_getters_with_guard!(engine, Request, [url, (max_text_size, Option<u64> => i64)]);
    register_getter_with_guard!(engine, Request, method, transform: |action| {
        match action {
            NetworkAction::Get => "Get",
            NetworkAction::Connect => "Connect",
            _ => {
                error!("Network action of type {action} is not supported");
                "Unknown"
            }
        }
    });
    register_getters_with_guard!(engine, Response, [status, text]);

    register_direct_safe_fn!(
        engine,
        "send",
        Request,
        send,
        cedar_auth,
        -> Response,
        convert_to_rhai_error;
        tests: { positive: "test_client_send_success", negative: "test_client_send_permission_denied" }
    );

    register_fn_with_auth!(
        engine,
        "connect",
        connect,
        cedar_auth,
        endpoint: &str,
        port: i64 => u16,
        protocol: TransportProtocol,
        -> Connection,
        convert_to_rhai_error;
        tests: { positive: "test_connect_success", negative: "test_connect_permission_denied" }
    );

    register_fn_with_auth!(
        engine,
        "ip_addresses",
        ip_addresses,
        cedar_auth,
        -> Array,
        transform: |entries: Vec<Network>| -> Result<Array, Box<EvalAltResult>> {
            Ok(entries.into_iter().map(Dynamic::from).collect())
        },
        rhai_safe_system_info::errors::convert_to_rhai_error;
        tests: { positive: "test_ip_addresses_success", negative: "test_ip_addresses_unauthorized" }
    );
    register_getters_with_guard!(engine, Network, [interface_name, (addresses, Vec<String> => Array)]);

    engine
        .register_type_with_name::<NetworkProtocol>("NetworkProtocol")
        .register_static_module(
            "NetworkProtocol",
            exported_module!(network_protocol_module).into(),
        );

    engine
        .register_type_with_name::<TcpState>("TcpState")
        .register_static_module("TcpState", exported_module!(tcp_state_module).into());

    engine
        .register_type_with_name::<UnixProtocol>("UnixProtocol")
        .register_static_module(
            "UnixProtocol",
            exported_module!(unix_protocol_module).into(),
        );

    engine
        .register_type_with_name::<UnixSocketState>("UnixSocketState")
        .register_static_module(
            "UnixSocketState",
            exported_module!(unix_socket_state_module).into(),
        );

    register_getters_with_guard!(engine, NetworkStats, [
        (internet_connections, Vec<InternetConnection> => Array),
        (unix_sockets, Vec<UnixSocket> => Array)
    ]);

    register_getters_with_guard!(
        engine,
        InternetConnection,
        [
            protocol,
            (recv_queue, u32 => i64),
            (send_queue, u32 => i64),
            local_address,
            remote_address,
            state,
            (inode, u64 => i64),
        ]
    );

    register_getters_with_guard!(
        engine,
        UnixSocket,
        [protocol, (ref_count, u32 => i64), state, (inode, u64 => i64), path]
    );

    engine.register_type_with_name::<SocketAddr>("SocketAddr");
    engine.register_fn("to_string", |addr: &mut SocketAddr| -> String {
        addr.to_string()
    });

    engine.register_type_with_name::<ProcessInfo>("ProcessInfo");
    register_getters_with_guard!(engine, ProcessInfo, [(pid, u32 => i64), process_name]);

    engine.register_get("process_info", |conn: &mut InternetConnection| -> Dynamic {
        match &conn.process_info {
            Some(info) => Dynamic::from(info.clone()),
            None => Dynamic::UNIT,
        }
    });

    engine.register_get("process_info", |socket: &mut UnixSocket| -> Dynamic {
        match &socket.process_info {
            Some(info) => Dynamic::from(info.clone()),
            None => Dynamic::UNIT,
        }
    });

    register_fn_with_auth!(
        engine,
        "network_stats",
        network_stats,
        cedar_auth,
        -> NetworkStats,
        convert_to_rhai_error;
        tests: { positive: "test_network_stats_success", negative: "test_network_stats_unauthorized" }
    );

    register_serializer_fns(engine);
}

fn register_serializer_fns(engine: &mut Engine) {
    register_map_serializers!(
        engine,
        [
            Request,
            Response,
            Network,
            NetworkStats,
            InternetConnection,
            UnixSocket,
            ProcessInfo
        ]
    );
}

/// Registers network functions with the Rhai engine for use in scripts.
pub(super) fn register(engine: &mut Engine, cedar_auth: &Rc<CedarAuth>) {
    register_network_functions(engine, cedar_auth);
}

#[cfg(test)]
mod tests {
    use super::{
        InternetConnection, NetworkProtocol, ProcessInfo, SocketAddr, TcpState, UnixProtocol,
        UnixSocket, UnixSocketState,
    };
    use rex_test_utils::rhai::common::create_test_engine_and_register;
    use rhai::Scope;
    use rstest::rstest;

    /// Given: Two identical RhaiNetworkErrorKind values
    /// When: Comparing them for equality in the Rhai engine
    /// Then: They should be equal
    #[test]
    fn test_error_kind_equality_same_type() {
        let engine = create_test_engine_and_register();
        let result = engine
            .eval::<bool>(
                r#"
                     let a = NetworkErrorKind::PermissionDenied;
                     let b = NetworkErrorKind::PermissionDenied;
                     a == b
                 "#,
            )
            .unwrap();
        assert!(result);
    }

    /// Given: Two identical RhaiNetworkErrorKind values
    /// When: Comparing them for inequality in the Rhai engine
    /// Then: They should not be unequal
    #[test]
    fn test_error_kind_inequality_same_type() {
        let engine = create_test_engine_and_register();
        let result = engine
            .eval::<bool>(
                r#"
                     let a = NetworkErrorKind::PermissionDenied;
                     let b = NetworkErrorKind::PermissionDenied;
                     a != b
                 "#,
            )
            .unwrap();
        assert!(!result);
    }

    /// Given: Two different RhaiNetworkErrorKind values
    /// When: Comparing them for inequality in the Rhai engine
    /// Then: They should be unequal
    #[test]
    fn test_error_kind_inequality_different_types() {
        let engine = create_test_engine_and_register();
        let result = engine
            .eval::<bool>(
                r#"
                     let a = NetworkErrorKind::PermissionDenied;
                     let b = NetworkErrorKind::RequestError;
                     a != b
                 "#,
            )
            .unwrap();
        assert!(result);
    }

    /// Given: Two different RhaiNetworkErrorKind values
    /// When: Comparing them for equality in the Rhai engine
    /// Then: They should not be equal
    #[test]
    fn test_error_kind_equality_different_types() {
        let engine = create_test_engine_and_register();
        let result = engine
            .eval::<bool>(
                r#"
                     let a = NetworkErrorKind::PermissionDenied;
                     let b = NetworkErrorKind::RequestError;
                     a == b
                 "#,
            )
            .unwrap();
        assert!(!result);
    }

    /// Given: A RhaiNetworkErrorKind value
    /// When: Converting it to a string in the Rhai engine
    /// Then: It should return the correct string representation
    #[test]
    fn test_error_kind_to_string() {
        let engine = create_test_engine_and_register();

        let result = engine
            .eval::<String>(
                r#"
                     let kind = NetworkErrorKind::RequestError;
                     kind.to_string()
                     "#,
            )
            .unwrap();

        assert_eq!(result, "RequestError");
    }

    /// Given: Two NetworkProtocol values and an operation
    /// When: Performing the operation in the Rhai engine
    /// Then: Should return the expected result
    #[rstest]
    #[case("TCP", "TCP", "==", true)]
    #[case("TCP", "UDP", "==", false)]
    #[case("TCP", "TCP", "!=", false)]
    #[case("TCP", "UDP", "!=", true)]
    fn test_network_protocol_operations(
        #[case] variant_a: &str,
        #[case] variant_b: &str,
        #[case] operation: &str,
        #[case] expected: bool,
    ) {
        let engine = create_test_engine_and_register();
        let script = format!(
            r#"
            let a = NetworkProtocol::{};
            let b = NetworkProtocol::{};
            a {} b
        "#,
            variant_a, variant_b, operation
        );

        let result = engine.eval::<bool>(&script).unwrap();
        assert_eq!(result, expected);
    }

    /// Given: A NetworkProtocol value
    /// When: Calling the to_string() method in the Rhai engine
    /// Then: Should return the expected string
    #[test]
    fn test_network_protocol_string() {
        let engine = create_test_engine_and_register();
        let result = engine
            .eval::<String>(
                r#"
                let protocol = NetworkProtocol::TCP;
                protocol.to_string()
            "#,
            )
            .unwrap();
        assert_eq!(result, "Tcp");
    }

    /// Given: Two TcpState values and an operation
    /// When: Performing the operation in the Rhai engine
    /// Then: Should return the expected result
    #[rstest]
    #[case("ESTABLISHED", "ESTABLISHED", "==", true)]
    #[case("ESTABLISHED", "LISTEN", "==", false)]
    #[case("ESTABLISHED", "ESTABLISHED", "!=", false)]
    #[case("ESTABLISHED", "LISTEN", "!=", true)]
    fn test_tcp_state_operations(
        #[case] variant_a: &str,
        #[case] variant_b: &str,
        #[case] operation: &str,
        #[case] expected: bool,
    ) {
        let engine = create_test_engine_and_register();
        let script = format!(
            r#"
            let a = TcpState::{};
            let b = TcpState::{};
            a {} b
        "#,
            variant_a, variant_b, operation
        );

        let result = engine.eval::<bool>(&script).unwrap();
        assert_eq!(result, expected);
    }

    /// Given: A TcpState value
    /// When: Calling the to_string() method in the Rhai engine
    /// Then: Should return the expected string
    #[test]
    fn test_tcp_state_to_string() {
        let engine = create_test_engine_and_register();
        let result = engine
            .eval::<String>(
                r#"
                let state = TcpState::ESTABLISHED;
                state.to_string()
            "#,
            )
            .unwrap();
        assert_eq!(result, "Established");
    }

    /// Given: Two UnixProtocol values and an operation
    /// When: Performing the operation in the Rhai engine
    /// Then: Should return the expected result
    #[rstest]
    #[case("STREAM", "STREAM", "==", true)]
    #[case("STREAM", "DGRAM", "==", false)]
    #[case("STREAM", "STREAM", "!=", false)]
    #[case("STREAM", "DGRAM", "!=", true)]
    fn test_unix_protocol_operations(
        #[case] variant_a: &str,
        #[case] variant_b: &str,
        #[case] operation: &str,
        #[case] expected: bool,
    ) {
        let engine = create_test_engine_and_register();
        let script = format!(
            r#"
            let a = UnixProtocol::{};
            let b = UnixProtocol::{};
            a {} b
        "#,
            variant_a, variant_b, operation
        );

        let result = engine.eval::<bool>(&script).unwrap();
        assert_eq!(result, expected);
    }

    /// Given: A UnixProtocol value
    /// When: Calling the to_string() method in the Rhai engine
    /// Then: Should return the expected string
    #[test]
    fn test_unix_protocol_to_string() {
        let engine = create_test_engine_and_register();
        let result = engine
            .eval::<String>(
                r#"
                let protocol = UnixProtocol::STREAM;
                protocol.to_string()
            "#,
            )
            .unwrap();
        assert_eq!(result, "Stream");
    }

    /// Given: Two UnixSocketState values and an operation
    /// When: Performing the operation in the Rhai engine
    /// Then: Should return the expected result
    #[rstest]
    #[case("CONNECTED", "CONNECTED", "==", true)]
    #[case("CONNECTED", "UNCONNECTED", "==", false)]
    #[case("CONNECTED", "CONNECTED", "!=", false)]
    #[case("CONNECTED", "UNCONNECTED", "!=", true)]
    fn test_unix_socket_state_operations(
        #[case] variant_a: &str,
        #[case] variant_b: &str,
        #[case] operation: &str,
        #[case] expected: bool,
    ) {
        let engine = create_test_engine_and_register();
        let script = format!(
            r#"
            let a = UnixSocketState::{};
            let b = UnixSocketState::{};
            a {} b
        "#,
            variant_a, variant_b, operation
        );

        let result = engine.eval::<bool>(&script).unwrap();
        assert_eq!(result, expected);
    }

    /// Given: A UnixSocketState value
    /// When: Calling the to_string() method in the Rhai engine
    /// Then: Should return the expected string
    #[test]
    fn test_unix_socket_state_to_string() {
        let engine = create_test_engine_and_register();
        let result = engine
            .eval::<String>(
                r#"
                let state = UnixSocketState::CONNECTED;
                state.to_string()
            "#,
            )
            .unwrap();
        assert_eq!(result, "Connected");
    }

    /// Given: A SocketAddr value
    /// When: Calling to_string() in Rhai
    /// Then: Should return a valid string representation
    #[test]
    fn test_socket_addr_to_string() {
        let engine = create_test_engine_and_register();
        let mut scope = Scope::new();

        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        scope.push("addr", addr);

        let result = engine.eval_with_scope::<String>(&mut scope, r#"addr.to_string()"#);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "127.0.0.1:8080");
    }

    /// Given: InternetConnections with and without process_info
    /// When: Accessing process_info getter
    /// Then: Should return ProcessInfo when Some, () when None
    #[test]
    fn test_internet_connection_process_info() {
        let engine = create_test_engine_and_register();
        let mut scope = Scope::new();

        let conn_with_proc = InternetConnection::new(
            NetworkProtocol::Tcp,
            0,
            0,
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap(),
            "127.0.0.1:9090".parse::<SocketAddr>().unwrap(),
            TcpState::Established,
            12345,
            Some(ProcessInfo {
                pid: 1234,
                process_name: "test_process".to_string(),
            }),
        );

        let conn_without_proc = InternetConnection::new(
            NetworkProtocol::Udp,
            0,
            0,
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap(),
            "0.0.0.0:0".parse::<SocketAddr>().unwrap(),
            TcpState::None,
            12346,
            None,
        );

        scope.push("conn_with_proc", conn_with_proc);
        scope.push("conn_without_proc", conn_without_proc);

        let result = engine.eval_with_scope::<()>(
            &mut scope,
            r#"
            // Test Some case
            let proc = conn_with_proc.process_info;
            if proc == () {
                throw "Expected process_info to be Some";
            }
            if proc.pid != 1234 {
                throw "Expected pid to be 1234";
            }
            if proc.process_name != "test_process" {
                throw "Expected process_name to be test_process";
            }
            
            // Test None case
            if conn_without_proc.process_info != () {
                throw "Expected process_info to be None";
            }
        "#,
        );

        assert!(
            result.is_ok(),
            "Should handle both Some and None process_info: {:?}",
            result
        );
    }

    /// Given: UnixSockets with and without process_info
    /// When: Accessing process_info getter
    /// Then: Should return ProcessInfo when Some, () when None
    #[test]
    fn test_unix_socket_process_info() {
        let engine = create_test_engine_and_register();
        let mut scope = Scope::new();

        let socket_with_proc = UnixSocket::new(
            UnixProtocol::Stream,
            2,
            UnixSocketState::Connected,
            54321,
            "/tmp/test.sock".to_string(),
            Some(ProcessInfo {
                pid: 5678,
                process_name: "socket_process".to_string(),
            }),
        );

        let socket_without_proc = UnixSocket::new(
            UnixProtocol::Dgram,
            1,
            UnixSocketState::Unconnected,
            54322,
            "".to_string(),
            None,
        );

        scope.push("socket_with_proc", socket_with_proc);
        scope.push("socket_without_proc", socket_without_proc);

        let result = engine.eval_with_scope::<()>(
            &mut scope,
            r#"
            // Test Some case
            let proc = socket_with_proc.process_info;
            if proc == () {
                throw "Expected process_info to be Some";
            }
            if proc.pid != 5678 {
                throw "Expected pid to be 5678";
            }
            if proc.process_name != "socket_process" {
                throw "Expected process_name to be socket_process";
            }
            
            // Test None case
            if socket_without_proc.process_info != () {
                throw "Expected process_info to be None";
            }
        "#,
        );

        assert!(
            result.is_ok(),
            "Should handle both Some and None process_info: {:?}",
            result
        );
    }
}
