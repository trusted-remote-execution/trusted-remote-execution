//! `netstat` — Network connection statistics (Linux only)
//!
//! # Example (Rhai)
//! ```rhai
//! let stats = netstat();
//! for conn in stats.internet {
//!     print(`${conn.protocol} ${conn.local_address} -> ${conn.remote_address} ${conn.state}`);
//! }
//! ```

use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::Map;
#[cfg(target_os = "linux")]
use rhai::{Array, Dynamic};

/// Returns network statistics as a map with internet and unix keys (Linux only).
#[cfg(target_os = "linux")]
#[allow(clippy::cast_possible_wrap)]
pub(crate) fn netstat(cedar_auth: &CedarAuth) -> Result<Map, String> {
    let stats = rust_safe_network::netstat::network_stats(cedar_auth).map_err(|e| e.to_string())?;

    let internet: Array = stats
        .internet_connections()
        .iter()
        .map(|conn| {
            let mut m = Map::new();
            m.insert(
                "protocol".into(),
                Dynamic::from(format!("{:?}", conn.protocol())),
            );
            m.insert(
                "local_address".into(),
                Dynamic::from(conn.local_address().to_string()),
            );
            m.insert(
                "remote_address".into(),
                Dynamic::from(conn.remote_address().to_string()),
            );
            m.insert("state".into(), Dynamic::from(format!("{:?}", conn.state())));
            m.insert(
                "recv_queue".into(),
                Dynamic::from(i64::from(*conn.recv_queue())),
            );
            m.insert(
                "send_queue".into(),
                Dynamic::from(i64::from(*conn.send_queue())),
            );
            Dynamic::from(m)
        })
        .collect();

    let unix: Array = stats
        .unix_sockets()
        .iter()
        .map(|sock| {
            let mut m = Map::new();
            m.insert(
                "protocol".into(),
                Dynamic::from(format!("{:?}", sock.protocol())),
            );
            m.insert("state".into(), Dynamic::from(format!("{:?}", sock.state())));
            m.insert("path".into(), Dynamic::from(sock.path().clone()));
            m.insert(
                "ref_count".into(),
                Dynamic::from(i64::from(*sock.ref_count())),
            );
            Dynamic::from(m)
        })
        .collect();

    let mut result = Map::new();
    result.insert("internet".into(), Dynamic::from(internet));
    result.insert("unix".into(), Dynamic::from(unix));
    Ok(result)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn netstat(_cedar_auth: &CedarAuth) -> Result<Map, String> {
    Err("netstat is only supported on Linux".to_string())
}
