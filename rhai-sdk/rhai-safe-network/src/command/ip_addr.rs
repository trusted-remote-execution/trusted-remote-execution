//! `ip_addr` — List network interfaces and IP addresses
//!
//! # Example (Rhai)
//! ```rhai
//! let interfaces = ip_addr();
//! for iface in interfaces {
//!     print(`${iface.interface_name}: ${iface.addresses}`);
//! }
//! ```

use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::Array;

/// Returns network interfaces and their IP addresses as `Network` structs.
#[cfg(target_os = "linux")]
pub(crate) fn ip_addr(cedar_auth: &CedarAuth) -> Result<Array, String> {
    use rhai::Dynamic;

    let networks =
        rust_safe_network::network::ip_addresses(cedar_auth).map_err(|e| e.to_string())?;

    Ok(networks.into_iter().map(Dynamic::from).collect())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn ip_addr(_cedar_auth: &CedarAuth) -> Result<Array, String> {
    Err("ip_addr is only supported on Linux".to_string())
}
