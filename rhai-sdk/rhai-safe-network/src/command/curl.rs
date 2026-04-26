//! `curl` — HTTP GET request
//!
//! # Example (Rhai)
//! ```rhai
//! let response = curl("https://example.com");
//! print(`Status: ${response.status}`);
//! print(response.text);
//! ```

use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::Dynamic;

/// Performs an HTTP GET request and returns a `Response` struct.
#[cfg(target_os = "linux")]
pub(crate) fn curl(url: &str, cedar_auth: &CedarAuth) -> Result<Dynamic, String> {
    use rust_safe_network::client::Client;

    let mut client = Client::new();
    let mut request = client.get(url.to_string());
    let response = request.send(cedar_auth).map_err(|e| e.to_string())?;

    Ok(Dynamic::from(response))
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn curl(_url: &str, _cedar_auth: &CedarAuth) -> Result<Dynamic, String> {
    Err("curl is only supported on Linux".to_string())
}
