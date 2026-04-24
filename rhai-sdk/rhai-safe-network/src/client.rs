#![deny(missing_docs)]
#![allow(
    unused_variables,
    unreachable_code,
    clippy::unreachable,
    unused_mut,
    clippy::needless_pass_by_value,
    dead_code,
    clippy::unused_self,
    clippy::trivially_copy_pass_by_ref,
    clippy::return_self_not_must_use
)]
//! The functions used here are declared in the `RustNetwork` package.

use anyhow::Result;
use rhai::EvalAltResult;
use rust_network::Response;

/// HTTP client for making network requests.
///
/// Provides HTTP client functionality for making network requests.
#[derive(Clone, Debug, Copy, Default)]
#[doc(alias = "curl")]
pub struct Client;

/// An HTTP request that can be configured and sent.
///
/// Represents an HTTP request that can be sent.
#[derive(Clone, Debug, Copy, Default)]
pub struct Request;

impl Request {
    /// Sends the request and returns the response
    ///
    /// Current getters include status (HTTP status code) and text (HTML body).
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `network::Action::"GET"` | [`network::Network`](cedar_auth::network::entities::NetworkEntity) |
    ///
    /// NB: Resource is the request URL.
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::sysinfo::{create_temp_test_env, create_mock_http_server};
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let (_server, url) = create_mock_http_server();
    /// # scope.push_constant("url", url);
    /// # let result = engine.eval_with_scope::<()>(
    /// #     &mut scope,
    /// #     r#"
    /// let client = Client();
    /// let request = client.get(url);
    /// let response = request.send();
    /// print("Status: " + response.status);
    /// print("Text:  " + response.text);
    /// #     "#);
    /// #
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    pub fn send(&mut self) -> Result<Response, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }
}

impl Client {
    /// Creates a new [`rust_network::Client`] instance
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::sysinfo::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// #     &mut scope,
    /// #     r#"
    /// let client = Client();
    /// #     "#);
    /// #
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    pub fn new() -> Self {
        unreachable!("This method exists only for documentation.")
    }

    /// Creates a GET request for the specified URL
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::sysinfo::{create_temp_test_env, create_mock_http_server};
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let (_server, url) = create_mock_http_server();
    /// # scope.push_constant("url", url);
    /// # let result = engine.eval_with_scope::<()>(
    /// #     &mut scope,
    /// #     r#"
    /// let client = Client();
    /// let request = client.get(url);
    /// #     "#);
    /// #
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    pub fn get(&self, url: String) -> Request {
        unreachable!("This method exists only for documentation.")
    }

    /// Sets the maximum text size (in bytes) for response bodies
    ///
    /// When set, only the first N bytes will be read from the response body.
    /// The default is unbounded.
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::sysinfo::{create_temp_test_env, create_mock_http_server};
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let (_server, url) = create_mock_http_server();
    /// # scope.push_constant("url", url);
    /// # let result = engine.eval_with_scope::<()>(
    /// #     &mut scope,
    /// #     r#"
    /// let client = Client();
    /// client.max_text_bytes(1024); // Limit response to 1KB
    /// let request = client.get(url);
    /// let response = request.send();
    /// #     "#);
    /// #
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    pub fn max_text_bytes(&mut self, size: u64) -> Self {
        unreachable!("This method exists only for documentation.")
    }
}
