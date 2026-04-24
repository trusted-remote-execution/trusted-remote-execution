//! HTTP client with Cedar policy authorization
//!
//! This module provides a blocking HTTP client that integrates with Cedar authorization
//! to enforce access control policies on network requests. All requests are validated
//! against Cedar policies before being sent.

use std::io::Read;
use std::rc::Rc;

use crate::RustNetworkError;
use crate::auth::is_authorized_url;
use derive_getters::Getters;
use reqwest::blocking::Client as ReqwestClient;
use reqwest::blocking::RequestBuilder;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::network::actions::NetworkAction;
use serde::Serialize;

/// HTTP client for making Cedar-authorized network requests
///
/// This client wraps reqwest's blocking client and integrates with Cedar
/// authorization to validate requests against policies before sending them.
///
/// # Example
///
/// ```no_run
/// use rust_network::client::Client;
///
/// let mut client = Client::new();
/// let request = client.get("https://api.example.com".to_string());
/// ```
#[derive(Debug, Clone)]
pub struct Client {
    client: ReqwestClient,
    max_text_bytes: Option<u64>,
}

/// A wrapper type to get around the orphan rule for serialization.
/// I don't think it makes sense to add serialization directly to the `CedarAuth` version so we use this workaround.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
#[serde(remote = "rex_cedar_auth::network::actions::NetworkAction")]
enum NetworkActionSer {
    Connect,
    Get,
}

/// Wrapper for an HTTP request with authorization metadata
#[derive(Debug, Clone, Getters, Serialize)]
pub struct Request {
    #[serde(skip_serializing)]
    #[getter(skip)]
    builder: Rc<RequestBuilder>,
    url: String,
    #[serde(with = "NetworkActionSer")]
    method: NetworkAction,
    max_text_size: Option<u64>,
}

/// HTTP response containing the response body and status
#[derive(Debug, Clone, Getters, Serialize)]
pub struct Response {
    text: String,
    status: u16,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    /// Creates a new HTTP client instance
    ///
    /// This uses the [`ReqwestClient`] defaults including a
    /// 30 second timeout.
    /// <https://docs.rs/reqwest/latest/reqwest/blocking/struct.ClientBuilder.html#method.timeout>
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_network::client::Client;
    ///
    /// let client = Client::new();
    /// ```
    pub fn new() -> Client {
        Client {
            client: ReqwestClient::new(),
            max_text_bytes: None,
        }
    }

    /// Sets the maximum text size (in bytes) for response bodies
    ///
    /// When set, only the first N bytes will be read from the response body.
    /// The default, if not set, is `None` (unbounded).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_network::client::Client;
    ///
    /// let client = Client::new().max_text_bytes(1024); // Max 1KB response
    /// ```
    #[must_use]
    pub fn max_text_bytes(&mut self, size: u64) -> Self {
        Client {
            client: self.client.clone(),
            max_text_bytes: Some(size),
        }
    }

    /// Builds a GET request for the specified URL
    pub fn get(&mut self, url: String) -> Request {
        Request {
            builder: Rc::new(self.client.get(url.clone())),
            url,
            method: NetworkAction::Get,
            max_text_size: self.max_text_bytes,
        }
    }
}

impl Request {
    /// Sends a request after validating it against Cedar authorization policies
    #[allow(clippy::needless_pass_by_value)]
    pub fn send(&mut self, cedar_auth: &CedarAuth) -> Result<Response, RustNetworkError> {
        is_authorized_url(cedar_auth, self.method, &self.url)?;

        let req_builder = self
            .builder
            .try_clone()
            .ok_or_else(|| RustNetworkError::Other(anyhow::anyhow!("failed to clone request")))?;

        let resp = req_builder
            .send()
            .map_err(|e| RustNetworkError::RequestError {
                reason: e.to_string(),
                kind: e,
            })?;

        let status = resp.status().as_u16();

        let text = match self.max_text_size {
            Some(limit) => {
                let capacity = usize::try_from(limit)
                    .map_err(|_| RustNetworkError::BufferSizeError { size: limit })?;
                let mut buffer = Vec::with_capacity(capacity);
                resp.take(limit).read_to_end(&mut buffer).map_err(|e| {
                    RustNetworkError::TruncateError {
                        reason: e.to_string(),
                    }
                })?;
                String::from_utf8_lossy(&buffer).into_owned()
            }
            None => resp.text().map_err(|e| RustNetworkError::RequestError {
                reason: e.to_string(),
                kind: e,
            })?,
        };

        Ok(Response { text, status })
    }
}

#[cfg(test)]
mod tests {
    use crate::client::Client;
    use httpmock::prelude::{GET, MockServer};
    use rex_cedar_auth::cedar_auth::CedarAuth;
    use rex_cedar_auth::network::actions::NetworkAction;
    use rex_cedar_auth::test_utils::TestCedarAuthBuilder;
    use rex_cedar_auth::test_utils::get_test_rex_principal;
    use rex_test_utils::assertions::assert_error_contains;

    struct TestSetup {
        server: MockServer,
        principal: String,
        url: String,
        base_url: String,
    }

    fn setup() -> TestSetup {
        let server = MockServer::start();
        let principal = get_test_rex_principal();
        let base_url = server.base_url();
        let url = format!("{}/test", base_url);
        TestSetup {
            server,
            principal,
            url,
            base_url,
        }
    }

    fn create_mock(server: &MockServer) -> httpmock::Mock<'_> {
        server.mock(|when, then| {
            when.method(GET).path("/test");
            then.status(200).body("Hello, World!");
        })
    }

    fn create_cedar_auth(policy: String) -> CedarAuth {
        TestCedarAuthBuilder::default()
            .policy(policy)
            .build()
            .unwrap()
            .create()
    }

    /// Given: A Cedar policy permits a specific URL exactly.
    /// When: A GET request is made to that exact URL.
    /// Then: The request succeeds with 200 status and response body.
    #[test]
    fn test_authorized_request_exact_url_match() {
        let setup = setup();
        let mock = create_mock(&setup.server);

        let policy = format!(
            r#"
            permit(
                principal == User::"{}",
                action == {},
                resource == network::url::"{}"
            );"#,
            setup.principal,
            NetworkAction::Get.to_string(),
            setup.url
        );
        let cedar_auth = create_cedar_auth(policy);

        let mut client = Client::new();
        let mut request = client.get(setup.url);
        let response = request.send(&cedar_auth).unwrap();

        assert_eq!(*response.status(), 200);
        assert_eq!(response.text(), "Hello, World!");
        mock.assert();
    }

    /// Given: A Cedar policy permits URLs matching a glob pattern.
    /// When: A GET request is made to a URL matching the pattern.
    /// Then: The request succeeds with 200 status and response body.
    #[test]
    fn test_authorized_request_glob_pattern() {
        let setup = setup();
        let mock = create_mock(&setup.server);

        let policy = format!(
            r#"
            permit(
                principal == User::"{}",
                action == {},
                resource
            )
            when {{
                resource.url like "*{}*"
            }};
            "#,
            setup.principal,
            NetworkAction::Get.to_string(),
            setup.base_url
        );
        let cedar_auth = create_cedar_auth(policy);

        let mut client = Client::new();
        let mut request = client.get(setup.url);
        let response = request.send(&cedar_auth).unwrap();

        assert_eq!(*response.status(), 200);
        assert_eq!(response.text(), "Hello, World!");
        mock.assert();
    }

    /// Given: A Cedar policy only permits a different URL (www.example.com/shop).
    /// When: A GET request is made to an unpermitted URL.
    /// Then: Authorization fails with an unauthorized error.
    #[test]
    fn test_unauthorized_url() {
        let setup = setup();
        let mock = create_mock(&setup.server);

        let policy = format!(
            r#"
            permit(
                principal == User::"{}",
                action == {},
                resource == network::url::"www.example.com/shop"
            );"#,
            setup.principal,
            NetworkAction::Get.to_string(),
        );
        let cedar_auth = create_cedar_auth(policy);

        let mut client = Client::new();
        let result = client.get(setup.url.clone()).send(&cedar_auth);

        assert!(
            result.is_err(),
            "Expected path '{}' to be unauthorized, but it was authorized",
            setup.url
        );
        assert_error_contains(result, "unauthorized to perform network::Action::\"GET\"");
        mock.assert_calls(0);
    }

    /// Given: A Cedar policy permits a URL and client has max_text_size set.
    /// When: A GET request is made and response body exceeds max_text_size.
    /// Then: The response text is truncated to max_text_size bytes.
    #[test]
    fn test_max_text_size_truncates_response() {
        let setup = setup();
        let _mock = setup.server.mock(|when, then| {
            when.method(GET).path("/test");
            then.status(200).body("Hello, World!"); // 13 bytes
        });

        let policy = format!(
            r#"
            permit(
                principal == User::"{}",
                action == {},
                resource == network::url::"{}"
            );"#,
            setup.principal,
            NetworkAction::Get.to_string(),
            setup.url
        );
        let cedar_auth = create_cedar_auth(policy);

        let mut client = Client::new().max_text_bytes(5); // Limit to 5 bytes
        let mut request = client.get(setup.url);
        let response = request.send(&cedar_auth).unwrap();

        assert_eq!(*response.status(), 200);
        assert_eq!(response.text(), "Hello"); // Only first 5 bytes
    }

    /// Given: A Cedar policy permits a URL and client has max_text_size larger than response.
    /// When: A GET request is made and response body is smaller than max_text_size.
    /// Then: The full response text is returned.
    #[test]
    fn test_max_text_size_larger_than_response() {
        let setup = setup();
        let _mock = setup.server.mock(|when, then| {
            when.method(GET).path("/test");
            then.status(200).body("Hello"); // 5 bytes
        });

        let policy = format!(
            r#"
            permit(
                principal == User::"{}",
                action == {},
                resource == network::url::"{}"
            );"#,
            setup.principal,
            NetworkAction::Get.to_string(),
            setup.url
        );
        let cedar_auth = create_cedar_auth(policy);

        let mut client = Client::new().max_text_bytes(100); // Limit larger than response
        let mut request = client.get(setup.url);
        let response = request.send(&cedar_auth).unwrap();

        assert_eq!(*response.status(), 200);
        assert_eq!(response.text(), "Hello"); // Full response
    }

    /// Given: A Cedar policy permits a non-existent URL.
    /// When: A GET request is sent to the non-existent URL.
    /// Then: The request fails with a network error.
    #[test]
    fn test_send_fails() {
        let setup = setup();
        let mock = create_mock(&setup.server);
        let url = "https://www.does-not-exist.com";

        let policy = format!(
            r#"
            permit(
                principal == User::"{}",
                action == {},
                resource == network::url::"{}"
            );"#,
            setup.principal,
            NetworkAction::Get.to_string(),
            url
        );
        let cedar_auth = create_cedar_auth(policy);

        let mut client = Client::new();
        let result = client.get(url.to_string()).send(&cedar_auth);

        assert_error_contains(result, "error sending request for url");
        mock.assert_calls(0);
    }
}
