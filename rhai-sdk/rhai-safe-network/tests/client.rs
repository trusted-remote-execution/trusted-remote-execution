use httpmock::prelude::{GET, MockServer};
use rex_test_utils::rhai::common::create_test_engine_and_register;

mod common;
use common::create_test_engine_and_register_with_policy;
use rhai::{EvalAltResult, Map, Scope};

/// Given: A mock HTTP server is running
/// When: A GET request is made to the mock server URL
/// Then: The response status code is returned successfully
#[test]
fn test_client_send_success() -> Result<(), Box<EvalAltResult>> {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(GET).path("/test");
        then.status(200).body("Hello, World!");
    });

    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    let url = format!("{}/test", server.base_url());
    let script = format!(
        r#"
            let client = Client().max_text_bytes(4);
            let request = client.get("{url}");
            let response = request.send();

            if !response.text.contains("Hell") {{
                let err_str = "expected: '" + response.text + "' to match'Hello, World!'";
                throw "html does not match expected" + err_str
            }}
            response.status
        "#
    );

    let result = engine.eval_with_scope::<u16>(&mut scope, &script)?;

    assert_eq!(result, 200, "Expected status code 200");
    mock.assert();

    Ok(())
}

/// Given: A valid request and response
/// When: to_map function is called
/// Then: the return value matches the expected
#[test]
fn test_request_response_to_map() -> Result<(), Box<EvalAltResult>> {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(GET).path("/test");
        then.status(200).body("Hello, World!");
    });

    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    let url = format!("{}/test", server.base_url());
    scope.push("url", url);

    // first validate the request to_map function
    let script = r#"
        let client = Client().max_text_bytes(4);
        let request = client.get(url);
        
        let expected = #{
            "max_text_size": request.max_text_size,
            "url": request.url,
            "method": request.method.to_string()
        };

        #{
            "expected": expected.to_json(),
            "actual": request.to_map().to_json()
        }
    "#;

    let result = engine.eval_with_scope::<Map>(&mut scope, &script)?;

    let expected: String = result.get("expected").unwrap().clone().into_string()?;
    let actual: String = result.get("actual").unwrap().clone().into_string()?;
    assert_eq!(expected, actual);

    // then validate the response to_map function
    let script = r#"
        let response = request.send();
        let expected = #{
            "status": response.status.to_int(),
            "text": response.text,
        };

        #{
            "expected": expected.to_json(),
            "actual": response.to_map().to_json()
        }
    "#;

    let result = engine.eval_with_scope::<Map>(&mut scope, &script)?;

    let expected: String = result.get("expected").unwrap().clone().into_string()?;
    let actual: String = result.get("actual").unwrap().clone().into_string()?;
    assert_eq!(expected, actual);

    mock.assert();

    Ok(())
}

/// Given: A Cedar policy that denies network GET operations
/// When: Attempting to send a GET request
/// Then: The operation fails with a PermissionDenied error
#[test]
fn test_client_send_permission_denied() {
    let principal = rex_cedar_auth::test_utils::get_test_rex_principal();
    let deny_policy = format!(
        r#"
        forbid(
            principal == User::"{principal}",
            action == network::Action::"GET",
            resource
        );"#
    );
    let engine = create_test_engine_and_register_with_policy(&deny_policy);

    let result = engine.eval::<()>(
        r#"
        let client = Client();
        let request = client.get("https://example.com");
        let response = request.send();
        "#,
    );

    assert!(result.is_err(), "Expected an error but got success");
    let error_msg = result.unwrap_err().to_string();
    let expected_error = format!("Permission denied: {principal} unauthorized to perform");
    assert!(
        error_msg.contains(&expected_error) || error_msg.contains("Permission denied"),
        "Error message should contain permission denied, got: {error_msg}"
    );
}
