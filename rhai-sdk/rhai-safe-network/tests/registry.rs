use rex_test_utils::rhai::common::create_test_engine_and_register;
use rhai::{EvalAltResult, Scope};

/// Given: A new Rhai engine is created
/// When: Safe network functions are registered
/// Then: All expected safe network functions are available in the engine
#[test]
fn test_network_function_registration() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    // Test Client creation
    assert!(
        engine
            .eval_with_scope::<()>(&mut scope, r#"let client = Client();"#)
            .is_ok(),
        "Client() constructor is not properly registered"
    );

    // Test Client::get method
    assert!(
        engine
            .eval_with_scope::<()>(
                &mut scope,
                r#"
                    let client = Client();
                    let request = client.get("https://www.example.com");
                "#
            )
            .is_ok(),
        "Client::get() is not properly registered"
    );

    // Test NetworkErrorKind constants
    assert!(
        engine
            .eval_with_scope::<()>(
                &mut scope,
                r#"
                    let kind = NetworkErrorKind::PermissionDenied;
                    let kind2 = NetworkErrorKind::AuthorizationError;
                    let kind3 = NetworkErrorKind::RequestError;
                    let kind4 = NetworkErrorKind::Other;
                "#
            )
            .is_ok(),
        "NetworkErrorKind constants are not properly registered"
    );

    // Test NetworkErrorKind equality
    let result = engine.eval_with_scope::<bool>(
        &mut scope,
        r#"
                    let a = NetworkErrorKind::PermissionDenied;
                    let b = NetworkErrorKind::PermissionDenied;
                    a == b
                "#,
    );
    assert!(
        result.is_ok() && result.unwrap(),
        "NetworkErrorKind equality is not properly registered"
    );

    // Test NetworkErrorKind to_string
    let result = engine.eval_with_scope::<String>(
        &mut scope,
        r#"
                    let kind = NetworkErrorKind::RequestError;
                    kind.to_string()
                "#,
    );
    assert!(
        result.is_ok() && result.unwrap() == "RequestError",
        "NetworkErrorKind::to_string() is not properly registered"
    );

    Ok(())
}
