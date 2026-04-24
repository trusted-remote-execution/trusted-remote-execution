#![cfg(target_os = "linux")]

use rex_test_utils::rhai::common::{create_test_engine_and_register, deny_all_engine};
use rhai::Dynamic;

// ── basic usage ─────────────────────────────────────────────────────────────

/// Given: A valid URL
/// When: Using curl(url)
/// Then: A Response struct with status and text properties is returned
#[test]
#[ignore] // Requires network access, not available in all build environments
fn test_curl_basic() {
    let engine = create_test_engine_and_register();
    let script = r#"
        let response = curl("https://example.com");
        let result = #{};
        result["status"] = response.status;
        result["text"] = response.text;
        result
    "#;
    let result = engine.eval::<rhai::Map>(script).unwrap();
    let status = result.get("status").unwrap().clone_cast::<i64>();
    assert!(status > 0);
    assert!(
        !result
            .get("text")
            .unwrap()
            .clone_cast::<String>()
            .is_empty()
    );
}

// ── error cases ─────────────────────────────────────────────────────────────

/// Given: An invalid URL
/// When: Using curl
/// Then: An error is returned
#[test]
fn test_curl_invalid_url() {
    let engine = create_test_engine_and_register();
    let result = engine.eval::<Dynamic>(r#"curl("not-a-url")"#);
    assert!(result.is_err());
}

/// Given: A deny-all Cedar policy
/// When: Using curl
/// Then: An authorization error is returned
#[test]
fn test_curl_unauthorized() {
    let engine = deny_all_engine();
    let result = engine.eval::<Dynamic>(r#"curl("https://example.com")"#);
    assert!(result.is_err());
}

// ── registry completeness ───────────────────────────────────────────────────

/// Given: The Response struct with all its fields serialized via serde
/// When: Comparing serde field names against registered Rhai getters
/// Then: Every serialized field has a corresponding Rhai property getter
#[test]
#[ignore] // Requires network access
fn test_curl_response_registry_completeness() {
    use rex_test_utils::rhai::safe_io::assert_rhai_getters_match_serde_fields;
    use rust_network::Response;

    let engine = create_test_engine_and_register();
    let resp: Response = engine.eval(r#"curl("https://example.com")"#).unwrap();
    let json = serde_json::to_value(&resp).unwrap();

    assert_rhai_getters_match_serde_fields(
        &engine,
        r#"curl("https://example.com")"#,
        &json,
        &[],
        "Response",
    );
}
