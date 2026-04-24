use assert_fs::TempDir;
use assert_fs::prelude::*;
use core::fmt::{Debug, Display};
use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
use rhai::{Dynamic, Engine, EvalAltResult, Position};
use rhai_sdk_common_utils::errors::RhaiCommonUtilsErrorKind;
use std::rc::Rc;

/// Extracts a readable error message from a Rhai `EvalAltResult`
pub fn extract_error_message(err: &EvalAltResult) -> String {
    match err {
        EvalAltResult::ErrorRuntime(obj, _) => obj.clone().try_cast::<rhai::Map>().map_or_else(
            || err.to_string(),
            |map| {
                map.get("message")
                    .map_or_else(|| err.to_string(), ToString::to_string)
            },
        ),
        _ => err.to_string(),
    }
}

/// Extracts the `RhaiCommonUtilsErrorKind` from a Rhai `EvalAltResult`
fn extract_rhai_common_utils_error_kind(error: &EvalAltResult) -> Option<RhaiCommonUtilsErrorKind> {
    if let EvalAltResult::ErrorRuntime(error_obj, _) = error
        && let Some(error_map) = error_obj.clone().try_cast::<rhai::Map>()
        && let Some(kind) = error_map.get("kind")
    {
        return kind.clone().try_cast::<RhaiCommonUtilsErrorKind>();
    }
    None
}

/// Creates a test instance of [`CedarAuth`] with default test schema and policy.
///
/// # Panics
///
/// Will panic if [`CedarAuth`] initialization fails
pub fn create_default_test_cedar_auth() -> CedarAuth {
    let test_schema = &get_default_test_rex_schema();
    let test_policy = &get_default_test_rex_policy();
    let test_entities = "[]";

    let (test_cedar_auth, _) = CedarAuth::new(test_policy, test_schema, test_entities)
        .expect("Failed to initialize CedarAuth for tests");
    test_cedar_auth
}

/// Creates a test instance of [`CedarAuth`] with default test schema and custom policy.
///
/// # Panics
///
/// Will panic if [`CedarAuth`] initialization fails
pub fn create_test_cedar_auth_with_policy(policy: &str) -> CedarAuth {
    let test_schema = &get_default_test_rex_schema();
    let test_entities = "[]";

    let (test_cedar_auth, _) = CedarAuth::new(policy, test_schema, test_entities)
        .expect("Failed to initialize CedarAuth for tests");
    test_cedar_auth
}

/// Return the current user and group names.
///
/// # Panics
/// * if `whoami` or `id -gn` commands fail
/// * if the output of the commands is not valid UTF-8
#[cfg(unix)]
pub fn get_current_user_and_group() -> (String, String) {
    use std::process::Command;

    let output = Command::new("whoami").output().unwrap().stdout;
    let user = String::from_utf8(output).unwrap().trim().to_string();

    let output = Command::new("id").arg("-gn").output().unwrap().stdout;
    let group = String::from_utf8(output).unwrap().trim().to_string();
    (user, group)
}

#[allow(clippy::needless_pass_by_value)]
pub fn to_eval_error(e: impl ToString) -> Box<EvalAltResult> {
    Box::new(EvalAltResult::ErrorRuntime(
        Dynamic::from(e.to_string()),
        Position::NONE,
    ))
}

/// Asserts that an error result contains a specific `RhaiCommonUtilsErrorKind`
///
/// # Panics
///
/// Panics if:
/// * The result does not contain an error
/// * The error doesn't contain a valid `RhaiCommonUtilsErrorKind` structure
/// * The actual error kind doesn't match the expected error kind
pub fn assert_error_kind(
    result: Result<(), Box<EvalAltResult>>,
    expected_kind: &RhaiCommonUtilsErrorKind,
) {
    assert!(result.is_err(), "Expected error but operation succeeded");

    let error = result.unwrap_err();
    let actual_kind = extract_rhai_common_utils_error_kind(&error)
        .expect("Failed to extract RhaiCommonUtilsErrorKind from EvalAltResult");

    assert_eq!(
        actual_kind,
        expected_kind.clone(),
        "Expected error kind {expected_kind}, but got {actual_kind}"
    );
}

/// Assertion helper that finds similar function names in Rhai to give more
/// detail on registration errors.
///
/// # Panics
///
/// Will panic if assertion fails to fail test.
pub fn assert_with_registration_details<T: Debug, E: Display + Debug>(
    result: &Result<T, E>,
    test: impl Fn() -> bool,
    engine: &Engine,
    signature: &str,
) {
    if test() {
        return;
    }

    for func in engine.gen_fn_signatures(false) {
        if func.contains(signature) {
            println!("registered funcs similar to '{signature}': {func}");
        }
    }

    assert!(test(), "{result:?}");
}

/// Creates and configures a Rhai engine with all registered functions for testing.
/// Registers common utils, safe IO, process management, and sysinfo functions
/// using the default test Cedar auth.
///
/// # Returns
/// A configured Rhai [`Engine`] with all functions registered and default cedar auth
pub fn create_test_engine_and_register() -> Engine {
    create_test_engine_with_auth(create_default_test_cedar_auth())
}

/// Creates and configures a Rhai engine with all registered functions for testing,
/// using a custom [`CedarAuth`].
///
/// # Returns
/// A configured Rhai [`Engine`] with all functions registered and custom cedar auth
pub fn create_test_engine_with_auth(cedar_auth: CedarAuth) -> Engine {
    let mut engine = Engine::new();
    engine.set_strict_variables(true);
    let cedar_auth = Rc::new(cedar_auth);

    rhai_sdk_common_utils::register(&mut engine);
    rhai_safe_io::register_safe_io_functions(&mut engine, &cedar_auth, None);
    #[cfg(target_os = "linux")]
    rhai_safe_process_mgmt::register_safe_process_functions(&mut engine, &cedar_auth, None);
    rhai_safe_disk_info::register(&mut engine, &cedar_auth);
    rhai_safe_system_info::register(&mut engine, &cedar_auth, None);
    rhai_safe_network::register(&mut engine, &cedar_auth);

    engine
}

/// Creates a Rhai engine configured with a deny-all Cedar policy.
///
/// # Returns
/// A configured Rhai [`Engine`] where all Cedar-authorized operations are denied
pub fn deny_all_engine() -> Engine {
    let auth = create_test_cedar_auth_with_policy("forbid (principal, action, resource);");
    create_test_engine_with_auth(auth)
}

/// Creates a temporary file with the given content and returns the temp directory
/// handle and the canonicalized file path.
///
/// # Returns
/// A tuple of ([`TempDir`], [`String`]) — the temp dir (must be kept alive) and the file path
///
/// # Panics
/// Will panic if file creation or path canonicalization fails
pub fn create_test_file(content: &str) -> (TempDir, String) {
    let temp = TempDir::new().unwrap();
    temp.child("test.txt").write_str(content).unwrap();
    let path = std::fs::canonicalize(temp.path().join("test.txt"))
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    (temp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Given: A runtime error with a non-Map object
    /// When: Extracting error message
    /// Then: Should return the default error string representation
    #[test]
    fn test_extract_error_message_runtime_error_non_map() {
        let non_map_obj = Dynamic::from("not a map");
        let err = EvalAltResult::ErrorRuntime(non_map_obj, Position::NONE);

        let result = extract_error_message(&err);
        assert_eq!(result, err.to_string());
    }

    /// Given: A runtime error with a Map object that has no "message" key
    /// When: Extracting error message
    /// Then: Should return the default error string representation
    #[test]
    fn test_extract_error_message_runtime_error_map_no_message() {
        let mut map = rhai::Map::new();
        map.insert("kind".into(), Dynamic::from("some_error_kind"));

        let map_obj = Dynamic::from(map);
        let err = EvalAltResult::ErrorRuntime(map_obj, Position::NONE);

        let result = extract_error_message(&err);
        assert_eq!(result, err.to_string());
    }
}
