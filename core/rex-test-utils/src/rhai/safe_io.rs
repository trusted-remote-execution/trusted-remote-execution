use super::common::{create_test_engine_and_register, to_eval_error};
use crate::io::create_temp_dir_and_path;
use assert_fs::prelude::*;
use flate2::Compression;
use flate2::write::GzEncoder;
use rhai::{Dynamic, Engine, EvalAltResult, Scope};
use rhai_safe_io::errors::RhaiSafeIoErrorKind;
use std::io::Write;

#[cfg(unix)]
use std::os::unix::fs::symlink;

/// Creates a test environment with a configured Rhai engine and scope.
///
/// # Returns
/// A tuple containing:
/// - A Rhai [`Scope`] with the temp directory path as a constant called `temp_dir_path`
/// - A configured Rhai `Engine` with all registered functions
///
/// # Panics
///
/// Will panic if unable to create the temporary directory
pub fn create_temp_test_env() -> (Scope<'static>, Engine) {
    let engine = create_test_engine_and_register();
    let (_temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error).unwrap();
    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    (scope.clone(), engine)
}

/// Creates a test environment with pre-created gzip fixture files for testing
/// gzip-related operations.
///
/// # Panics
///
/// Will panic if unable to create the temporary directory or fixture files
pub fn create_temp_test_env_with_gzip_fixtures() -> (Scope<'static>, Engine, assert_fs::TempDir) {
    let engine = create_test_engine_and_register();
    let temp_dir = assert_fs::TempDir::new().unwrap();
    let temp_dir_path: String = std::fs::canonicalize(temp_dir.path())
        .unwrap()
        .to_string_lossy()
        .into();

    // Create sample log content with various log levels for search testing
    let log_content = "2024-01-01 10:00:00 INFO Application started successfully
2024-01-01 10:00:01 DEBUG Loading configuration from /etc/app/config.yaml
2024-01-01 10:00:02 INFO Connected to database server
2024-01-01 10:00:03 WARNING High memory usage detected: 85%
2024-01-01 10:00:04 ERROR Failed to process request: timeout
2024-01-01 10:00:05 INFO Request processed successfully
2024-01-01 10:00:06 DEBUG Cache hit ratio: 0.75
2024-01-01 10:00:07 WARNING Disk space running low
2024-01-01 10:00:08 INFO User authentication successful
2024-01-01 10:00:09 ERROR Connection refused to external service
2024-01-01 10:00:10 DEBUG Memory allocation: 512MB
2024-01-01 10:00:11 INFO Scheduled task completed
2024-01-01 10:00:12 WARNING Rate limit approaching
2024-01-01 10:00:13 ERROR Invalid input received
2024-01-01 10:00:14 INFO Service health check passed
2024-01-01 10:00:15 DEBUG Thread pool size: 8
2024-01-01 10:00:16 CRITICAL_ERROR System failure detected
2024-01-01 10:00:17 INFO Recovery process initiated
2024-01-01 10:00:18 DEBUG Garbage collection completed
2024-01-01 10:00:19 INFO Application running normally
";

    temp_dir.child("data.log").write_str(log_content).unwrap();

    let gz_path = format!("{temp_dir_path}/file.log.gz");
    let file = std::fs::File::create(&gz_path).unwrap();
    let mut encoder = GzEncoder::new(file, Compression::default());
    encoder.write_all(log_content.as_bytes()).unwrap();
    encoder.finish().unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    (scope.clone(), engine, temp_dir)
}

/// Creates a test environment with pre-created certificate fixture files for testing
/// certificate verification operations.
///
/// # Panics
///
/// Will panic if unable to create the temporary directory or fixture files
pub fn create_temp_test_env_with_cert_fixtures() -> (Scope<'static>, Engine, assert_fs::TempDir) {
    const ROOT_CA_PEM: &str = include_str!("../../fixtures/crypto/root-ca.pem");
    const INTERMEDIATE_CA_PEM: &str = include_str!("../../fixtures/crypto/intermediate-ca.pem");
    const SERVER_PEM: &str = include_str!("../../fixtures/crypto/server.pem");
    const SERVER_DIRECT_PEM: &str = include_str!("../../fixtures/crypto/server-direct.pem");
    const SELF_SIGNED_SERVER_PEM: &str =
        include_str!("../../fixtures/crypto/self-signed-server.pem");

    let engine = create_test_engine_and_register();
    let temp_dir = assert_fs::TempDir::new().unwrap();
    let temp_dir_path: String = std::fs::canonicalize(temp_dir.path())
        .unwrap()
        .to_string_lossy()
        .into();

    temp_dir
        .child("root-ca.pem")
        .write_str(ROOT_CA_PEM)
        .unwrap();
    temp_dir
        .child("intermediate-ca.pem")
        .write_str(INTERMEDIATE_CA_PEM)
        .unwrap();
    temp_dir.child("server.pem").write_str(SERVER_PEM).unwrap();
    temp_dir
        .child("server-direct.pem")
        .write_str(SERVER_DIRECT_PEM)
        .unwrap();
    temp_dir
        .child("self-signed-server.pem")
        .write_str(SELF_SIGNED_SERVER_PEM)
        .unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    (scope.clone(), engine, temp_dir)
}

/// Creates a test environment with a pre-created symlink for testing
/// symlink-related operations like `set_ownership`.
///
/// # Panics
///
/// Will panic if unable to create the temporary directory, target file, or symlink
#[cfg(unix)]
pub fn create_temp_test_env_with_symlink() -> (Scope<'static>, Engine, assert_fs::TempDir, String) {
    let engine = create_test_engine_and_register();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error).unwrap();

    let target_file = "target_file.txt";
    temp_dir
        .child(target_file)
        .write_str("test content")
        .unwrap();

    let symlink_name = "test_symlink";
    let symlink_path = temp_dir.path().join(symlink_name);
    let target_path = temp_dir.path().join(target_file);

    symlink(target_path, symlink_path).unwrap();

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    (scope.clone(), engine, temp_dir, symlink_name.to_string())
}

/// Extracts the `RhaiSafeIoErrorKind` from a Rhai `EvalAltResult`
fn extract_rhai_safe_io_error_kind(error: &EvalAltResult) -> Option<RhaiSafeIoErrorKind> {
    if let EvalAltResult::ErrorRuntime(error_obj, _) = error
        && let Some(error_map) = error_obj.clone().try_cast::<rhai::Map>()
        && let Some(kind) = error_map.get("kind")
    {
        return kind.clone().try_cast::<RhaiSafeIoErrorKind>();
    }
    None
}

/// Asserts that an error result contains a specific `RhaiSafeIoErrorKind`
///
/// # Panics
///
/// Panics if:
/// * The result does not contain an error
/// * The error doesn't contain a valid `RhaiSafeIoErrorKind` structure
/// * The actual error kind doesn't match the expected error kind
pub fn assert_error_kind(
    result: &Result<(), Box<EvalAltResult>>,
    expected_kind: &RhaiSafeIoErrorKind,
) {
    assert!(result.is_err(), "Expected error but operation succeeded");

    let error = result.as_ref().unwrap_err();
    let actual_kind = extract_rhai_safe_io_error_kind(error)
        .expect("Failed to extract RhaiSafeIoErrorKind from EvalAltResult");

    assert_eq!(
        actual_kind,
        expected_kind.clone(),
        "Expected error kind {expected_kind}, but got {actual_kind}"
    );
}

#[cfg(test)]
mod tests {
    use crate::rhai::common::{
        create_test_cedar_auth_with_policy, create_test_engine_with_auth, extract_error_message,
    };
    use rex_cedar_auth::test_utils::get_test_rex_principal;
    use rhai::{Dynamic, EvalAltResult, Position};

    use super::*;

    /// Given: A Rhai engine with functions registered and a temp dir created
    /// When: A script is run to create a file
    /// Then: The file is successfully with no errors
    #[test]
    fn test_registration_and_script_exec() -> Result<(), Box<EvalAltResult>> {
        let (mut scope, engine) = create_temp_test_env();
        let result = engine.eval_with_scope::<()>(
            &mut scope,
            r#"
                    let dir_config = DirConfig()
                        .path(temp_dir_path)
                        .build();
                    let dir_handle = dir_config.open(OpenDirOptions().create(true).recursive(true).build());
                    let file = dir_handle.open_file("test.txt", OpenFileOptions().create(true).build());
                    dir_handle.delete(DeleteDirOptions().recursive(true).build());
            "#,
        );

        assert!(
            result.is_ok(),
            "test registration failed with error: {:?}",
            result.unwrap_err()
        );
        Ok(())
    }

    /// Given: A Rhai engine with functions registered and custom policy
    /// When: A script is run
    /// Then: The script returns successfully
    #[test]
    fn test_registration_with_custom_policy() -> Result<(), Box<EvalAltResult>> {
        let principal = get_test_rex_principal();
        let custom_policy = format!(
            r#"permit(
            principal == User::"{principal}",
            action in [
                file_system::Action::"read",
                file_system::Action::"open"
            ],
            resource
        );"#
        );
        let auth = create_test_cedar_auth_with_policy(&custom_policy);
        let engine = create_test_engine_with_auth(auth);
        assert_eq!(engine.eval::<i64>("40 + 2")?, 42);
        Ok(())
    }

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
}

/// Verifies that every field in a serialized Rust struct has a corresponding
/// Rhai property getter registered in the engine.
///
/// Serializes the struct to JSON, extracts field names, applies any serde→Rhai
/// renames, then probes each field via `obj.field` in a Rhai script.
/// Fails with an explicit list of missing fields if any getter is unregistered.
///
/// # Arguments
/// * `engine` - The Rhai engine with registered types
/// * `obj_expr` - Rhai expression that produces the object (e.g. `"df()[0]"`)
/// * `json_value` - The `serde_json::Value` from serializing the same struct
/// * `serde_to_rhai_renames` - Pairs of `(serde_key, rhai_getter_name)` for
///   fields where `#[serde(rename)]` differs from the Rust field name
/// * `type_name` - Human-readable struct name for error messages
/// # Panics
/// Panics if `json_value` is not a JSON object or if any serde field is missing a Rhai getter.
#[allow(clippy::expect_used)]
pub fn assert_rhai_getters_match_serde_fields(
    engine: &Engine,
    obj_expr: &str,
    json_value: &serde_json::Value,
    serde_to_rhai_renames: &[(&str, &str)],
    type_name: &str,
) {
    let obj = json_value.as_object().expect("expected JSON object");

    let mut missing_fields = Vec::new();

    for serde_key in obj.keys() {
        let rhai_field = serde_to_rhai_renames
            .iter()
            .find(|(sk, _)| sk == serde_key)
            .map_or(serde_key.as_str(), |(_, rk)| rk);

        let script = format!("let obj = {obj_expr}; obj.{rhai_field}");
        if engine.eval::<Dynamic>(&script).is_err() {
            missing_fields.push(format!("{rhai_field} (serde key: {serde_key})"));
        }
    }

    assert!(
        missing_fields.is_empty(),
        "{type_name} registry mismatch — fields in struct but missing Rhai getters: {missing_fields:?}"
    );
}
