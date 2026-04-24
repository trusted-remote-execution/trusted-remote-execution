use super::common::{create_test_engine_and_register, to_eval_error};
use crate::io::create_temp_dir_and_path;
use httpmock::Method::GET;
use httpmock::prelude::MockServer;
use rhai::Scope;

pub fn create_mock_http_server() -> (MockServer, String) {
    let server = MockServer::start();

    server.mock(|when, then| {
        when.method(GET).path("/test");
        then.status(200).body("Hello, World!");
    });

    let url = server.url("/test");
    (server, url)
}

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
pub fn create_temp_test_env() -> (Scope<'static>, rhai::Engine) {
    let engine = create_test_engine_and_register();
    let (_temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error).unwrap();
    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    (scope.clone(), engine)
}

#[cfg(test)]
mod tests {
    use crate::rhai::common::{create_test_cedar_auth_with_policy, create_test_engine_with_auth};
    use reqwest::blocking::get;
    use rex_cedar_auth::fs::actions::FilesystemAction;
    use rex_cedar_auth::test_utils::get_test_rex_principal;
    use rhai::EvalAltResult;

    use super::*;

    /// Given: A Rhai engine with sysinfo functions registered
    /// When: A script is run to get filesystem information
    /// Then: The filesystems are retrieved successfully with no errors
    #[test]
    #[cfg(target_os = "linux")]
    fn test_registration_and_script_exec() -> Result<(), Box<EvalAltResult>> {
        let (mut scope, engine) = create_temp_test_env();
        let result = engine.eval_with_scope::<()>(
            &mut scope,
            r#"
                let options = FilesystemOptions().build();
                let fs_handle = Filesystems(options);
                let filesystems = fs_handle.filesystems();
            "#,
        );

        assert!(
            result.is_ok(),
            "test registration failed with error: {:?}",
            result.unwrap_err()
        );
        Ok(())
    }

    /// Given: A Rhai engine with sysinfo functions registered and custom policy
    /// When: A script is run to get filesystem information
    /// Then: The script returns successfully
    #[test]
    #[cfg(target_os = "linux")]
    fn test_registration_with_custom_policy() -> Result<(), Box<EvalAltResult>> {
        let principal = get_test_rex_principal();
        let custom_policy = format!(
            r#"
                permit(
                    principal == User::"{principal}",
                    action == {},
                    resource == file_system::File::"/proc/mounts"
                );
                permit(
                    principal == User::"{principal}",
                    action == {},
                    resource == file_system::File::"/proc/diskstats"
                );
                permit(
                    principal == User::"{principal}",
                    action == {},
                    resource
                );
            "#,
            FilesystemAction::Read.to_string(),
            FilesystemAction::Read.to_string(),
            FilesystemAction::Stat.to_string(),
        );

        let auth = create_test_cedar_auth_with_policy(&custom_policy);
        let engine = create_test_engine_with_auth(auth);

        let result = engine.eval::<()>(
            r#"
                let options = FilesystemOptions().build();
                let fs_handle = Filesystems(options);
                let filesystems = fs_handle.filesystems();
            "#,
        );

        assert!(
            result.is_ok(),
            "Failed with error: {:?}",
            result.unwrap_err()
        );
        Ok(())
    }

    /// Given: A mock HTTP server
    /// When: A GET request is made to /test
    /// Then: The server responds with 200 and "Hello, World!"
    #[test]
    fn test_create_mock_http_server() {
        let (_server, url) = create_mock_http_server();

        let response = get(&url).expect("Failed to make request");

        assert_eq!(response.status(), 200);
        assert_eq!(response.text().unwrap(), "Hello, World!");
    }
}
