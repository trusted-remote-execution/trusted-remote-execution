use super::common::create_test_engine_and_register;
use rhai::Scope;

/// Creates a test environment with a configured Rhai engine and scope.
///
/// # Returns
/// A tuple containing:
/// - A Rhai [`Scope`] for registering variables to the engine
/// - A configured Rhai `Engine` with all registered functions
pub fn create_test_env() -> (Scope<'static>, rhai::Engine) {
    let engine = create_test_engine_and_register();
    let scope = Scope::new();
    (scope.clone(), engine)
}

#[cfg(test)]
mod tests {
    use crate::rhai::common::{
        create_test_cedar_auth_with_policy, create_test_engine_and_register,
        create_test_engine_with_auth,
    };
    use rex_cedar_auth::process::actions::ProcessAction;
    use rex_cedar_auth::test_utils::get_test_rex_principal;
    use rhai::{EvalAltResult, Scope};

    use super::*;

    /// Given: A Rhai engine with functions registered using default cedar auth
    /// When: A script is run to create a process manager
    /// Then: The script executes successfully with no errors
    #[test]
    fn test_default_auth_and_engine_registration() -> Result<(), Box<EvalAltResult>> {
        let engine = create_test_engine_and_register();

        assert_eq!(engine.eval::<i64>("40 + 2")?, 42);

        let (_, engine2) = create_test_env();
        assert_eq!(engine2.eval::<i64>("40 + 2")?, 42);

        Ok(())
    }

    /// Given: A Rhai engine with functions registered and a custom policy that allows process listing
    /// When: A script is run to get processes
    /// Then: The script executes successfully with no errors
    #[test]
    #[cfg(target_os = "linux")]
    fn test_registration_and_script_exec() -> Result<(), Box<EvalAltResult>> {
        let principal = get_test_rex_principal();
        let custom_policy = format!(
            r#"
            permit(
                principal == User::"{principal}",
                action == {},
                resource
            );
            "#,
            ProcessAction::List
        );
        let auth = create_test_cedar_auth_with_policy(&custom_policy);
        let engine = create_test_engine_with_auth(auth);

        let mut scope = Scope::new();
        let result = engine.eval_with_scope::<()>(
            &mut scope,
            r#"
                let process_manager = ProcessManager();
                let processes = process_manager.processes();
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
            r#"
            permit(
                principal == User::"{principal}",
                action == {},
                resource
            );
            "#,
            ProcessAction::List
        );
        let auth = create_test_cedar_auth_with_policy(&custom_policy);
        let engine = create_test_engine_with_auth(auth);
        assert_eq!(engine.eval::<i64>("40 + 2")?, 42);
        Ok(())
    }
}
