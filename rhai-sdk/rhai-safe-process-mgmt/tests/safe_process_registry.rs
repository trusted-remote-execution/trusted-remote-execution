#![cfg(target_os = "linux")]
use rex_test_utils::rhai::common::create_test_engine_and_register;
use rhai::{EvalAltResult, Scope};

/// Given: A new Rhai engine is created
/// When: Safe process management functions are registered
/// Then: All expected safe process management functions are available in the engine
#[test]
fn test_standard_process_operations() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    assert!(
        engine
            .eval_with_scope::<()>(
                &mut scope,
                r#"
                    let pm = ProcessManager();
                    let processes = pm.processes();
                "#,
            )
            .is_ok(),
        "processes function is not properly registered"
    );

    let current_pid = std::process::id();
    scope.push("current_pid", current_pid as i64);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
                let options = NamespaceOptions().pid(current_pid).mount(true).build();
                pm.nsenter(options, || { "test" });
            "#,
    );

    // nsenter should be registered and callable, but will fail due to capabilities
    // We expect a specific namespace operation error, not a registration error
    match result {
        Ok(_) => {
            assert!(
                false,
                "nsenter succeeded unexpectedly - test environment may have elevated privileges"
            );
        }
        Err(e) => {
            let error_msg = e.to_string();
            assert!(
                error_msg.contains("Namespace operation failed"),
                "nsenter function is not properly registered"
            );
        }
    }

    Ok(())
}

/// Given: A new Rhai engine is created
/// When: Safe process management functions are registered
/// Then: The ProcessManager and its processes_using_inode method are available in the engine
#[test]
fn test_processes_using_inode_operation() -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    assert!(
        engine
            .eval_with_scope::<()>(
                &mut scope,
                r#"
                    let process_manager = ProcessManager();
                    let processes = process_manager.processes_using_inode(".");
                "#,
            )
            .is_ok(),
        "ProcessManager and processes_using_inode method are not properly registered"
    );

    Ok(())
}

/// Given: A Rhai engine with SystemctlManager registered
/// When: Creating a SystemctlManager without CAP_SETUID capability
/// Then: Should fail with a privilege error
#[test]
fn test_systemctl_manager_creation() {
    let engine = create_test_engine_and_register();

    let result = engine.eval::<()>(
        r#"
        let manager = SystemctlManager();
        "#,
    );

    assert!(
        result.is_err(),
        "Expected SystemctlManager creation to fail without CAP_SETUID"
    );

    let error = result.unwrap_err();
    let error_msg = error.to_string();

    assert!(
        error_msg.contains("Failed to initialize systemd manager")
            || error_msg.contains("Privilege error"),
        "Error message should indicate privilege/initialization failure. Got: {}",
        error_msg
    );
}
