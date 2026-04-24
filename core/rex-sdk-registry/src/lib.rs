//! Centralized SDK registration for Rex

use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_runner_registrar_utils::execution_context::ExecutionContext;
use rhai::Engine;
use std::rc::Rc;

pub fn register_sdk_functions(
    engine: &mut Engine,
    cedar_auth: &Rc<CedarAuth>,
    execution_context: Option<&ExecutionContext>,
) {
    rhai_safe_io::register_safe_io_functions(engine, cedar_auth, execution_context);
    rhai_safe_system_info::register(engine, cedar_auth, execution_context);
    rhai_safe_disk_info::register(engine, cedar_auth);
    rhai_safe_network::register(engine, cedar_auth);
    rhai_sdk_common_utils::register(engine);

    #[cfg(target_os = "linux")]
    rhai_safe_process_mgmt::register_safe_process_functions(engine, cedar_auth, execution_context);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};

    /// Given: Valid engine and cedar auth
    /// When: Calling register_sdk_functions
    /// Then: Function completes without engine error
    #[test]
    fn test_register_sdk_functions() {
        let mut engine = Engine::new();
        let (cedar_auth, _) = CedarAuth::new(
            &get_default_test_rex_policy(),
            &get_default_test_rex_schema(),
            "[]",
        )
        .unwrap();
        let cedar_auth = Rc::new(cedar_auth);

        register_sdk_functions(&mut engine, &cedar_auth, None);

        assert!(engine.eval::<i64>("1 + 1").is_ok());
    }
}
