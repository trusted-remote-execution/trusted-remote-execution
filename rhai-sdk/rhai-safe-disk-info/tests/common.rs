use rex_test_utils::rhai::common::{
    create_test_cedar_auth_with_policy, create_test_engine_with_auth,
};

pub fn create_test_engine_and_register_with_policy(policy: &str) -> rhai::Engine {
    let cedar_auth = create_test_cedar_auth_with_policy(policy);
    create_test_engine_with_auth(cedar_auth)
}
