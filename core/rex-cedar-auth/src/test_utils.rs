//! Test utilities for creating `CedarAuth` instances in tests.
//!
//! This module is only available when the `test-utils` feature is enabled.
//!
//! # Example
//!
//! Add to your `Cargo.toml`:
//! ```toml
//! [dev-dependencies]
//! cedar-auth = { version = "0.1", features = ["test-utils"] }
//! ```

use std::sync::LazyLock;

use derive_builder::Builder;
use rex_policy_schema::get_rex_policy_schema;

use crate::cedar_auth::CedarAuth;

/// Returns the test principal for REX Cedar
///
/// This function returns the current username to be used as the principal in tests.
pub fn get_test_rex_principal() -> String {
    whoami::username()
}

/// Returns the REX Cedar policy for tests
///
/// This function returns a policy that allows basic file/directory operations.
pub fn get_default_test_rex_policy() -> String {
    let principal = get_test_rex_principal();
    format!(
        r#"permit(
        principal == User::"{principal}",
        action in [
            file_system::Action::"read",
            file_system::Action::"write",
            file_system::Action::"open",
            file_system::Action::"create",
            file_system::Action::"delete",
            file_system::Action::"stat",
            file_system::Action::"chmod",
            file_system::Action::"chown",
            file_system::Action::"move",
            file_system::Action::"execute",
            file_system::Action::"network_namespace"
        ],
        resource
    );

    permit (
        principal == User::"{principal}",
        action in
            [
                process_system::Action::"list",
                process_system::Action::"list_fds",
                process_system::Action::"kill",
                process_system::Action::"interrupt",
                process_system::Action::"mount_namespace",
                process_system::Action::"network_namespace",
                process_system::Action::"trace"
            ],
        resource
    );

    permit(
        principal == User::"{principal}",
        action in [
            sysinfo::Action::"list",
            sysinfo::Action::"resolve_hostname"
        ],
        resource
    );

    permit(
        principal == User::"{principal}",
        action in [
            network::Action::"GET",
            network::Action::"connect",
        ],
        resource
    ) when {{
            resource.url like "http*" ||
            resource.url like "127.0.0.1"
    }};
    "#
    )
}

//  this is a dupe in test-utils. We'll remove from test utils
/// after initial CR.
/// Returns the REX Cedar schema for tests
pub const fn get_default_test_rex_schema() -> &'static str {
    get_rex_policy_schema()
}

/// A builder for configuring `CedarAuth` in tests.
///
/// # Default Values
///
/// - **policy**: Uses [`get_default_test_rex_policy()`] which permits common file system,
///   process system, caps, and sysinfo actions for the current user
/// - **schema**: Uses [`get_default_test_rex_schema()`] which defines the REX policy schema
/// - **entities**: Empty JSON array `"[]"`
///
/// # Examples
///
/// ## Using all defaults
///
/// ```no_run
/// use rex_cedar_auth::test_utils::TestCedarAuthBuilder;
///
/// let cedar_auth = TestCedarAuthBuilder::default()
///     .build()
///     .expect("Failed to build TestCedarAuth")
///     .create();
/// ```
///
/// ## Using the pre-built static instance
///
/// For convenience, a pre-initialized static instance is available:
///
/// ```no_run
/// use rex_cedar_auth::test_utils::DEFAULT_TEST_CEDAR_AUTH;
///
/// // Access the pre-built CedarAuth instance
/// let cedar_auth = &*DEFAULT_TEST_CEDAR_AUTH;
/// ```
///
/// ## Customizing the policy
///
/// ```no_run
/// use rex_cedar_auth::test_utils::TestCedarAuthBuilder;
///
/// let custom_policy = r#"permit(principal, action, resource);"#.to_string();
/// let cedar_auth = TestCedarAuthBuilder::default()
///     .policy(custom_policy)
///     .build()
///     .expect("Failed to build TestCedarAuth")
///     .create();
/// ```
///
/// ## Customizing entities
///
/// ```no_run
/// use rex_cedar_auth::test_utils::TestCedarAuthBuilder;
///
/// let custom_entities = r#"[{"uid": "User::\"test\"", "attrs": {}, "parents": []}]"#.to_string();
/// let cedar_auth = TestCedarAuthBuilder::default()
///     .entities(custom_entities)
///     .build()
///     .expect("Failed to build TestCedarAuth")
///     .create();
/// ```
///
/// ## Fully custom configuration
///
/// ```no_run
/// use rex_cedar_auth::test_utils::{
///     TestCedarAuthBuilder, get_default_test_rex_schema
/// };
///
/// let cedar_auth = TestCedarAuthBuilder::default()
///     .policy(r#"permit(principal, action, resource);"#.to_string())
///     .schema(get_default_test_rex_schema().to_string())
///     .entities("[]".to_string())
///     .build()
///     .expect("Failed to build TestCedarAuth")
///     .create();
/// ```
#[derive(Builder, Debug, Clone)]
#[builder(derive(Debug))]
pub struct TestCedarAuth {
    #[builder(default = "get_default_test_rex_policy()")]
    policy: String,
    #[builder(default = "get_rex_policy_schema().to_string()")]
    schema: String,
    #[builder(default = "TestCedarAuth::DEFAULT_REX_ENTITIES.to_string()")]
    entities: String,
}

impl TestCedarAuth {
    const DEFAULT_REX_ENTITIES: &'static str = "[]";

    /// Creates a `CedarAuth` instance from the configured policy, schema, and entities.
    ///
    /// # Panics
    /// Panics if `CedarAuth::new` fails to initialize with the provided
    /// policy, schema, or entities.
    #[allow(clippy::expect_used)]
    pub fn create(self) -> CedarAuth {
        let (cedar_auth, _) = CedarAuth::new(&self.policy, &self.schema, &self.entities)
            .expect("Failed to initialize CedarAuth for tests");
        cedar_auth
    }
}

/// A pre-initialized `CedarAuth` instance with default test configuration.
///
/// This static instance is lazily initialized on first access and provides
/// a convenient way to get a `CedarAuth` for tests without manual setup.
///
/// # Example
///
/// ```no_run
/// use rex_cedar_auth::test_utils::DEFAULT_TEST_CEDAR_AUTH;
///
/// let cedar_auth = &*DEFAULT_TEST_CEDAR_AUTH;
/// ```
#[allow(clippy::expect_used)]
pub static DEFAULT_TEST_CEDAR_AUTH: LazyLock<CedarAuth> = LazyLock::new(|| {
    TestCedarAuthBuilder::default()
        .build()
        .expect("Failed to build TestCedarAuth with default values")
        .create()
});

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Helper function to create a custom policy for the current user with read-only permissions
    fn create_custom_read_only_policy() -> String {
        let principal = get_test_rex_principal();
        format!(
            r#"permit(
            principal == User::"{principal}",
            action in [
                file_system::Action::"read"
            ],
            resource
        );"#
        )
    }

    /// Given: A TestCedarAuthBuilder with various configurations
    /// When: The builder is built and create() is called
    /// Then: It should return a valid CedarAuth instance
    #[rstest]
    #[case::with_defaults(None, None, "default values")]
    #[case::with_custom_policy(Some(create_custom_read_only_policy()), None, "custom policy")]
    #[case::with_custom_entities(None, Some("[]".to_string()), "custom entities")]
    #[case::with_custom_policy_and_entities(Some(create_custom_read_only_policy()), Some("[]".to_string()), "custom policy and entities")]
    fn test_test_cedar_auth_builder_configurations(
        #[case] policy: Option<String>,
        #[case] entities: Option<String>,
        #[case] description: &str,
    ) {
        let mut builder = TestCedarAuthBuilder::default();

        if let Some(p) = policy {
            builder.policy(p);
        }
        if let Some(e) = entities {
            builder.entities(e);
        }

        let test_cedar_auth = builder.build();
        assert!(
            test_cedar_auth.is_ok(),
            "TestCedarAuthBuilder should build successfully with {description}"
        );

        let cedar_auth = test_cedar_auth
            .expect(&format!("Failed to build TestCedarAuth with {description}"))
            .create();

        // If we get here without panicking, the CedarAuth was created successfully
        drop(cedar_auth);
    }

    /// Given: The DEFAULT_TEST_CEDAR_AUTH static
    /// When: It is accessed
    /// Then: It should return a valid CedarAuth instance
    #[test]
    fn test_default_test_cedar_auth_static() {
        // Access the static CedarAuth instance
        let cedar_auth = &*DEFAULT_TEST_CEDAR_AUTH;

        // Verify it's accessible and valid by checking we can reference it
        // The LazyLock ensures this is initialized on first access
        assert!(
            std::mem::size_of_val(cedar_auth) > 0,
            "DEFAULT_TEST_CEDAR_AUTH should be a valid CedarAuth instance"
        );
    }

    /// Given: A TestCedarAuthBuilder
    /// When: Debug is derived on it
    /// Then: It should be debuggable
    #[test]
    fn test_test_cedar_auth_builder_debug() {
        let builder = TestCedarAuthBuilder::default();
        let debug_str = format!("{:?}", builder);

        assert!(
            !debug_str.is_empty(),
            "TestCedarAuthBuilder should have Debug implementation"
        );
    }

    /// Given: A TestCedarAuth instance
    /// When: It is cloned
    /// Then: The clone should be equal to the original
    #[test]
    fn test_test_cedar_auth_clone() {
        let test_cedar_auth = TestCedarAuthBuilder::default()
            .build()
            .expect("Failed to build TestCedarAuth");

        let cloned = test_cedar_auth.clone();
        let debug_original = format!("{:?}", test_cedar_auth);
        let debug_cloned = format!("{:?}", cloned);

        assert_eq!(
            debug_original, debug_cloned,
            "Cloned TestCedarAuth should be equal to original"
        );
    }

    /// Given: A function to get the test principal
    /// When: The function is called
    /// Then: It should return a non-empty string representing the current username
    #[test]
    fn test_get_test_rex_principal() {
        let principal = get_test_rex_principal();
        assert!(!principal.is_empty());
    }

    /// Given: A function to get the default test REX policy
    /// When: The function is called
    /// Then: It should return a valid policy with permit, principal, action, and resource
    #[test]
    fn test_get_default_test_rex_policy() {
        let policy = get_default_test_rex_policy();

        assert!(!policy.is_empty(), "Policy should not be empty");
        assert!(policy.starts_with("permit"), "Policy should have permit");
        assert!(policy.contains("principal"), "Policy should have principal");
        assert!(policy.contains("action"), "Policy should have action");
        assert!(policy.contains("resource"), "Policy should have resource");
    }

    /// Given: A function to get the default test REX schema
    /// When: The function is called
    /// Then: It should return a valid schema with User, File, Dir entities and actions
    #[test]
    fn test_get_default_test_rex_schema() {
        let schema = get_default_test_rex_schema();

        assert!(!schema.is_empty(), "Schema should not be empty");
        assert!(
            schema.contains("entity User"),
            "Schema should have a User entity"
        );
        assert!(
            schema.contains("entity File"),
            "Schema should have a File entity"
        );
        assert!(
            schema.contains("entity Dir"),
            "Schema should have a Directory entity"
        );
        assert!(schema.contains("action"), "Schema should have actions");
    }
}
