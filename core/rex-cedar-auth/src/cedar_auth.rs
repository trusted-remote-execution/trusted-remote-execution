//! Core Cedar policy engine: authorization checks, entity management, and context building.

pub use crate::entities::{CedarRexEntity, UserEntity};
pub use crate::fs::entities::{ArgumentsEntity, EnvironmentEntity};
use crate::network::actions::NetworkAction;
use crate::sysinfo::actions::SysinfoAction;
pub use crate::users::Username;
use anyhow::{Context, Result};
use cedar_policy::SchemaFragment;
use cedar_policy::{
    Authorizer, Context as CedarContext, EntityUid, PolicySet, Request, Schema, SchemaWarning,
    ValidationMode, Validator,
};
pub use cedar_policy::{Decision, Entities, Entity};
use core::fmt;
use derive_builder::Builder;
use rex_logger::{RUNNER_AND_SYSLOG_TARGET, warn};
use serde_json::{Value, json};
use std::str::FromStr;

const PERMISSIVE_MODE_DENY: &str = "PERMISSIVE_MODE_DENY";

/// [`AuthContext`] represents the authorization context required for the Cedar policy evaluation.
#[derive(Builder, Debug, Clone)]
#[builder(derive(Debug))]
pub struct AuthContext {
    principal: String,
    action: String,
    resource: String,
    context: Value,
    #[builder(default = "Entities::empty()")]
    entities: Entities,
    #[builder(default = "Vec::new()")]
    context_entities: Vec<(String, Entity)>,
}

/// [`CedarAuth`] is responsible for performing authorization checks using the Cedar policy engine.
#[derive(Debug)]
pub struct CedarAuth {
    authorizer: Authorizer,
    policy_set: PolicySet,
    schema_fragments: Vec<String>,
    schema: Schema,
    entities: Entities,
    /// Enables permissive mode for non-production environments only. When true, denied
    /// authorization requests are logged and allowed to proceed instead of being rejected.
    /// Controlled exclusively via `rex_config` — never enable in production.
    enable_permissive_mode: bool,
}

/// This trait can be used anywhere an action is requested by Cedar
pub trait Action: fmt::Display {}

pub fn convert_pascal_to_snake_case(input: &str) -> String {
    let mut result = String::new();

    for (i, ch) in input.chars().enumerate() {
        if ch.is_uppercase() && i > 0 {
            result.push('_');
        }
        result.push(ch.to_ascii_lowercase());
    }

    result
}

impl CedarAuth {
    /// Creates a new [`CedarAuth`] instance for the provided policy, schema, and entities.
    ///
    /// # Arguments
    /// * `policy` - A string slice representing the Cedar policy for the auth.
    /// * `schema` - A string slice representing the Cedar schema for the policy.
    /// * `entities` - A string slice representing the Cedar entities JSON.
    ///
    /// # Returns
    /// * `Ok((CedarAuth, Vec<SchemaWarning>))` - The cedar auth instance and any schema construction warnings.
    /// * `Err` - If we fail to create the cedar auth instance
    pub fn new(
        policy: &str,
        schema_string: &str,
        entities: &str,
    ) -> Result<(Self, Vec<SchemaWarning>)> {
        let policy_set = PolicySet::from_str(policy)
            .context("Failed to parse Cedar policy - check syntax and structure")?;

        let entities = Entities::from_json_str(entities, None)
            .context("Failed to parse Cedar entities JSON - verify JSON format")?;

        let schema_fragments = vec![schema_string.to_string()];
        let (schema, schema_warnings) = Schema::from_cedarschema_str(schema_string)
            .context("Failed to build schema from fragments")?;

        let schema_warnings: Vec<_> = schema_warnings.collect();

        let authorizer = Authorizer::new();
        Ok((
            Self {
                authorizer,
                policy_set,
                schema_fragments,
                schema,
                entities,
                enable_permissive_mode: false,
            },
            schema_warnings,
        ))
    }

    /// Configures permissive mode at construction time, returning `Self` for chaining.
    #[must_use]
    pub fn with_permissive_mode(mut self, enabled: bool) -> Self {
        self.enable_permissive_mode = enabled;
        self
    }

    pub fn is_permissive_mode_enabled(&self) -> bool {
        self.enable_permissive_mode
    }

    pub fn set_permissive_mode(&mut self, enabled: bool) {
        self.enable_permissive_mode = enabled;
    }

    /// Adds an additional schema to the existing `CedarAuth` instance
    ///
    /// # Arguments
    /// * `schema_str` - Cedar schema string content to add
    ///
    /// # Returns
    /// * `Ok(())` - Schema successfully added
    /// * `Err` - If schema parsing or combining fails
    pub fn additional_schema(&mut self, schema_str: &str) -> Result<()> {
        self.schema_fragments.push(schema_str.to_string());

        let fragments = Self::convert_strings_to_fragments(&self.schema_fragments)?;
        self.schema = Schema::from_schema_fragments(fragments)
            .context("Failed to combine schema fragments")?;

        Ok(())
    }

    /// Validates the current policy set against the current schema using Cedar's strict validation mode.
    ///
    /// # Returns
    /// * `Ok(())` - All policies are valid according to the current schema
    /// * `Err` - One or more policies failed validation with detailed error information
    pub fn validate_policy(&self) -> Result<()> {
        let validator = Validator::new(self.schema.clone());
        let validation_result = validator.validate(&self.policy_set, ValidationMode::Strict);
        if !validation_result.validation_passed() {
            return Err(anyhow::anyhow!(
                "Failed to validate cedar policy: {validation_result}",
            ));
        }
        Ok(())
    }

    fn generate_uid_from_str(entity_uid_str: &str, cedar_type: &str) -> Result<EntityUid> {
        EntityUid::from_str(entity_uid_str).with_context(|| {
            format!("Failed to create {cedar_type} EntityUid from '{entity_uid_str}'")
        })
    }

    /// This fn hosts the core Cedar-based authorization logic. It builds the [`cedar_policy::Request`] from the [`AuthContext`]:
    /// # Arguments
    /// * `auth_context` - The authorization context containing principal, action, resource, and context information
    ///
    /// The Request is then validated using the Cedar Policy Engine and is only authorized if all the
    /// provided inputs / parameters are authorized by the previously provided Cedar policy.
    ///
    /// # Returns
    /// * <code>Ok([Decision::Allow])</code> - if the command is authorized for the current principal/user
    /// * <code>Ok([Decision::Deny])</code> - if the command is not authorized for the current principal/user
    /// * `Err` - if we fail to construct or process the authorization request
    /// # Examples
    /// ```no_run
    /// # use cedar_policy::Decision;
    /// use serde_json::json;
    /// # use rex_cedar_auth::cedar_auth::{AuthContext, AuthContextBuilder, CedarAuth};
    /// # fn example() -> anyhow::Result<()> {
    /// let policy = r#"
    ///     permit(
    ///         principal == User::"nobody",
    ///         action == Action::"read",
    ///         resource == File::"file.txt"
    ///     )
    ///     when { context.path == "/opt/rex" };
    /// "#;
    ///
    /// let schema = r#"
    ///     namespace {
    ///         entity User;
    ///         entity File;
    ///         action "read" appliesTo {
    ///             principal: [User],
    ///             resource: [File],
    ///             context: {
    ///                 path: String
    ///             }
    ///         };
    ///     }
    /// "#;
    ///
    /// let (auth, warnings) = CedarAuth::new(policy, schema, "[]")?;
    /// println!("Schema warnings: {warnings:?}");
    /// let context = AuthContextBuilder::default()
    ///     .principal(r#"User::"nobody""#.to_string())
    ///     .action(r#"Action::"read""#.to_string())
    ///     .resource(r#"File::"file.txt""#.to_string())
    ///     .build()?;
    ///
    /// match auth.is_authorized(context)? {
    ///     Decision::Allow => println!("Authorization successful"),
    ///     Decision::Deny => println!("Unauthorized operation doesn't have sufficient permissions"),
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn is_authorized(&self, auth_context: AuthContext) -> Result<Decision> {
        let principal_uid = Self::generate_uid_from_str(&auth_context.principal, "principal")?;
        let action_uid = Self::generate_uid_from_str(&auth_context.action, "action")?;
        let resource_uid = Self::generate_uid_from_str(&auth_context.resource, "resource")?;

        let context_for_logging = self
            .enable_permissive_mode
            .then(|| auth_context.context.clone());

        let context_entities_for_logging = self
            .enable_permissive_mode
            .then(|| auth_context.context_entities.clone());

        let mut entities_owned = auth_context.entities;

        let entity_context = if auth_context.context_entities.is_empty() {
            None
        } else {
            let context_entity_vec: Vec<Entity> = auth_context
                .context_entities
                .iter()
                .map(|(_, entity)| entity.clone())
                .collect();
            let context_entities = Entities::from_entities(context_entity_vec, Some(&self.schema))
                .context("Failed to build context_entities")?;
            entities_owned = entities_owned.add_entities(context_entities, Some(&self.schema))?;

            let entity_pairs: Vec<(String, cedar_policy::RestrictedExpression)> = auth_context
                .context_entities
                .iter()
                .map(|(key, entity)| {
                    let entity_ref =
                        cedar_policy::RestrictedExpression::new_entity_uid(entity.uid());
                    (key.clone(), entity_ref)
                })
                .collect();

            Some(
                CedarContext::from_pairs(entity_pairs)
                    .context("Failed to create entity context")?,
            )
        };

        let json_context = match auth_context.context.as_object() {
            Some(map) if !map.is_empty() => Some(
                CedarContext::from_json_value(auth_context.context, None)
                    .context("Failed to build JSON context")?,
            ),
            _ => None,
        };

        let cedar_context = match (json_context, entity_context) {
            (Some(json_ctx), Some(entity_ctx)) => {
                let merged = json_ctx
                    .merge(entity_ctx)
                    .context("Failed to merge contexts")?;
                merged
                    .validate(&self.schema, &action_uid)
                    .context("Failed to validate merged context")?;
                merged
            }
            (Some(ctx), None) | (None, Some(ctx)) => {
                ctx.validate(&self.schema, &action_uid)
                    .context("Failed to validate context")?;
                ctx
            }
            (None, None) => CedarContext::empty(),
        };

        entities_owned = entities_owned.add_entities(self.entities.clone(), Some(&self.schema))?;

        let request = Request::new(
            principal_uid,
            action_uid,
            resource_uid,
            cedar_context,
            Some(&self.schema),
        )
        .context("Failed to create authorization request")?;

        let response = self
            .authorizer
            .is_authorized(&request, &self.policy_set, &entities_owned);

        let decision = response.decision();

        if self.enable_permissive_mode && decision == Decision::Deny {
            let denying_policies: Vec<String> = response
                .diagnostics()
                .reason()
                .map(ToString::to_string)
                .collect();
            warn!(
                target: RUNNER_AND_SYSLOG_TARGET,
                "{} principal: {}, action: {}, resource: {}, context: {:?}, context_entities: {:?}, denying_policies: {:?}",
                PERMISSIVE_MODE_DENY,
                auth_context.principal,
                auth_context.action,
                auth_context.resource,
                context_for_logging,
                context_entities_for_logging,
                denying_policies,
            );
            return Ok(Decision::Allow);
        }

        Ok(decision)
    }

    pub fn check_sysinfo_permission<T: CedarRexEntity>(
        &self,
        principal: &dyn CedarRexEntity,
        action: SysinfoAction,
        resource: &str,
        entity: &T,
    ) -> Result<Decision> {
        let principal_uid = principal.cedar_eid();

        let context = AuthContextBuilder::default()
            .principal(principal_uid)
            .action(action.to_string())
            .resource(resource.to_string())
            .context(json!({}))
            .entities(entity.to_cedar_entities()?)
            .build()?;
        self.is_authorized(context)
    }

    pub fn check_network_permission<T: CedarRexEntity>(
        &self,
        principal: &dyn CedarRexEntity,
        action: NetworkAction,
        resource: &str,
        entity: &T,
    ) -> Result<Decision> {
        let principal_uid = principal.cedar_eid();

        let context = AuthContextBuilder::default()
            .principal(principal_uid)
            .action(action.to_string())
            .resource(resource.to_string())
            .context(json!({}))
            .entities(entity.to_cedar_entities()?)
            .build()?;
        self.is_authorized(context)
    }

    /// Helper method to convert schema strings to `SchemaFragments`
    ///
    /// # Arguments
    /// * `schema_strings` - Vector of schema strings to convert
    ///
    /// # Returns
    /// * `Ok(Vec<SchemaFragment>)` - Converted schema fragments
    /// * `Err` - If any schema string fails to parse
    fn convert_strings_to_fragments(schema_strings: &[String]) -> Result<Vec<SchemaFragment>> {
        let mut fragments = Vec::new();
        for schema_str in schema_strings {
            let (fragment, _) = SchemaFragment::from_cedarschema_str(schema_str)
                .with_context(|| format!("Failed to parse schema string: {schema_str}"))?;
            fragments.push(fragment);
        }
        Ok(fragments)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        network::entities::NetworkEntity,
        sysinfo::entities::{HostnameEntity, SysinfoEntity},
    };

    use super::*;
    use rex_cedar_auth::test_utils::get_default_test_rex_schema;
    use serde_json::json;

    const MOCK_PRINCIPAL: &str = "Namespace::User::\"MockUser\"";
    const MOCK_ACTION: &str = "Namespace::Action::\"MockCommand\"";
    const MOCK_RESOURCE: &str = "Namespace::MockResource::\"Any\"";
    const MOCK_INPUT_VALUE: &str = "mockValue";

    const MOCK_POLICY: &str = r#"
        permit(
            principal == Namespace::User::"MockUser",
            action == Namespace::Action::"MockCommand",
            resource == Namespace::MockResource::"Any"
        )
        when { context.value == "mockValue" };
    "#;

    const MOCK_SCHEMA: &str = r#"
        namespace Namespace {
            entity User;
            entity MockResource;

            action "MockCommand" appliesTo {
                principal: [User],
                resource: [MockResource],
                context: {
                    value: String
                }
            };
        }
    "#;

    const MOCK_ENTITIES: &str = "[]";
    const TEST_CEDAR_AUTH_ERROR: &str = "Failed to create test cedar auth";

    fn build_mock_auth_context(value: &str) -> Result<AuthContext> {
        Ok(AuthContextBuilder::default()
            .principal(MOCK_PRINCIPAL.to_string())
            .action(MOCK_ACTION.to_string())
            .resource(MOCK_RESOURCE.to_string())
            .context(json!({"value": value}))
            .build()?)
    }

    /// Given: A valid Cedar policy, Cedar schema, context JSON and authorized user.
    /// When:  `authorize` is called on the `MockCommand` using `CedarAuth`.
    /// Then:  Authorization should succeed (i.e. no errors thrown).
    #[test]
    fn test_cedar_authorize_success() -> Result<()> {
        let context = build_mock_auth_context(MOCK_INPUT_VALUE)?;
        let (cedar_auth, _warnings) =
            CedarAuth::new(MOCK_POLICY, MOCK_SCHEMA, MOCK_ENTITIES).expect(TEST_CEDAR_AUTH_ERROR);
        let result = cedar_auth.is_authorized(context).unwrap();
        assert_eq!(result, Decision::Allow);
        Ok(())
    }

    /// Given: A valid Cedar policy, Cedar schema and authorized user, but bad values in context.
    /// When:  `authorize` is called on the `MockCommand` using `CedarAuth`.
    /// Then:  Authorization should return Decision::Deny.
    #[test]
    fn test_cedar_authorize_fail_bad_value() -> Result<()> {
        let context = build_mock_auth_context("badValue")?;
        let (cedar_auth, _warnings) =
            CedarAuth::new(MOCK_POLICY, MOCK_SCHEMA, MOCK_ENTITIES).expect(TEST_CEDAR_AUTH_ERROR);
        let result = cedar_auth.is_authorized(context).unwrap();
        assert_eq!(result, Decision::Deny);
        Ok(())
    }

    /// Given: A valid Cedar policy, Cedar schema, context JSON, but unauthorized user.
    /// When:  `authorize` is called on the `MockCommand` using `CedarAuth`.
    /// Then:  Authorization should return Decision::Deny.
    #[test]
    fn test_cedar_authorize_fail_bad_user() -> Result<()> {
        let context = AuthContextBuilder::default()
            .principal("Namespace::User::\"BadUser\"".to_string())
            .action(MOCK_ACTION.to_string())
            .resource(MOCK_RESOURCE.to_string())
            .context(json!({"value": MOCK_INPUT_VALUE}))
            .build()?;
        let (cedar_auth, _warnings) =
            CedarAuth::new(MOCK_POLICY, MOCK_SCHEMA, MOCK_ENTITIES).expect(TEST_CEDAR_AUTH_ERROR);
        let result = cedar_auth.is_authorized(context).unwrap();
        assert_eq!(result, Decision::Deny);
        Ok(())
    }

    /// Given: A valid Cedar schema, context JSON and authorized user, but policy doesn't match schema.
    /// When:  `validate_policy` is called on the CedarAuth instance.
    /// Then:  Validation should fail (i.e. throws error).
    #[test]
    fn test_cedar_authorize_fail_policy_schema_mismatch() {
        const BAD_POLICY: &str = r#"
            permit(
                principal == Namespace::User::"MockUser",
                action == Namespace::Action::"MockCommand",
                resource == Namespace::BadResource::"any"
            )
            when { context.value == "mockValue" };
        "#;

        let result = CedarAuth::new(BAD_POLICY, MOCK_SCHEMA, MOCK_ENTITIES);
        assert!(result.is_ok());

        let (cedar_auth, _) = result.unwrap();
        let validation_result = cedar_auth.validate_policy();
        assert!(validation_result.is_err());
    }

    /// Given: A valid Cedar policy, context JSON and authorized user, but invalid schema.
    /// When:  `authorize` is called on the `MockCommand` using `CedarAuth`.
    /// Then:  Should fail to build cedar schema (i.e. throws error).
    #[test]
    fn test_cedar_authorize_fail_bad_schema() {
        const BAD_SCHEMA: &str = r#"
            namespace Namespace {
                entity User;

                action "MockCommand" appliesTo {
                    principal: [User],
                    resource: [MockResource],
                };
            }
        "#;

        let result = CedarAuth::new(MOCK_POLICY, BAD_SCHEMA, MOCK_ENTITIES);
        assert!(result.is_err());
        let error_string = format!("{:#}", result.unwrap_err());
        assert!(
            error_string.contains("Failed to build schema from fragments"),
            "Got: '{error_string}'"
        );
    }

    /// Given: A malformed Cedar policy string
    /// When: `CedarAuth::new` is called
    /// Then: Should fail to build cedar policy
    #[test]
    fn test_cedar_new_fail_malformed_policy() {
        const MALFORMED_POLICY: &str = r#"
            permit(
                principal == Namespace::User::"MockUser"
                action == Namespace::Action::"MockCommand"
                resource == Namespace::MockResource::"Any"
            )
        "#;

        let result = CedarAuth::new(MALFORMED_POLICY, MOCK_SCHEMA, MOCK_ENTITIES);
        assert!(result.is_err());
        let error_string = format!("{:#}", result.unwrap_err());
        assert!(
            error_string.contains("Failed to parse Cedar policy"),
            "Got: '{error_string}'"
        );
    }

    /// Given: A malformed entities JSON string
    /// When: `CedarAuth::new` is called
    /// Then: Should fail to build cedar entities
    #[test]
    fn test_cedar_new_fail_malformed_entities() {
        const MALFORMED_ENTITIES: &str = r#"[{"invalid": "json"}"#;

        let result = CedarAuth::new(MOCK_POLICY, MOCK_SCHEMA, MALFORMED_ENTITIES);
        assert!(result.is_err());
        let error_string = format!("{:#}", result.unwrap_err());
        assert!(
            error_string.contains("Failed to parse Cedar entities JSON"),
            "Got: '{error_string}'"
        );
    }

    /// Given: A valid Cedar policy, schema, and entities
    /// When: `CedarAuth::new` is called
    /// Then: Should return schema warnings if any exist
    #[test]
    fn test_cedar_new_with_schema_warnings() -> Result<()> {
        let schema_with_warnings = r#"
            namespace Namespace {
                entity User;
                entity MockResource;
                entity UnusedEntity;

                action "MockCommand" appliesTo {
                    principal: [User],
                    resource: [MockResource],
                    context: {
                        value: String
                    }
                };
            }
        "#;

        let (cedar_auth, _) = CedarAuth::new(MOCK_POLICY, schema_with_warnings, MOCK_ENTITIES)?;
        assert!(cedar_auth.policy_set.is_empty() == false);
        Ok(())
    }

    /// Given: A CedarAuth instance with invalid principal format
    /// When: `is_authorized` is called
    /// Then: Should fail to create principal EntityUid
    #[test]
    fn test_is_authorized_fail_invalid_principal() -> Result<()> {
        let context = AuthContextBuilder::default()
            .principal("InvalidPrincipalFormat".to_string())
            .action(MOCK_ACTION.to_string())
            .resource(MOCK_RESOURCE.to_string())
            .context(json!({"value": MOCK_INPUT_VALUE}))
            .build()?;

        let (cedar_auth, _) = CedarAuth::new(MOCK_POLICY, MOCK_SCHEMA, MOCK_ENTITIES)?;
        let result = cedar_auth.is_authorized(context);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to create principal EntityUid")
        );
        Ok(())
    }

    /// Given: A CedarAuth instance with invalid action format
    /// When: `is_authorized` is called
    /// Then: Should fail to create action EntityUid
    #[test]
    fn test_is_authorized_fail_invalid_action() -> Result<()> {
        let context = AuthContextBuilder::default()
            .principal(MOCK_PRINCIPAL.to_string())
            .action("InvalidActionFormat".to_string())
            .resource(MOCK_RESOURCE.to_string())
            .context(json!({"value": MOCK_INPUT_VALUE}))
            .build()?;

        let (cedar_auth, _) = CedarAuth::new(MOCK_POLICY, MOCK_SCHEMA, MOCK_ENTITIES)?;
        let result = cedar_auth.is_authorized(context);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to create action EntityUid")
        );
        Ok(())
    }

    /// Given: A CedarAuth instance with invalid resource format
    /// When: `is_authorized` is called
    /// Then: Should fail to create resource EntityUid
    #[test]
    fn test_is_authorized_fail_invalid_resource() -> Result<()> {
        let context = AuthContextBuilder::default()
            .principal(MOCK_PRINCIPAL.to_string())
            .action(MOCK_ACTION.to_string())
            .resource("InvalidResourceFormat".to_string())
            .context(json!({"value": MOCK_INPUT_VALUE}))
            .build()?;

        let (cedar_auth, _) = CedarAuth::new(MOCK_POLICY, MOCK_SCHEMA, MOCK_ENTITIES)?;
        let result = cedar_auth.is_authorized(context);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to create resource EntityUid")
        );
        Ok(())
    }

    /// Given: A CedarAuth instance with invalid context format
    /// When: `is_authorized` is called
    /// Then: Should fail to validate cedar context
    #[test]
    fn test_is_authorized_fail_invalid_context() -> Result<()> {
        let context = AuthContextBuilder::default()
            .principal(MOCK_PRINCIPAL.to_string())
            .action(MOCK_ACTION.to_string())
            .resource(MOCK_RESOURCE.to_string())
            .context(json!({"invalidField": "value"}))
            .build()?;

        let (cedar_auth, _) = CedarAuth::new(MOCK_POLICY, MOCK_SCHEMA, MOCK_ENTITIES)?;
        let result = cedar_auth.is_authorized(context);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to validate context")
        );
        Ok(())
    }

    /// Given: AuthContextBuilder with missing principal
    /// When: `build` is called
    /// Then: Should fail to build AuthContext
    #[test]
    fn test_auth_context_builder_missing_principal() {
        let result = AuthContextBuilder::default()
            .action(MOCK_ACTION.to_string())
            .resource(MOCK_RESOURCE.to_string())
            .context(json!({"value": MOCK_INPUT_VALUE}))
            .build();

        assert!(result.is_err());
    }

    /// Given: AuthContextBuilder with missing action
    /// When: `build` is called
    /// Then: Should fail to build AuthContext
    #[test]
    fn test_auth_context_builder_missing_action() {
        let result = AuthContextBuilder::default()
            .principal(MOCK_PRINCIPAL.to_string())
            .resource(MOCK_RESOURCE.to_string())
            .context(json!({"value": MOCK_INPUT_VALUE}))
            .build();

        assert!(result.is_err());
    }

    /// Given: AuthContextBuilder with missing resource
    /// When: `build` is called
    /// Then: Should fail to build AuthContext
    #[test]
    fn test_auth_context_builder_missing_resource() {
        let result = AuthContextBuilder::default()
            .principal(MOCK_PRINCIPAL.to_string())
            .action(MOCK_ACTION.to_string())
            .context(json!({"value": MOCK_INPUT_VALUE}))
            .build();

        assert!(result.is_err());
    }

    /// Given: AuthContextBuilder with missing context
    /// When: `build` is called
    /// Then: Should fail to build AuthContext
    #[test]
    fn test_auth_context_builder_missing_context() {
        let result = AuthContextBuilder::default()
            .principal(MOCK_PRINCIPAL.to_string())
            .action(MOCK_ACTION.to_string())
            .resource(MOCK_RESOURCE.to_string())
            .build();

        assert!(result.is_err());
    }

    /// Given: AuthContextBuilder with default entities
    /// When: `build` is called
    /// Then: Should use empty entities as default
    #[test]
    fn test_auth_context_builder_default_entities() -> Result<()> {
        let context = AuthContextBuilder::default()
            .principal(MOCK_PRINCIPAL.to_string())
            .action(MOCK_ACTION.to_string())
            .resource(MOCK_RESOURCE.to_string())
            .context(json!({"value": MOCK_INPUT_VALUE}))
            .build()?;

        assert_eq!(context.entities.iter().count(), 0);
        Ok(())
    }

    /// Given: A CedarAuth instance with permissive mode enabled and a deny policy
    /// When: `is_authorized` is called
    /// Then: Should return Allow despite the deny decision
    #[test]
    fn test_permissive_mode_deny_returns_allow() -> Result<()> {
        let context = build_mock_auth_context("badValue")?;
        let (mut cedar_auth, _) =
            CedarAuth::new(MOCK_POLICY, MOCK_SCHEMA, MOCK_ENTITIES).expect(TEST_CEDAR_AUTH_ERROR);
        cedar_auth.set_permissive_mode(true);
        assert!(
            cedar_auth.is_permissive_mode_enabled(),
            "Permissive mode should be enabled"
        );
        let result = cedar_auth.is_authorized(context)?;
        assert_eq!(
            result,
            Decision::Allow,
            "Permissive mode enabled should return Allow despite deny decision"
        );
        Ok(())
    }

    /// Given: A CedarAuth instance with permissive mode disabled and a deny policy
    /// When: `is_authorized` is called
    /// Then: Should return Deny as normal
    #[test]
    fn test_permissive_mode_disabled_deny_returns_deny() -> Result<()> {
        let context = build_mock_auth_context("badValue")?;
        let (cedar_auth, _) =
            CedarAuth::new(MOCK_POLICY, MOCK_SCHEMA, MOCK_ENTITIES).expect(TEST_CEDAR_AUTH_ERROR);
        let result = cedar_auth.is_authorized(context)?;
        assert_eq!(
            result,
            Decision::Deny,
            "Permissive mode disabled should return Deny"
        );
        Ok(())
    }

    /// Given: A CedarAuth instance with permissive mode enabled and an allow policy
    /// When: `is_authorized` is called
    /// Then: Should still return Allow (no change for allowed requests)
    #[test]
    fn test_permissive_mode_allow_still_returns_allow() -> Result<()> {
        let context = build_mock_auth_context(MOCK_INPUT_VALUE)?;
        let (mut cedar_auth, _) =
            CedarAuth::new(MOCK_POLICY, MOCK_SCHEMA, MOCK_ENTITIES).expect(TEST_CEDAR_AUTH_ERROR);
        cedar_auth.set_permissive_mode(true);
        assert!(
            cedar_auth.is_permissive_mode_enabled(),
            "Permissive mode should be enabled"
        );
        let result = cedar_auth.is_authorized(context)?;
        assert_eq!(
            result,
            Decision::Allow,
            "Permissive mode enabled should still return Allow for allowed requests"
        );
        Ok(())
    }

    /// Given: A CedarAuth instance with resource containing hostname
    /// When: Hostname resolution is called
    /// Then: Should properly handle resource
    #[test]
    fn test_check_hostname_resolution_permission() -> Result<()> {
        let user = UserEntity::new("test_user".to_string());
        let policy = r#"
            permit(
                principal == User::"test_user",
                action == sysinfo::Action::"resolve_hostname",
                resource == sysinfo::Hostname::"one.one.one.one"
            );
        "#;

        let schema = get_default_test_rex_schema();
        let (cedar_auth, _) = CedarAuth::new(policy, schema, "[]")?;
        let entity = HostnameEntity::new("one.one.one.one".to_string());
        let result = cedar_auth.check_sysinfo_permission(
            &user,
            SysinfoAction::ResolveHostname,
            &entity.cedar_eid(),
            &entity,
        )?;
        assert_eq!(result, Decision::Allow);
        Ok(())
    }

    /// Given: AuthContext with HashMap containing ArgumentsEntity and EnvironmentEntity
    /// When: is_authorized is called with complex policy using entity attributes and tags
    /// Then: Entities are properly converted and policy conditions are evaluated correctly
    #[test]
    fn test_is_authorized_with_arguments_and_environment_entities() -> Result<()> {
        // Complex policy that tests entity attributes and tags
        let policy = r#"
            permit(
                principal == User::"test_user",
                action == file_system::Action::"execute", 
                resource == file_system::File::"/usr/bin/ls"
            )
            when {
                // Test argument attributes (keys set)
                context.arguments.keys.contains("--verbose") && 
                context.arguments.keys.contains("--output") &&

                // Test argument attributes (flags set)
                context.arguments.flags.contains("--reverse") &&

                // Test argument attributes (poisitional values set)
                context.arguments.positional_values.contains("/tmp/input.txt") &&
                 
                // Test argument tags (values)
                context.arguments.hasTag("--verbose") && 
                context.arguments.getTag("--verbose") == "true" &&
                context.arguments.hasTag("--output") &&
                context.arguments.hasTag("--reverse") &&
                context.arguments.hasTag("/tmp/input.txt") &&

                // Test environment attributes (names set)
                context.environment.names.contains("PATH") &&
                context.environment.names.contains("USER") &&
                 
                // Test environment tags (values)
                context.environment.hasTag("PATH") &&
                context.environment.getTag("PATH") like "/usr/bin*" &&
                context.environment.hasTag("USER") &&
                context.environment.getTag("USER") like "test*" &&
                 
                // Test other required context fields
                context.user.username == "test_user" &&
                context.user.uid == 1000
            };
        "#;

        let (cedar_auth, _) = CedarAuth::new(policy, get_default_test_rex_schema(), "[]")?;

        let user = UserEntity::new("test_user".to_string());

        // Create ArgumentsEntity with named arguments that match policy conditions
        let args_entity = ArgumentsEntity::new(vec![
            ("--verbose".to_string(), Some("true".to_string())),
            ("--output".to_string(), Some("json".to_string())),
            ("--reverse".to_string(), None),
            ("/tmp/input.txt".to_string(), None),
        ]);

        let env_vars = vec![
            ("PATH".to_string(), "/usr/bin:/bin".to_string()),
            ("HOME".to_string(), "/home/user".to_string()),
            ("USER".to_string(), "testuser".to_string()),
        ];
        let env_entity = EnvironmentEntity::new(env_vars);

        let mut context_entities = Vec::new();
        context_entities.push(("arguments".to_string(), args_entity.to_cedar_entity()?));
        context_entities.push(("environment".to_string(), env_entity.to_cedar_entity()?));

        let auth_context = AuthContextBuilder::default()
            .principal(user.cedar_eid())
            .action("file_system::Action::\"execute\"".to_string())
            .resource("file_system::File::\"/usr/bin/ls\"".to_string())
            .context(json!({
                "user": {"username": "test_user", "uid": 1000},
                "group": {"groupname": "testgroup", "gid": 1000}
            }))
            .context_entities(context_entities)
            .build()?;

        let decision = cedar_auth.is_authorized(auth_context)?;
        assert_eq!(decision, Decision::Allow);
        Ok(())
    }

    /// Given: AuthContext with empty HashMap
    /// When: is_authorized is called
    /// Then: Authorization proceeds without entity conversion
    #[test]
    fn test_is_authorized_with_empty_context_entities() -> Result<()> {
        let policy = "permit(principal, action, resource);";
        let (cedar_auth, _) = CedarAuth::new(policy, get_default_test_rex_schema(), "[]")?;

        let user = UserEntity::new("test_user".to_string());
        let context_entities = Vec::new();

        let auth_context = AuthContextBuilder::default()
            .principal(user.cedar_eid())
            .action("file_system::Action::\"read\"".to_string())
            .resource("file_system::File::\"/test\"".to_string())
            .context(json!({}))
            .context_entities(context_entities)
            .build()?;

        let decision = cedar_auth.is_authorized(auth_context)?;
        assert_eq!(decision, Decision::Allow);
        Ok(())
    }

    /// Given: A CedarAuth instance with policy
    /// When: GET is called
    /// Then: Access allowed
    #[test]
    fn test_check_network_authorized() -> Result<()> {
        let user = UserEntity::new("test_user".to_string());
        let policy = r#"
            permit(
                principal == User::"test_user",
                action == network::Action::"GET",
                resource == network::url::"https://example.com"
            );
        "#;

        let schema = get_default_test_rex_schema();
        let (cedar_auth, _) = CedarAuth::new(policy, schema, "[]")?;
        let entity = NetworkEntity::new("https://example.com".to_string());
        let result = cedar_auth.check_network_permission(
            &user,
            NetworkAction::Get,
            &entity.cedar_eid(),
            &entity,
        )?;
        assert_eq!(result, Decision::Allow);
        Ok(())
    }

    /// Given: A CedarAuth instance with policy
    /// When: GET is called on a globbed URL
    /// Then: Access allowed
    #[test]
    fn test_check_network_glob_authorized() -> Result<()> {
        let user = UserEntity::new("test_user".to_string());
        let policy = r#"
            permit(
                principal == User::"test_user",
                action == network::Action::"GET",
                resource
            ) when {
                resource.url like "https://*"
            };
        "#;

        let schema = get_default_test_rex_schema();
        let (cedar_auth, _) = CedarAuth::new(policy, schema, "[]")?;
        let entity = NetworkEntity::new("https://example.com".to_string());
        let result = cedar_auth.check_network_permission(
            &user,
            NetworkAction::Get,
            &entity.cedar_eid(),
            &entity,
        )?;
        assert_eq!(result, Decision::Allow);
        Ok(())
    }

    /// Given: A CedarAuth instance with policy
    /// When: GET is called on a URL not allowed
    /// Then: Access denied
    #[test]
    fn test_check_network_denied() -> Result<()> {
        let user = UserEntity::new("test_user".to_string());
        let policy = r#"
            permit(
                principal == User::"test_user",
                action == network::Action::"GET",
                resource == network::url::"https://example.com"
            );
        "#;

        let schema = get_default_test_rex_schema();
        let (cedar_auth, _) = CedarAuth::new(policy, schema, "[]")?;
        let entity = NetworkEntity::new("https://blocked.example.com".to_string());
        let result = cedar_auth.check_network_permission(
            &user,
            NetworkAction::Get,
            &entity.cedar_eid(),
            &entity,
        )?;
        assert_eq!(result, Decision::Deny);
        Ok(())
    }

    /// Given: Policy that checks both JSON context and entity context
    /// When: is_authorized is called with both JSON context and context_entities
    /// Then: Both contexts should be merged and evaluated correctly
    #[test]
    fn test_is_authorized_merges_json_and_entity_contexts() -> Result<()> {
        let schema = r#"
            entity User;
            
            namespace file_system {
                entity File;
                entity Arguments {
                    keys: Set<String>,
                    flags: Set<String>,
                    positional_values: Set<String>
                } tags String;

                action "execute" appliesTo {
                    principal: [User],
                    resource: [File],
                    context: {
                        json_field?: String,
                        arguments?: Arguments
                    }
                };
            }
        "#;

        let policy = r#"
            permit(
                principal == User::"test_user",
                action == file_system::Action::"execute",
                resource == file_system::File::"/bin/ls"
            )
            when {
                context.arguments.hasTag("--verbose") &&
                context.json_field == "json_value"
            };
        "#;

        let (cedar_auth, _) = CedarAuth::new(policy, schema, "[]")?;

        let args_entity =
            ArgumentsEntity::new(vec![("--verbose".to_string(), Some("true".to_string()))]);

        let mut context_entities = Vec::new();
        context_entities.push(("arguments".to_string(), args_entity.to_cedar_entity()?));

        let auth_context = AuthContextBuilder::default()
            .principal("User::\"test_user\"".to_string())
            .action("file_system::Action::\"execute\"".to_string())
            .resource("file_system::File::\"/bin/ls\"".to_string())
            .context(json!({"json_field": "json_value"}))
            .context_entities(context_entities)
            .build()?;

        let decision = cedar_auth.is_authorized(auth_context)?;
        assert_eq!(decision, Decision::Allow);
        Ok(())
    }
}
