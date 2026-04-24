/// Returns the REX Cedar policy schema
///
/// This function returns a schema that defines entities and actions for basic file/directory operations
///
/// # Example
/// ```
/// # use rex_policy_schema::get_rex_policy_schema;
/// let schema = get_rex_policy_schema();
/// assert!(!schema.is_empty());
/// ```
pub const fn get_rex_policy_schema() -> &'static str {
    include_str!("schema/rex.cedarschema")
}

/// Returns a JSON array string for the REX Cedar entities
///
/// Currently, we have not defined an entities JSON as we're not using any attributes in our policies and are not doing any role-based access control
///
/// # Example
/// ```
/// # use rex_policy_schema::get_rex_entities;
/// let entities = get_rex_entities();
/// assert_eq!(entities, "[]");
/// ```
pub const fn get_rex_entities() -> &'static str {
    "[]"
}

#[cfg(test)]
mod tests {
    use super::*;
    use cedar_policy::{PolicySet, Schema, ValidationMode, Validator};
    use std::str::FromStr;

    /// Returns the test REX Cedar policy for tests

    const fn get_rex_policy() -> &'static str {
        include_str!("policy/rex_policy.cedar")
    }

    /// Given: The REX Cedar policy and schema
    /// When: Parsing and validating the policy against the schema
    /// Then: The policy should successfully validate against the schema
    #[test]
    fn test_rex_policy_schema_validation() {
        let policy = get_rex_policy();
        let schema = get_rex_policy_schema();

        let policy_set = PolicySet::from_str(policy).expect("Failed to parse policy");
        let schema = Schema::from_str(schema).expect("Failed to parse schema");

        let validator = Validator::new(schema);
        let validation_result = validator.validate(&policy_set, ValidationMode::Strict);

        assert!(
            validation_result.validation_passed(),
            "Policy validation failed: {}",
            validation_result.validation_errors().next().unwrap()
        );
    }

    /// Given: The REX Cedar entities JSON
    /// When: Parsing the entities JSON
    /// Then: It should be a valid JSON
    #[test]
    fn test_rex_entities() {
        let entities = get_rex_entities();
        serde_json::from_str::<serde_json::Value>(entities)
            .expect("REX entities should be valid JSON");
    }
}
