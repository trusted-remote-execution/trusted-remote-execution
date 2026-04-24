use std::process::Command;

const BINARY_PATH: &str = env!("CARGO_BIN_EXE_cedar-policy-validator");

const VALID_POLICY: &str = r#"
permit(
    principal == User::"test_user",
    action == Action::"read",
    resource == File::"test.txt"
);
"#;

const INVALID_POLICY: &str = r#"
permit(
    principal == User::"test_user"
    action == Action::"read"
    resource == File::"test.txt"
);
"#;

const VALID_SCHEMA: &str = r#"
entity User;
entity File;
action "read" appliesTo {
    principal: [User],
    resource: [File]
};
"#;

const PLUGIN_SCHEMA: &str = r#"
entity Plugin;
action "execute" appliesTo {
    principal: [User],
    resource: [Plugin]
};
"#;

const POLICY_WITH_PLUGIN: &str = r#"
permit(
    principal == User::"test_user",
    action == Action::"execute",
    resource == Plugin::"test_plugin"
);
"#;

const INVALID_PLUGIN_SCHEMA: &str = r#"
entity Plugin;
action "execute" appliesTo {
    principal: [UndefinedEntity],
    resource: [Plugin]
};
"#;

const CONFLICTING_SCHEMA: &str = r#"
entity User;
entity File;
action "read" appliesTo {
    principal: [User],
    resource: [File]
};
"#;

/// Given: Valid policy and schema content.
/// When: The binary is executed with valid policy and schema strings.
/// Then: Policy validation should succeed with exit code 0 and success message.
#[test]
fn test_valid_policy_with_valid_schema() {
    let output = Command::new(BINARY_PATH)
        .args(&["--policy", VALID_POLICY, "--schema", VALID_SCHEMA])
        .output()
        .expect("Failed to execute process");

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0));
    assert!(stdout.contains("Policy validation successful!"));
}

/// Given: Invalid policy content (missing commas) and valid schema content.
/// When: The binary is executed with invalid policy and valid schema strings.
/// Then: Policy validation should fail with exit code 1 and error message.
#[test]
fn test_invalid_policy_with_valid_schema() {
    let output = Command::new(BINARY_PATH)
        .args(&["--policy", INVALID_POLICY, "--schema", VALID_SCHEMA])
        .output()
        .expect("Failed to execute process");

    assert_eq!(output.status.code(), Some(1));
}

/// Given: Valid policy that uses plugin entities, valid rex schema, and valid plugin schema.
/// When: The binary is executed with all three schema strings.
/// Then: Policy validation should succeed with combined schemas.
#[test]
fn test_valid_policy_with_plugin_schema() {
    let output = Command::new(BINARY_PATH)
        .args(&[
            "--policy",
            POLICY_WITH_PLUGIN,
            "--schema",
            VALID_SCHEMA,
            "--additional-schema",
            PLUGIN_SCHEMA,
        ])
        .output()
        .expect("Failed to execute process");

    assert_eq!(output.status.code(), Some(0));
}

/// Given: Valid policy and rex schema, but invalid plugin schema with undefined entities.
/// When: The binary is executed with the invalid plugin schema.
/// Then: Policy validation should fail with schema parsing error.
#[test]
fn test_valid_policy_with_invalid_plugin_schema() {
    let output = Command::new(BINARY_PATH)
        .args(&[
            "--policy",
            VALID_POLICY,
            "--schema",
            VALID_SCHEMA,
            "--additional-schema",
            INVALID_PLUGIN_SCHEMA,
        ])
        .output()
        .expect("Failed to execute process");

    assert_eq!(output.status.code(), Some(1));
}

/// Given: Policy requiring combined schemas and conflicting schema definitions.
/// When: The binary is executed with overlapping schema definitions.
/// Then: Schema combination should handle conflicts appropriately.
#[test]
fn test_schema_combination_with_conflicts() {
    let output = Command::new(BINARY_PATH)
        .args(&[
            "--policy",
            VALID_POLICY,
            "--schema",
            VALID_SCHEMA,
            "--additional-schema",
            CONFLICTING_SCHEMA,
        ])
        .output()
        .expect("Failed to execute process");

    assert!(output.status.code() == Some(1));
}

/// Given: Invalid rex schema content.
/// When: The binary is executed with malformed rex schema string.
/// Then: Should fail with schema parsing error.
#[test]
fn test_invalid_rex_schema_content() {
    let output = Command::new(BINARY_PATH)
        .args(&[
            "--policy",
            VALID_POLICY,
            "--schema",
            "invalid schema content",
        ])
        .output()
        .expect("Failed to execute process");

    assert_eq!(output.status.code(), Some(1));
}

/// Given: Empty schema content.
/// When: The binary is executed with empty schema string.
/// Then: Should fail with schema parsing error.
#[test]
fn test_empty_schema_content() {
    let output = Command::new(BINARY_PATH)
        .args(&["--policy", VALID_POLICY, "--schema", ""])
        .output()
        .expect("Failed to execute process");

    assert_eq!(output.status.code(), Some(1));
}
