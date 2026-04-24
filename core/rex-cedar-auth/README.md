# CedarAuth

This package provides Cedar policy validation and authorization infrastructure for the Rex ecosystem.

## Key Components

### cedar-policy-validator (Binary)
A command-line tool that validates Cedar policy files against Cedar schema files. This binary provides a simple interface for policy validation and can be integrated into build processes or used standalone for policy verification.

The tool will:
- Read and parse the specified Cedar policy file
- Read and parse the specified Cedar schema file  
- Validate the policy against the schema
- Exit with status 0 on successful validation or status 1 on failure

### CedarAuth Library
A Rust library that provides comprehensive Cedar policy authorization functionality, including:
- Policy validation against schemas
- Authorization checks using the Cedar policy engine
- Entity management and context building for Cedar policies

## Usage

Other packages can depend on CedarAuth to get Cedar policy validation and authorization capabilities:

1. Add CedarAuth as a dependency in your `Config` file
2. Use the `cedar-policy-validator` binary for policy validation
3. Add dependency in `Cargo.toml` and use the library components for programmatic authorization

### Binary Usage Example
```bash
# Validate a Cedar policy against a schema
cedar-policy-validator --policy my-policy.cedar --schema my-schema.cedarschema
```

### Library Usage Example
```rust
use rex_cedar_auth::cedar_auth::{CedarAuth, AuthContextBuilder};
use cedar_policy::Decision;

// Create a CedarAuth instance
let (auth, warnings) = CedarAuth::new(policy_str, schema_str, entities_json)?;

// Build authorization context
let context = AuthContextBuilder::default()
    .principal("User::\"alice\"".to_string())
    .action("Action::\"read\"".to_string())
    .resource("File::\"document.txt\"".to_string())
    .context(serde_json::json!({"path": "/secure"}))
    .build()?;
```

## Useful Links

- [Cedar](https://docs.cedarpolicy.com/)
