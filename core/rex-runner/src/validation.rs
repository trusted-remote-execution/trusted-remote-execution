use crate::model::ScriptArgumentValue;
use std::collections::HashMap;

/// Validates that script arguments do not exceed the maximum nesting depth of 2.
#[allow(clippy::implicit_hasher)]
pub fn validate_script_arguments_depth(
    script_args: &HashMap<String, ScriptArgumentValue>,
) -> Result<(), String> {
    const MAX_DEPTH: usize = 2;
    for (key, value) in script_args {
        validate_script_argument_value_depth(value, 1, MAX_DEPTH)
            .map_err(|e| format!("Argument '{key}': {e}"))?;
    }
    Ok(())
}

/// Recursively validates the depth of a single [`ScriptArgumentValue`].
pub fn validate_script_argument_value_depth(
    value: &ScriptArgumentValue,
    current_depth: usize,
    max_depth: usize,
) -> Result<(), String> {
    if current_depth > max_depth {
        return Err(format!("Maximum nesting depth of {max_depth} exceeded"));
    }

    match value {
        ScriptArgumentValue::ListValue(list) => {
            for item in list {
                validate_script_argument_value_depth(item, current_depth + 1, max_depth)?;
            }
        }
        ScriptArgumentValue::MapValue(map) => {
            for item in map.values() {
                validate_script_argument_value_depth(item, current_depth + 1, max_depth)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Given: Script arguments with valid depth (primitives only)
    /// When: validate_script_arguments_depth is called
    /// Then: Returns Ok
    #[test]
    fn test_validate_script_arguments_depth_primitives_success() {
        let mut args = HashMap::new();
        args.insert(
            "name".to_string(),
            ScriptArgumentValue::StringValue("Alice".to_string()),
        );
        args.insert("age".to_string(), ScriptArgumentValue::LongValue(30));
        assert!(validate_script_arguments_depth(&args).is_ok());
    }

    /// Given: Script arguments with valid depth (depth 2)
    /// When: validate_script_arguments_depth is called
    /// Then: Returns Ok
    #[test]
    fn test_validate_script_arguments_depth_level2_success() {
        let mut args = HashMap::new();
        args.insert(
            "list".to_string(),
            ScriptArgumentValue::ListValue(vec![ScriptArgumentValue::StringValue(
                "item1".to_string(),
            )]),
        );
        assert!(validate_script_arguments_depth(&args).is_ok());
    }

    /// Given: Script arguments with depth 3
    /// When: validate_script_arguments_depth is called
    /// Then: Returns Err
    #[test]
    fn test_validate_script_arguments_depth_level3_failure() {
        let mut inner_map = HashMap::new();
        inner_map.insert(
            "deep".to_string(),
            ScriptArgumentValue::StringValue("value".to_string()),
        );
        let mut outer_map = HashMap::new();
        outer_map.insert(
            "inner".to_string(),
            ScriptArgumentValue::MapValue(inner_map),
        );
        let mut args = HashMap::new();
        args.insert(
            "nested".to_string(),
            ScriptArgumentValue::MapValue(outer_map),
        );

        let result = validate_script_arguments_depth(&args);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("Maximum nesting depth of 2 exceeded")
        );
    }

    /// Given: Deeply nested list (depth 3)
    /// When: validate_script_arguments_depth is called
    /// Then: Returns Err
    #[test]
    fn test_validate_script_arguments_depth_nested_list_failure() {
        let deep_list = vec![ScriptArgumentValue::ListValue(vec![
            ScriptArgumentValue::StringValue("deep".to_string()),
        ])];
        let mut args = HashMap::new();
        args.insert(
            "deep_list".to_string(),
            ScriptArgumentValue::ListValue(deep_list),
        );

        let result = validate_script_arguments_depth(&args);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("Maximum nesting depth of 2 exceeded")
        );
    }
}
