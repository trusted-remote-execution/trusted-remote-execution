use rhai_safe_disk_info::errors::RhaiDiskinfoErrorKind;
use rhai_safe_io::errors::RhaiSafeIoErrorKind;
#[cfg(target_os = "linux")]
use rhai_safe_process_mgmt::errors::RhaiSafeProcessMgmtErrorKind;
use rhai_safe_system_info::errors::RhaiSysteminfoErrorKind;
use rhai_sdk_common_utils::errors::RhaiCommonUtilsErrorKind;

use rhai::{EvalAltResult, Map};

/// Formats Rhai evaluation errors into human-readable error messages.
pub fn format_error_message(err: &EvalAltResult) -> String {
    match err {
        EvalAltResult::ErrorRuntime(obj, pos) => {
            let position_info = if pos.is_none() {
                String::new()
            } else {
                format!(
                    " (line {}, position {})",
                    pos.line().unwrap_or(0),
                    pos.position().unwrap_or(0)
                )
            };

            obj.clone().try_cast::<Map>().map_or_else(
                || format!("{err}{position_info}"),
                |map| {
                    let source = map
                        .get("source")
                        .map_or_else(|| "Unknown".to_string(), |d| format!("{d}"));

                    let kind_display = map
                        .get("kind")
                        .and_then(|d| {
                            d.clone()
                                .try_cast::<RhaiSafeIoErrorKind>()
                                .map(|k| k.to_string())
                                .or_else(|| {
                                    #[cfg(target_os = "linux")]
                                    {
                                        d.clone()
                                            .try_cast::<RhaiSafeProcessMgmtErrorKind>()
                                            .map(|k| k.to_string())
                                    }
                                    #[cfg(not(target_os = "linux"))]
                                    {
                                        None
                                    }
                                })
                                .or_else(|| {
                                    d.clone()
                                        .try_cast::<RhaiDiskinfoErrorKind>()
                                        .map(|k| k.to_string())
                                })
                                .or_else(|| {
                                    d.clone()
                                        .try_cast::<RhaiSysteminfoErrorKind>()
                                        .map(|k| k.to_string())
                                })
                                .or_else(|| {
                                    d.clone()
                                        .try_cast::<RhaiCommonUtilsErrorKind>()
                                        .map(|k| k.to_string())
                                })
                        })
                        .unwrap_or_else(|| "Unknown".to_string());

                    let message = map
                        .get("message")
                        .map_or_else(|| "No message available".to_string(), |d| format!("{d}"));

                    format!("{source}: {kind_display}: {message}{position_info}")
                },
            )
        }
        EvalAltResult::ErrorTerminated(token, pos) => {
            let position_info = if pos.is_none() {
                String::new()
            } else {
                format!(
                    " (line {}, position {})",
                    pos.line().unwrap_or(0),
                    pos.position().unwrap_or(0)
                )
            };

            format!("Script terminated: {token}{position_info}")
        }
        _ => err.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rhai::Dynamic;
    use rhai_safe_io::errors::RhaiSafeIoErrorKind;
    use rstest::rstest;

    fn create_test_map(kind: Option<Dynamic>, message: Option<String>) -> Map {
        let mut map = Map::new();
        if let Some(k) = kind {
            map.insert("kind".into(), k);
        }
        if let Some(m) = message {
            map.insert("message".into(), Dynamic::from(m));
        }
        map
    }

    /// Helper function to create a runtime error with a map (if not already present)
    fn create_runtime_error_with_map(map: Map) -> EvalAltResult {
        EvalAltResult::ErrorRuntime(Dynamic::from(map), rhai::Position::NONE)
    }

    /// Given: Various error map configurations
    /// When: `format_error_message` is called with these configurations
    /// Then: It should return appropriately formatted error messages containing expected kind and message values or fallback values
    #[rstest]
    #[case(
        Some(Dynamic::from(RhaiSafeIoErrorKind::DirectoryOpenError)),
        Some("Failed to open directory".to_string()),
        vec!["DirectoryOpenError", "Failed to open directory", ":"]
    )]
    #[case(
        Some(Dynamic::from("invalid_kind_string")),
        Some("Test message".to_string()),
        vec!["Unknown", "Test message"]
    )]
    #[case(
        None,
        Some("Test message".to_string()),
        vec!["Unknown", "Test message"]
    )]
    #[case(
        Some(Dynamic::from(RhaiSafeIoErrorKind::IoError)),
        None,
        vec!["IoError", "No message available"]
    )]
    #[case(
        None,
        None,
        vec!["Unknown", "No message available"]
    )]
    fn test_format_error_message_map_cases(
        #[case] kind: Option<Dynamic>,
        #[case] message: Option<String>,
        #[case] expected_contents: Vec<&str>,
    ) {
        let map = create_test_map(kind, message);
        let error = create_runtime_error_with_map(map);
        let result = format_error_message(&error);

        for expected in expected_contents {
            assert!(result.contains(expected));
        }
    }

    /// Given: An ErrorRuntime with position information (line and column)
    /// When: format_error_message is called with this positioned error
    /// Then: The formatted message should include the line and column numbers
    #[test]
    fn test_format_error_message_with_line_numbers() {
        let mut map = Map::new();
        map.insert("source".into(), Dynamic::from("test_source"));
        map.insert("kind".into(), Dynamic::from(RhaiSafeIoErrorKind::IoError));
        map.insert("message".into(), Dynamic::from("No such file or directory"));

        let position = rhai::Position::new(15, 23);
        let error = EvalAltResult::ErrorRuntime(Dynamic::from(map), position);

        let result = format_error_message(&error);

        assert!(result.contains("test_source"), "Should contain source");
        assert!(result.contains("IoError"), "Should contain error kind");
        assert!(
            result.contains("No such file or directory"),
            "Should contain message"
        );
        assert!(
            result.contains("(line 15, position 23)"),
            "Should contain line and column numbers"
        );

        let expected = "test_source: IoError: No such file or directory (line 15, position 23)";
        assert_eq!(result, expected);
    }

    /// Given: An ErrorTerminated with a termination token and position information
    /// When: format_error_message is called
    /// Then: It should return a properly formatted termination message with position info
    #[test]
    fn test_format_error_message_terminated_with_position() {
        let token = "Script terminated: SIGTERM timeout exceeded";
        let position = rhai::Position::new(42, 15);
        let error = EvalAltResult::ErrorTerminated(Dynamic::from(token), position);

        let result = format_error_message(&error);

        assert_eq!(
            result,
            "Script terminated: Script terminated: SIGTERM timeout exceeded (line 42, position 15)"
        );
    }
}
