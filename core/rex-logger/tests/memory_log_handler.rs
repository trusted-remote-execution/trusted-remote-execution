use rex_logger::memory_logger::config::{DEFAULT_LOG_ENTRIES_LIMIT, DEFAULT_MESSAGE_LENGTH_LIMIT};
use rex_logger::memory_logger::handler::{get_current_rhai_context, push_rhai_context_with_guard};
use rex_logger::{
    LoggingOptionBuilder, RUNNER_AND_SYSLOG_TARGET, RUNNER_TARGET, ScriptLogHandle,
    get_script_handle, init_logger,
};
use rstest::rstest;
use sealed_test::prelude::{rusty_fork_test, sealed_test};
use tracing::info;
use tracing::subscriber::{DefaultGuard, set_default};
use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;
use tracing_subscriber::registry;

/// Helper function to set up tracing with ScriptLogHandle for testing
/// Returns the handle and a guard that should be kept alive for the test duration
fn setup_tracing() -> (ScriptLogHandle, DefaultGuard) {
    let handle = ScriptLogHandle::new(DEFAULT_MESSAGE_LENGTH_LIMIT, DEFAULT_LOG_ENTRIES_LIMIT);
    let handle_clone = handle.clone();

    let subscriber = registry().with(handle_clone);
    let guard = set_default(subscriber);

    (handle, guard)
}

/// Given: A logger is initialized with script logging enabled
/// When: get_script_handle() is called
/// Then: It should return Some(handle) with the global script handle
#[sealed_test]
fn test_get_script_handle_after_init() {
    let config = LoggingOptionBuilder::default()
        .script_log(true)
        .console(false)
        .syslog(false)
        .build()
        .unwrap();

    let result = init_logger(&config);
    assert!(result.is_ok(), "Logger initialization should succeed");

    let handle = get_script_handle();
    assert!(
        handle.is_some(),
        "Should return Some when script logging is enabled"
    );

    if let Some(h) = handle {
        let logs = h.get_logs();
        assert!(logs.is_empty(), "Initial logs should be empty");
    }
}

/// Given: A ScriptLogHandle integrated with a real tracing subscriber
/// When: Real tracing events are generated with `RUNNER_AND_SYSLOG_TARGET` and `RUNNER_TARGET` target
/// Then: The events should capture only 1 log as `RUNNER_TARGET` log will be skipped
#[test]
fn test_real_tracing_integration() {
    let (handle, _guard) = setup_tracing();

    info!(target: RUNNER_AND_SYSLOG_TARGET, "Test message 1");
    info!(target: RUNNER_TARGET, "Test message 2");
    info!(target: "other_target", "Should be ignored");

    let logs = handle.get_logs();
    assert_eq!(logs.len(), 1);

    let messages: Vec<String> = logs.iter().map(|log| log.message.clone()).collect();
    assert!(messages.iter().any(|msg| msg.contains("Test message 1")));
    assert!(!messages.iter().any(|msg| msg.contains("Should be ignored")));
}

/// Given: A ScriptLogHandle with real tracing
/// When: Empty messages are logged in different ways
/// Then: The handler should gracefully handle empty messages
#[test]
fn test_empty_message_scenarios() {
    let (handle, _guard) = setup_tracing();

    info!(target: RUNNER_AND_SYSLOG_TARGET, "");

    let logs = handle.get_logs();
    assert_eq!(logs.len(), 1);

    let log = &logs[0];
    assert!(log.message.is_empty(), "Log message is empty message");
}

/// Given: A ScriptLogHandle with real tracing
/// When: Events with various string field types are logged
/// Then: Only the "message" field should be captured by record_str
#[test]
fn test_record_str_field_filtering() {
    let (handle, _guard) = setup_tracing();

    info!(
        target: RUNNER_AND_SYSLOG_TARGET,
        message = "This should be captured",
        user_name = "john_doe",           // Should be ignored
        action = "login",                 // Should be ignored
        "Event occurred"
    );

    let logs = handle.get_logs();
    assert_eq!(logs.len(), 1);

    let log_message = &logs[0].message;
    assert!(log_message.contains("This should be captured"));

    // The visitor should only capture the "message" field
    assert!(!log_message.contains("john_doe"));
    assert!(!log_message.contains("login"));
}

/// Given: A ScriptLogHandle is initialized
/// When: `push_rhai_context_with_guard` is called
/// Then: The context should be added to the stack and retrievable
#[sealed_test]
fn test_rhai_context() {
    let config = LoggingOptionBuilder::default()
        .script_log(true)
        .console(false)
        .syslog(false)
        .build()
        .unwrap();

    let result = init_logger(&config);
    assert!(result.is_ok());

    let _guard = push_rhai_context_with_guard(Some("test_function"), 42);

    let current = get_current_rhai_context();
    assert!(current.is_some());

    let context = current.unwrap();
    assert_eq!(context.rhai_api_name, Some("test_function".to_string()));
    assert_eq!(context.line_number, 42);
}

/// Given: Various message length limits in LoggingOption
/// When: Messages of different lengths are logged
/// Then: Messages should be truncated correctly based on the configured limit
#[rstest]
#[case(Some(100), 50, false)]
#[case(Some(100), 100, false)]
#[case(Some(100), 150, true)]
#[case(None, 1000, false)]
#[case(None, 3000, true)]
#[case(Some(40), 50, true)]
#[sealed_test]
fn test_message_truncation_scenarios(
    #[case] max_script_log_message_length: Option<usize>,
    #[case] input_message_length: usize,
    #[case] should_truncate: bool,
) {
    let config = LoggingOptionBuilder::default()
        .script_log(true)
        .max_script_log_message_length(max_script_log_message_length)
        .build()
        .unwrap();

    let _ = init_logger(&config).expect("Logger should initialize");

    let test_message = "X".repeat(input_message_length);
    info!(target: RUNNER_AND_SYSLOG_TARGET, message = %test_message, "Test");

    let logs = get_script_handle().unwrap().get_logs();
    let logged_message = &logs[0].message;

    if should_truncate {
        let expected_len = max_script_log_message_length.unwrap_or(2048).max(20);
        assert_eq!(logged_message.len(), expected_len);
        assert!(logged_message.ends_with("...[truncate]"));
    } else {
        assert_eq!(logged_message, &test_message);
    }
}
