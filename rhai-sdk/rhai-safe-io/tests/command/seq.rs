use rex_test_utils::rhai::common::create_test_engine_and_register;

// ── basic usage ─────────────────────────────────────────────────────────────

/// Given: A start and end value
/// When: Using seq(1, 5)
/// Then: A sequence [1, 2, 3, 4, 5] is returned
#[test]
fn test_seq_basic() {
    let engine = create_test_engine_and_register();
    let result: rhai::Array = engine.eval(r#"seq(1, 5)"#).unwrap();
    let nums: Vec<i64> = result.into_iter().map(|v| v.cast::<i64>()).collect();
    assert_eq!(nums, vec![1, 2, 3, 4, 5]);
}

/// Given: A single-element range
/// When: Using seq(3, 3)
/// Then: A single-element array is returned
#[test]
fn test_seq_single_element() {
    let engine = create_test_engine_and_register();
    let result: rhai::Array = engine.eval(r#"seq(3, 3)"#).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].clone().cast::<i64>(), 3);
}

// ── flags ───────────────────────────────────────────────────────────────────

/// Given: A step of 2
/// When: Using seq with seq::step(2)
/// Then: Every other number is returned
#[test]
fn test_seq_step_flag() {
    let engine = create_test_engine_and_register();
    let result: rhai::Array = engine.eval(r#"seq([seq::step(2)], 1, 10)"#).unwrap();
    let nums: Vec<i64> = result.into_iter().map(|v| v.cast::<i64>()).collect();
    assert_eq!(nums, vec![1, 3, 5, 7, 9]);
}

/// Given: A step of 3
/// When: Using seq with seq::step(3)
/// Then: Every third number is returned
#[test]
fn test_seq_step_3() {
    let engine = create_test_engine_and_register();
    let result: rhai::Array = engine.eval(r#"seq([seq::step(3)], 0, 9)"#).unwrap();
    let nums: Vec<i64> = result.into_iter().map(|v| v.cast::<i64>()).collect();
    assert_eq!(nums, vec![0, 3, 6, 9]);
}

/// Given: A negative step
/// When: Using seq with seq::step(-1) and start > end
/// Then: A descending sequence is returned
#[test]
fn test_seq_negative_step() {
    let engine = create_test_engine_and_register();
    let result: rhai::Array = engine.eval(r#"seq([seq::step(-1)], 5, 1)"#).unwrap();
    let nums: Vec<i64> = result.into_iter().map(|v| v.cast::<i64>()).collect();
    assert_eq!(nums, vec![5, 4, 3, 2, 1]);
}

// ── error cases ─────────────────────────────────────────────────────────────

/// Given: A step of 0
/// When: Using seq
/// Then: An error is returned
#[test]
fn test_seq_zero_step_error() {
    let engine = create_test_engine_and_register();
    let result = engine.eval::<rhai::Array>(r#"seq([seq::step(0)], 1, 5)"#);
    assert!(result.is_err());
}
