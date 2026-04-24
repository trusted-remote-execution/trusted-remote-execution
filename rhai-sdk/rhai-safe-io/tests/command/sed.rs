use assert_fs::TempDir;
use rex_test_utils::rhai::common::{
    create_test_engine_and_register, create_test_file, deny_all_engine,
};
use std::fs;

// ── basic usage ─────────────────────────────────────────────────────────────

/// Given: A file with "hello hello"
/// When: Using sed("hello", "world", path)
/// Then: Only the first occurrence is replaced
#[test]
fn test_sed_basic_first_occurrence() {
    let (_temp, path) = create_test_file("hello hello");
    let engine = create_test_engine_and_register();
    let result: String = engine
        .eval(&format!(r#"sed("hello", "world", "{path}")"#))
        .unwrap();
    assert_eq!(result, "world hello");
}

// ── flags ───────────────────────────────────────────────────────────────────

/// Given: A file with repeated content
/// When: Using sed with sed::all flag
/// Then: All occurrences are replaced
#[test]
fn test_sed_all_flag() {
    let (_temp, path) = create_test_file("aaa");
    let engine = create_test_engine_and_register();
    let result: String = engine
        .eval(&format!(r#"sed([sed::all], "a", "b", "{path}")"#))
        .unwrap();
    assert_eq!(result, "bbb");
}

/// Given: A file with repeated content
/// When: Using sed with sed::g (short form)
/// Then: All occurrences are replaced
#[test]
fn test_sed_short_g_flag() {
    let (_temp, path) = create_test_file("xx");
    let engine = create_test_engine_and_register();
    let result: String = engine
        .eval(&format!(r#"sed([sed::g], "x", "y", "{path}")"#))
        .unwrap();
    assert_eq!(result, "yy");
}

/// Given: A file with content matching a regex
/// When: Using sed with sed::regex flag
/// Then: The regex pattern is matched and replaced
#[test]
fn test_sed_regex_flag() {
    let (_temp, path) = create_test_file("err123 err456");
    let engine = create_test_engine_and_register();
    let result: String = engine
        .eval(&format!(
            r#"sed([sed::regex], "err\\d+", "ERROR", "{path}")"#
        ))
        .unwrap();
    assert_eq!(result, "ERROR err456");
}

/// Given: A file with content
/// When: Using sed with sed::in_place flag
/// Then: The file is modified on disk
#[test]
fn test_sed_in_place_flag() {
    let (temp, path) = create_test_file("old content");
    let engine = create_test_engine_and_register();
    engine
        .eval::<String>(&format!(r#"sed([sed::in_place], "old", "new", "{path}")"#))
        .unwrap();
    let on_disk = fs::read_to_string(temp.path().join("test.txt")).unwrap();
    assert_eq!(on_disk, "new content");
}

/// Given: A file with content
/// When: Using sed with sed::i (short form for in_place)
/// Then: The file is modified on disk
#[test]
fn test_sed_short_i_flag() {
    let (temp, path) = create_test_file("foo bar");
    let engine = create_test_engine_and_register();
    engine
        .eval::<String>(&format!(r#"sed([sed::i], "foo", "baz", "{path}")"#))
        .unwrap();
    let on_disk = fs::read_to_string(temp.path().join("test.txt")).unwrap();
    assert_eq!(on_disk, "baz bar");
}

// ── flag combinations ───────────────────────────────────────────────────────

/// Given: A file with repeated regex-matchable content
/// When: Using sed with regex + all flags
/// Then: All regex matches are replaced
#[test]
fn test_sed_regex_and_all() {
    let (_temp, path) = create_test_file("a1 b2 c3");
    let engine = create_test_engine_and_register();
    let result: String = engine
        .eval(&format!(
            r#"sed([sed::regex, sed::all], "[a-z]\\d", "X", "{path}")"#
        ))
        .unwrap();
    assert_eq!(result, "X X X");
}

/// Given: A file with repeated content
/// When: Using sed with all + in_place flags
/// Then: All occurrences are replaced on disk
#[test]
fn test_sed_all_and_in_place() {
    let (temp, path) = create_test_file("ab ab ab");
    let engine = create_test_engine_and_register();
    engine
        .eval::<String>(&format!(
            r#"sed([sed::all, sed::in_place], "ab", "cd", "{path}")"#
        ))
        .unwrap();
    let on_disk = fs::read_to_string(temp.path().join("test.txt")).unwrap();
    assert_eq!(on_disk, "cd cd cd");
}

// ── error cases ─────────────────────────────────────────────────────────────

/// Given: A nonexistent file
/// When: Using sed
/// Then: An error is returned
#[test]
fn test_sed_nonexistent_file() {
    let temp = TempDir::new().unwrap();
    let missing = fs::canonicalize(temp.path()).unwrap().join("nope.txt");
    let engine = create_test_engine_and_register();
    let result = engine.eval::<String>(&format!(r#"sed("a", "b", "{}")"#, missing.display()));
    assert!(result.is_err());
}

/// Given: A file and a deny-all policy
/// When: Using sed
/// Then: An authorization error is returned
#[test]
fn test_sed_unauthorized() {
    let (_temp, path) = create_test_file("content");
    let engine = deny_all_engine();
    let result = engine.eval::<String>(&format!(r#"sed("a", "b", "{path}")"#));
    assert!(result.is_err());
    let err_str = format!("{:?}", result.unwrap_err());
    assert!(
        err_str.contains("unauthorized") || err_str.contains("Permission denied"),
        "Expected authorization error, got: {err_str}",
    );
}
