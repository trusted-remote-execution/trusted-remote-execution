#![cfg(target_os = "linux")]

use rex_test_utils::rhai::common::{create_test_engine_and_register, deny_all_engine};
use rhai::Array;

// ── basic usage ─────────────────────────────────────────────────────────────

/// Given: A Linux system
/// When: Using df()
/// Then: A non-empty array of Filesystem structs is returned
#[test]
fn test_df_basic() {
    let engine = create_test_engine_and_register();
    let result: Array = engine.eval(r#"df()"#).unwrap();
    assert!(!result.is_empty());
}

/// Given: A Linux system
/// When: Accessing all fields of a df() entry
/// Then: All registered Filesystem fields are accessible
#[test]
fn test_df_entry_fields() {
    let engine = create_test_engine_and_register();
    let script = r#"
        let filesystems = df();
        let fs = filesystems[0];

        // String fields
        let s1 = fs.fs_device;
        let s2 = fs.fs_kind;
        let s3 = fs.mounted_on;

        // Numeric fields
        let v1 = fs.inodes;
        let v2 = fs.iused;
        let v3 = fs.ifree;
        let v4 = fs.block_used;
        let v5 = fs.block_available;
        let v6 = fs.kb_blocks;
        let v7 = fs.mb_blocks;
        let v8 = fs.size;

        // Float fields
        let f1 = fs.iuse_percent;
        let f2 = fs.block_use_percent;

        // Array field
        let a1 = fs.mount_options;
    "#;
    let result = engine.eval::<()>(script);
    assert!(
        result.is_ok(),
        "df entry field access failed: {:?}",
        result.unwrap_err()
    );
}

// ── error cases ─────────────────────────────────────────────────────────────

/// Given: A deny-all Cedar policy
/// When: Using df()
/// Then: An authorization error is returned
#[test]
fn test_df_unauthorized() {
    let engine = deny_all_engine();
    let result = engine.eval::<Array>(r#"df()"#);
    assert!(result.is_err());
}

// ── registry completeness ───────────────────────────────────────────────────

/// Given: The Filesystem struct with all its fields serialized via serde
/// When: Comparing serde field names against registered Rhai getters
/// Then: Every serialized field has a corresponding Rhai property getter
#[test]
fn test_df_filesystem_registry_completeness() {
    use rex_test_utils::rhai::safe_io::assert_rhai_getters_match_serde_fields;
    use rust_disk_info::Filesystem;

    let engine = create_test_engine_and_register();
    let filesystems: Array = engine.eval("df()").unwrap();
    let fs: Filesystem = filesystems[0].clone().cast();
    let json = serde_json::to_value(&fs).unwrap();

    assert_rhai_getters_match_serde_fields(&engine, "df()[0]", &json, &[], "Filesystem");
}
