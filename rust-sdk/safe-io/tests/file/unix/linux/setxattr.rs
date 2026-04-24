use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{TestCedarAuthBuilder, get_test_rex_principal};
use rex_test_utils::assertions::assert_error_contains;
use rstest::rstest;
use rust_safe_io::options::SetXAttrOptionsBuilder;
use rustix::fs::fgetxattr;
use std::os::fd::AsFd;
use std::process::Command;

use anyhow::Result;

use crate::test_common::open_dir_and_file;

/// Returns true if SELinux is disabled, meaning tests that require SELinux should be skipped.
/// Runs `getenforce` command and checks if output is "Disabled".
fn should_skip_tests() -> bool {
    Command::new("/usr/sbin/getenforce")
        .output()
        .map(|output| {
            String::from_utf8(output.stdout)
                .unwrap_or_default()
                .trim()
                .eq_ignore_ascii_case("disabled")
        })
        .unwrap_or(true) // Skip if getenforce command fails (SELinux not installed)
}

/// Given: A file and an unauthorized user
/// When: `safe_set_xattr` is called with SetXAttr action forbidden
/// Then: An error is returned indicating the user is unauthorized
#[test]
fn test_safe_set_xattr_unauthorized() -> Result<()> {
    let test_contents = open_dir_and_file()?;

    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"forbid(
            principal == User::"{principal}",
            action == {},
            resource
        );"#,
        FilesystemAction::SetXAttr
    );
    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()?
        .create();

    let set_xattr_options = SetXAttrOptionsBuilder::default()
        .name("security.selinux".to_string())
        .selinux_type("test_type".to_string())
        .build()?;

    let result = test_contents
        .file_handle
        .safe_set_xattr(&test_cedar_auth, set_xattr_options);

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::SetXAttr
    );
    assert_error_contains(result, &expected_error);
    Ok(())
}

/// Given: A file and an authorized user
/// When: `safe_set_xattr` is called with an invalid SELinux component
/// Then: An error is returned with the appropriate validation message
#[rstest]
#[case::empty_string("", "cannot be empty or whitespace-only")]
#[case::whitespace_only("   ", "cannot be empty or whitespace-only")]
#[case::leading_whitespace(" valid", "cannot have leading or trailing whitespace")]
#[case::trailing_whitespace("valid ", "cannot have leading or trailing whitespace")]
#[case::contains_colon("user:role", "cannot contain ':' character")]
#[case::contains_control_char("user\x00type", "cannot contain control characters")]
#[case::contains_newline("user\ntype", "cannot contain control characters")]
#[case::contains_tab("user\ttype", "cannot contain control characters")]
fn test_safe_set_xattr_invalid_selinux_component(
    #[case] invalid_value: &str,
    #[case] expected_error_substring: &str,
) -> Result<()> {
    let test_contents = open_dir_and_file()?;

    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action == {},
            resource
        );"#,
        FilesystemAction::SetXAttr
    );
    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()?
        .create();

    let set_xattr_options = SetXAttrOptionsBuilder::default()
        .name("security.selinux".to_string())
        .selinux_type(invalid_value.to_string())
        .build()?;

    let result = test_contents
        .file_handle
        .safe_set_xattr(&test_cedar_auth, set_xattr_options);

    assert_error_contains(result, expected_error_substring);
    Ok(())
}

fn get_selinux_xattr<Fd: AsFd>(fd: Fd) -> Result<String> {
    let mut buffer = vec![0u8; 1024];
    let size = fgetxattr(&fd, "security.selinux", &mut buffer)?;
    buffer.truncate(size);
    Ok(String::from_utf8_lossy(&buffer).to_string())
}

fn extract_selinux_type(context: &str) -> Option<&str> {
    // SELinux context format: user:role:type:level
    context.split(':').nth(2)
}

/// Given: A file and an authorized user with SELinux enabled
/// When: `safe_set_xattr` is called with security.selinux attribute
/// Then: The xattr type is successfully updated
#[test]
fn test_safe_set_xattr_success() -> Result<()> {
    if should_skip_tests() {
        println!("Skipping SELinux xattr test - SELinux is disabled or not installed");
        return Ok(());
    }

    let test_contents = open_dir_and_file()?;

    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action == {},
            resource
        );"#,
        FilesystemAction::SetXAttr
    );
    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()?
        .create();

    let xattr_before = get_selinux_xattr(&test_contents.file_handle)?;
    let type_before = extract_selinux_type(&xattr_before);

    let new_type = if type_before == Some("container_file_t") {
        "user_tmp_t"
    } else {
        "container_file_t"
    };
    let set_xattr_options = SetXAttrOptionsBuilder::default()
        .name("security.selinux".to_string())
        .selinux_type(new_type.to_string())
        .build()?;

    let result = test_contents
        .file_handle
        .safe_set_xattr(&test_cedar_auth, set_xattr_options);

    assert!(
        result.is_ok(),
        "Expected success but got: {:?}",
        result.err()
    );

    let xattr_after = get_selinux_xattr(&test_contents.file_handle)?;
    let type_after = extract_selinux_type(&xattr_after);

    assert_eq!(
        type_after,
        Some(new_type),
        "Expected SELinux type to be '{}' but got '{:?}'. Full context: {}",
        new_type,
        type_after,
        xattr_after
    );

    Ok(())
}

/// Given: A policy that only allows set_x_attr for a specific xattr name (system.posix_acl_access)
/// When: `safe_set_xattr` is called with a different xattr name (security.selinux)
/// Then: An error is returned indicating the user is unauthorized due to context mismatch
#[test]
fn test_safe_set_xattr_unauthorized_wrong_xattr_name_in_context() -> Result<()> {
    let test_contents = open_dir_and_file()?;

    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action == {},
            resource
        ) when {{
            context.xattr.name == "system.posix_acl_access"
        }};"#,
        FilesystemAction::SetXAttr
    );
    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()?
        .create();

    let set_xattr_options = SetXAttrOptionsBuilder::default()
        .name("security.selinux".to_string())
        .selinux_type("test_type".to_string())
        .build()?;

    let result = test_contents
        .file_handle
        .safe_set_xattr(&test_cedar_auth, set_xattr_options);

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::SetXAttr
    );
    assert_error_contains(result, &expected_error);
    Ok(())
}

/// Given: A file and an authorized user
/// When: `safe_set_xattr` is called with an unsupported xattr name (not security.selinux)
/// Then: An error is returned indicating the operation is unsupported
#[test]
fn test_safe_set_xattr_unsupported_xattr_name() -> Result<()> {
    let test_contents = open_dir_and_file()?;

    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action == {},
            resource
        );"#,
        FilesystemAction::SetXAttr
    );
    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()?
        .create();

    let unsupported_xattr_name = "user.custom";
    let set_xattr_options = SetXAttrOptionsBuilder::default()
        .name(unsupported_xattr_name.to_string())
        .selinux_type("test_type".to_string())
        .build()?;

    let result = test_contents
        .file_handle
        .safe_set_xattr(&test_cedar_auth, set_xattr_options);

    let expected_error = format!(
        "Extended attribute for '{}' is not supported. Only 'security.selinux' is supported.",
        unsupported_xattr_name
    );
    assert_error_contains(result, &expected_error);
    Ok(())
}
