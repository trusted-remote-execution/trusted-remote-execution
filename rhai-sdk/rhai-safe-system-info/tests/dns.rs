use rex_cedar_auth::sysinfo::actions::SysinfoAction;
use rex_cedar_auth::test_utils::get_test_rex_principal;
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::io::is_container;
use rex_test_utils::network::parse_nslookup_output;
use std::process::Command;

mod common;
use common::create_test_engine_and_register_with_policy;
use rhai::Array;
use rstest::rstest;

/// Given: an unauthorized user and a SystemInfo object
/// When: resolve method is called
/// Then: an authorization error is returned
#[test]
fn test_resolve_hostname_unauthorized() {
    let principal = get_test_rex_principal();
    let restrictive_policy = format!(
        r#"
            permit (
                principal,  
                action == {},
                resource
            );

            forbid (
                principal,  
                action,
                resource
            );
        "#,
        SysinfoAction::ResolveHostname
    );

    let engine = create_test_engine_and_register_with_policy(&restrictive_policy);
    let result = engine.eval::<()>(
        r#"
                let system_info = SystemInfo();
                let resolve_opts = ResolveOptions()
                    .hostname("localhost")
                    .timeout(from_secs(5))
                    .build();
                system_info.resolve_hostname(resolve_opts);
            "#,
    );

    assert!(
        result.is_err(),
        "Unauthorized user should not be able to resolve hostname"
    );

    let expected_error = format!("Permission denied: {principal} unauthorized to perform");
    assert_error_contains(result, &expected_error);
}

#[cfg(unix)]
/// Given: A hostname that resolves to multiple IP addresses "one.one.one.one"
/// When: Both our DNS resolver and nslookup are used to resolve the hostname with different ResolveOptions configurations
/// Then: Both should return the same set of IP addresses
#[rstest]
#[case("basic", r#"ResolveOptions().hostname("localhost").build()"#)]
#[case(
    "custom_resolver_google",
    r#"ResolveOptions().hostname("localhost").resolver("8.8.8.8").build()"#
)]
#[case(
    "UDP only",
    r#"ResolveOptions().hostname("localhost").protocol(TransportProtocol::UDP).build()"#
)]
#[cfg(target_os = "linux")]
fn test_resolve_hostname_success(#[case] test_name: &str, #[case] resolve_options_script: &str) {
    if is_container() {
        return;
    }

    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"
            permit (
                principal == User::"{principal}",
                action == {},
                resource
            );"#,
        SysinfoAction::ResolveHostname
    );

    let hostname = "localhost";
    let engine = create_test_engine_and_register_with_policy(&test_policy);
    let result = engine.eval::<Array>(&format!(
        r#"
                let system_info = SystemInfo();
                let resolve_opts = {};
                system_info.resolve_hostname(resolve_opts);
            "#,
        resolve_options_script
    ));

    assert!(
        result.is_ok(),
        "Resolution should succeed for test case '{}': {:?}",
        test_name,
        result.as_ref().err()
    );

    let our_ips_array = result.unwrap();

    // Convert Rhai Array to Vec<String>
    let our_ips: Vec<String> = our_ips_array
        .iter()
        .filter_map(|ip| ip.clone().try_cast::<String>())
        .collect();

    assert!(
        !our_ips.is_empty(),
        "Our resolver should return at least one IP for {} (test case: {})",
        hostname,
        test_name
    );

    let nslookup_output = Command::new("nslookup")
        .arg(hostname)
        .output()
        .expect("Failed to execute nslookup command");

    assert!(
        nslookup_output.status.success(),
        "nslookup command failed with status: {}",
        nslookup_output.status
    );

    let output_str = String::from_utf8_lossy(&nslookup_output.stdout);
    let nslookup_ips = parse_nslookup_output(&output_str);

    assert!(
        !nslookup_ips.is_empty(),
        "nslookup should return at least one IP for {}",
        hostname
    );

    let mut our_ips_sorted: Vec<String> = our_ips.iter().cloned().collect();
    our_ips_sorted.sort();
    our_ips_sorted.dedup();

    let mut nslookup_ips_sorted: Vec<String> = nslookup_ips.iter().cloned().collect();
    nslookup_ips_sorted.sort();
    nslookup_ips_sorted.dedup();

    assert_eq!(
        our_ips_sorted, nslookup_ips_sorted,
        "IP addresses should match for test case: {}",
        test_name
    );
}

/// Given: A policy that allows access
/// When: Hostname for the instance is called
/// Then: Hostname is returned
#[test]
fn test_hostname_success() {
    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"
            permit (
                principal == User::"{principal}",
                action == {},
                resource
            );"#,
        SysinfoAction::List
    );

    let engine = create_test_engine_and_register_with_policy(&test_policy);
    let result = engine.eval::<String>(
        r#"
                let system_info = SystemInfo();
                system_info.hostname();
            "#,
    );

    assert!(result.is_ok(), "Resolution should succeed");

    let hostname = result.unwrap();
    assert!(!hostname.is_empty(), "Hostname should not be empty");
}

/// Given: Policy to allow resolving hostnames but not getting system info
/// When: getting the hostname is attempted for the host
/// Then: an authorization error is returned because list is not granted
#[test]
fn test_hostname_unauthorized() {
    let principal = get_test_rex_principal();
    let restrictive_policy = format!(
        r#"
            permit (
                principal,  
                action == {},
                resource
            );
        "#,
        SysinfoAction::ResolveHostname
    );

    let engine = create_test_engine_and_register_with_policy(&restrictive_policy);
    let result = engine.eval::<()>(
        r#"
                let system_info = SystemInfo();
                system_info.hostname();
            "#,
    );

    assert!(
        result.is_err(),
        "Unauthorized user should not be able to resolve hostname"
    );

    let expected_error = format!("Permission denied: {principal} unauthorized to perform");
    assert_error_contains(result, &expected_error);
}
