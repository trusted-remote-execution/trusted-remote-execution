use rex_cedar_auth::sysinfo::actions::SysinfoAction;
use rex_cedar_auth::test_utils::{TestCedarAuthBuilder, get_test_rex_principal};
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::io::is_container;
use rex_test_utils::network::parse_nslookup_output;
use rstest::rstest;
use rust_safe_system_info::{ResolveConfigBuilder, SystemInfo, TransportProtocol};
use std::process::Command;

/// Given: A hostname that resolves to multiple IP addresses
/// When: Both our DNS resolver and nslookup are used to resolve the hostname
/// Then: Both should return the same set of IP addresses
#[test]
#[cfg(target_os = "linux")]
fn test_dns_resolve_matches_nslookup() {
    if is_container() {
        return;
    }

    let hostname = "one.one.one.one";
    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"
            permit (
                principal == User::"{principal}",
                action == {},
                resource == sysinfo::Hostname::"{hostname}"
            );"#,
        SysinfoAction::ResolveHostname,
    );

    let cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let system_info = SystemInfo::new().unwrap();
    let config = ResolveConfigBuilder::default()
        .hostname(hostname)
        .build()
        .unwrap();
    let result = system_info.resolve(&cedar_auth, config);
    assert!(
        result.is_ok(),
        "Resolution should succeed: {:?}",
        result.unwrap_err()
    );

    let our_ips = result.unwrap();

    assert!(
        !our_ips.is_empty(),
        "Our resolver should return at least one IP for {}",
        hostname
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

    assert_eq!(our_ips_sorted, nslookup_ips_sorted);
}

/// Given: a hostname
/// When: resolution method is called and the user is not authorized
/// Then: an authorization error is returned
#[test]
fn test_resolve_hostname_unauthorized() {
    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"
            permit (
                principal == User::"randouser",
                action == {},
                resource
            );"#,
        SysinfoAction::ResolveHostname
    );

    let cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let system_info = SystemInfo::new().unwrap();

    let config = ResolveConfigBuilder::default()
        .hostname("one.one.one.one")
        .build()
        .unwrap();
    let result = system_info.resolve(&cedar_auth, config);

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        SysinfoAction::ResolveHostname
    );
    assert_error_contains(result, &expected_error);
}

/// Given: a hostname not in the policy
/// When: resolution method is called on the hostname with an authorized user but not authorized resource
/// Then: an authorization error is returned
#[test]
fn test_resolve_hostname_not_in_policy_unauthorized() {
    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"
            permit (
                principal == User::"{principal}",
                action == {},
                resource == sysinfo::Hostname::"www.example.com"
            );"#,
        SysinfoAction::ResolveHostname
    );

    let cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let system_info = SystemInfo::new().unwrap();

    let config = ResolveConfigBuilder::default()
        .hostname("one.one.one.one")
        .build()
        .unwrap();
    let result = system_info.resolve(&cedar_auth, config);

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        SysinfoAction::ResolveHostname
    );
    assert_error_contains(result, &expected_error);
}

/// Given: A policy with a wildcard
/// When: A request is made
/// Then: AuthZ allowed
#[test]
fn test_wildcard_hostname() {
    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"
            permit (
                principal == User::"{principal}",
                action == {},
                resource
            )
            when {{
                resource.hostname like "*host"
            }};
            "#,
        SysinfoAction::ResolveHostname
    );

    let cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let system_info = SystemInfo::new().unwrap();

    let config = ResolveConfigBuilder::default()
        .hostname("localhost")
        .build()
        .unwrap();
    let result = system_info.resolve(&cedar_auth, config);
    assert!(result.is_ok());
}

/// Given: A call to hostname()
/// When: policy does not allow access
/// Then: an authorization error is returned
#[test]
fn test_hostname_unauthorized() {
    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"
            permit (
                principal == User::"randouser",
                action == {},
                resource
            );"#,
        SysinfoAction::List
    );

    let cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let system_info = SystemInfo::new().unwrap();

    let result = system_info.hostname(&cedar_auth);

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        SysinfoAction::List
    );
    assert_error_contains(result, &expected_error);
}

/// Given: A call to hostname()
/// When: policy allows access
/// Then: Authorization allows successful call
#[test]
fn test_hostname_authorized() {
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

    let cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let system_info = SystemInfo::new().unwrap();

    let result = system_info.hostname(&cedar_auth);
    assert!(
        result.is_ok(),
        "getting hostname was not authorized: {}",
        result.unwrap_err()
    );
}

/// Given: localhost hostname with specified transport protocol
/// When: resolution is performed using Auto, UDP, or TCP protocol
/// Then: resolution succeeds and returns loopback addresses
#[rstest]
#[case(TransportProtocol::UDP, true)]
#[case(TransportProtocol::TCP, true)]
#[case(TransportProtocol::Auto, true)]
#[case(TransportProtocol::UDP, false)]
#[case(TransportProtocol::TCP, false)]
#[case(TransportProtocol::Auto, false)]
fn test_resolve_localhost_with_protocol(
    #[case] protocol: TransportProtocol,
    #[case] custom_resolver: bool,
) {
    let hostname = "localhost";
    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"
            permit (
                principal == User::"{principal}",
                action == {},
                resource == sysinfo::Hostname::"{hostname}"
            );"#,
        SysinfoAction::ResolveHostname,
    );

    let cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let system_info = SystemInfo::new().unwrap();
    let mut config_builder = ResolveConfigBuilder::default();
    config_builder.hostname(hostname).protocol(protocol);

    if custom_resolver {
        config_builder.resolver("8.8.8.8");
    }

    let config = config_builder.build().unwrap();

    let result = system_info.resolve(&cedar_auth, config);
    assert!(
        result.is_ok(),
        "Resolution should succeed with protocol {:?}: {:?}",
        protocol,
        result.as_ref().err()
    );

    let ips = result.unwrap();
    assert!(
        !ips.is_empty(),
        "Expected at least one IP address for localhost with protocol {:?}",
        protocol
    );

    // Verify all returned IPs are valid
    for ip in &ips {
        assert!(
            ip.parse::<std::net::IpAddr>().is_ok(),
            "Resolved address should be a valid IP: {}",
            ip
        );
    }

    // Verify at least one loopback address is present
    let has_ipv4_loopback = ips.iter().any(|ip| ip == "127.0.0.1");
    let has_ipv6_loopback = ips.iter().any(|ip| ip == "::1");

    assert!(
        has_ipv4_loopback || has_ipv6_loopback,
        "Expected at least one loopback address (127.0.0.1 or ::1) for localhost with protocol {:?}, got: {:?}",
        protocol,
        ips
    );
}

/// Given: A resolver that isn't an IP
/// When: Resolution is attempted
/// Then: There is an error
#[test]
#[cfg(unix)]
fn test_dns_resolve_invalid_ip() {
    let hostname = "one.one.one.one";
    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"
            permit (
                principal == User::"{principal}",
                action == {},
                resource == sysinfo::Hostname::"{hostname}"
            );"#,
        SysinfoAction::ResolveHostname,
    );

    let cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let system_info = SystemInfo::new().unwrap();
    let config = ResolveConfigBuilder::default()
        .hostname(hostname)
        .resolver("1.2.3.4.5.7")
        .build()
        .unwrap();
    let result = system_info.resolve(&cedar_auth, config);
    let expected_error = "invalid IP address syntax";
    assert_error_contains(result, &expected_error);
}
