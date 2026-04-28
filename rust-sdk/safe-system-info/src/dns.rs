//! DNS related implementations
//!
//! Provides access to hostname resolution and other DNS utilities
//! for UNIX and Windows.

use crate::RustSysteminfoError;
use crate::options::{DnsResolver, ResolveConfig, TransportProtocol};
use hickory_proto::xfer::Protocol;
use hickory_resolver::config::{LookupIpStrategy, NameServerConfig, ResolverConfig};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::system_conf::read_system_conf;
use hickory_resolver::{ResolveError, ResolveErrorKind, TokioResolver};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use sysinfo::System;
use tokio::runtime::Builder;

#[derive(Debug, Copy, Clone)]
pub(crate) struct DNSInfo;

const DNS_PORT: u16 = 53;

impl DNSInfo {
    /// Resolve hostname provided in config
    pub(crate) fn resolve(config: &ResolveConfig) -> Result<Vec<String>, RustSysteminfoError> {
        // Create a single-threaded tokio runtime

        let rt = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| RustSysteminfoError::DnsResolutionError {
                hostname: config.hostname.clone(),
                reason: format!("Failed to create tokio runtime: {e}"),
                kind: None,
            })?;

        // Perform DNS resolution - the resolver's timeout configuration handles timing out
        rt.block_on(async { Self::async_resolve(config).await })
    }

    /// Returns the hostname where this API is invoked
    pub(crate) fn hostname() -> Result<String, RustSysteminfoError> {
        System::host_name().map_or_else(
            || {
                Err(RustSysteminfoError::HostnameError {
                    reason: "Failed to get hostname".to_string(),
                })
            },
            Ok,
        )
    }

    async fn async_resolve(config: &ResolveConfig) -> Result<Vec<String>, RustSysteminfoError> {
        let resolver = Self::build_resolver(config)?;
        let lookup_result = resolver.lookup_ip(&config.hostname).await;

        match lookup_result {
            Ok(lookup) => {
                let mut ips: Vec<String> = lookup.iter().map(|ip| ip.to_string()).collect();
                ips.sort();
                ips.dedup();

                Ok(ips)
            }
            Err(e) => Err(Self::convert_resolve_error(&config.hostname, &e)),
        }
    }

    fn build_resolver(config: &ResolveConfig) -> Result<TokioResolver, RustSysteminfoError> {
        let resolver_config = match &config.resolver {
            DnsResolver::System => {
                let (sys_config, _sys_options) =
                    read_system_conf().map_err(|e| RustSysteminfoError::DnsResolutionError {
                        hostname: config.hostname.clone(),
                        reason: format!("Failed to read system configuration: {e}"),
                        kind: None,
                    })?;

                if matches!(config.protocol, TransportProtocol::Auto) {
                    sys_config
                } else {
                    let filtered_nameservers: Vec<NameServerConfig> = sys_config
                        .name_servers()
                        .iter()
                        .filter(|ns| match config.protocol {
                            TransportProtocol::UDP => ns.protocol == Protocol::Udp,
                            TransportProtocol::TCP => ns.protocol == Protocol::Tcp,
                            // fallback
                            TransportProtocol::Auto => true,
                        })
                        .cloned()
                        .collect();

                    ResolverConfig::from_parts(
                        sys_config.domain().cloned(),
                        sys_config.search().to_vec(),
                        filtered_nameservers,
                    )
                }
            }
            DnsResolver::Custom(ip) => {
                let resolver_ip: IpAddr =
                    ip.parse()
                        .map_err(|e| RustSysteminfoError::DnsResolutionError {
                            hostname: config.hostname.clone(),
                            reason: format!("failed to parse resolver IP address: {e}"),
                            kind: None,
                        })?;

                let mut resolver_config = ResolverConfig::new();

                let socket_addr = SocketAddr::new(resolver_ip, DNS_PORT);

                match config.protocol {
                    TransportProtocol::Auto => {
                        resolver_config
                            .add_name_server(NameServerConfig::new(socket_addr, Protocol::Udp));
                        resolver_config
                            .add_name_server(NameServerConfig::new(socket_addr, Protocol::Tcp));
                    }
                    TransportProtocol::UDP => {
                        resolver_config
                            .add_name_server(NameServerConfig::new(socket_addr, Protocol::Udp));
                    }
                    TransportProtocol::TCP => {
                        resolver_config
                            .add_name_server(NameServerConfig::new(socket_addr, Protocol::Tcp));
                    }
                }

                resolver_config
            }
        };

        let mut builder =
            TokioResolver::builder_with_config(resolver_config, TokioConnectionProvider::default());
        let opts = builder.options_mut();
        // the builder defaults to Ipv4thenIpv6, but we want both
        opts.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
        opts.timeout = Duration::from_secs(config.timeout);

        Ok(builder.build())
    }

    fn convert_resolve_error(hostname: &str, error: &ResolveError) -> RustSysteminfoError {
        let (reason, kind) = match error.kind() {
            ResolveErrorKind::Msg(msg) => (msg.clone(), None),
            ResolveErrorKind::Message(msg) => ((*msg).to_string(), None),
            ResolveErrorKind::Proto(proto_error) => {
                let reason = format!("{proto_error}");
                let kind = Some(Box::new((*proto_error.kind).clone()));
                (reason, kind)
            }
            _ => (format!("{error}"), None),
        };

        RustSysteminfoError::DnsResolutionError {
            hostname: hostname.to_string(),
            reason,
            kind,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::DNSInfo;
    use crate::options::{ResolveConfigBuilder, TransportProtocol};
    use rex_test_utils::assertions::assert_error_contains;
    use rex_test_utils::io::is_container;

    /// Given: A valid hostname with default config
    /// When: The resolve function is called with the hostname
    /// Then: It returns multiple resolved IP addresses
    #[test]
    fn test_dns_resolve() {
        if is_container() {
            return;
        }

        let config = ResolveConfigBuilder::default()
            .hostname("one.one.one.one")
            .build()
            .unwrap();

        let result = DNSInfo::resolve(&config);
        assert!(
            result.is_ok(),
            "Expected successful DNS resolution: err: {:?}",
            result.unwrap_err()
        );

        let ips = result.unwrap();

        assert!(!ips.is_empty(), "Expected resolved IP addresses");

        for ip in &ips {
            assert!(
                ip.parse::<std::net::IpAddr>().is_ok(),
                "Resolved address should be a valid IP: {}",
                ip
            );
        }

        assert!(
            ips.len() >= 1,
            "Expected at least 1 IP address, got {}",
            ips.len()
        );
    }

    /// Given: A very short timeout duration (1 nanosecond)
    /// When: The resolve_with_timeout function is called with a valid hostname
    /// Then: It returns a DnsTimeout error because the timeout expires before resolution completes
    #[test]
    fn test_dns_resolve_timeout() {
        let config = ResolveConfigBuilder::default()
            .hostname("WWW.example.com")
            // Use an extremely short timeout that will expire before DNS resolution completes
            .timeout(0)
            .resolver("8.8.8.8")
            .build()
            .unwrap();

        let result = DNSInfo::resolve(&config);

        let expected_error = "request timed out";
        assert_error_contains(result, &expected_error);
    }

    /// Given: A hostname that does not resolve
    /// When: The resolve function processes the result
    /// Then: It returns an error
    #[test]
    fn test_dns_fail_resolve() {
        if is_container() {
            return;
        }

        let config = ResolveConfigBuilder::default()
            .hostname("this-hostname-does-not-exist-12345.invalid")
            .build()
            .unwrap();

        let result = DNSInfo::resolve(&config);
        let expected_error = "DNS resolution failed";
        assert_error_contains(result, &expected_error);
    }

    /// Given: A custom DNS resolver
    /// When: Resolution is performed using a custom resolver
    /// Then: It resolves correctly
    #[test]
    #[cfg(target_os = "linux")]
    #[ignore = "Requires a DNS server at 127.53.53.53 which may not be available in all environments"]
    fn test_dns_resolve_custom_resolver() {
        if is_container() {
            return;
        }

        let config = ResolveConfigBuilder::default()
            .hostname("one.one.one.one")
            .resolver("127.53.53.53")
            .build()
            .unwrap();

        let result = DNSInfo::resolve(&config);
        assert!(
            result.is_ok(),
            "Expected successful DNS resolution with custom resolver: err: {:?}",
            result.unwrap_err()
        );

        let ips = result.unwrap();
        assert!(!ips.is_empty(), "Expected resolved IP addresses");
    }

    /// Given: TCP protocol specified
    /// When: Resolution is performed
    /// Then: It resolves correctly using TCP
    #[test]
    fn test_dns_resolve_tcp() {
        if is_container() {
            return;
        }

        let config = ResolveConfigBuilder::default()
            .hostname("one.one.one.one")
            .protocol(TransportProtocol::TCP)
            .build()
            .unwrap();

        let result = DNSInfo::resolve(&config);
        assert!(
            result.is_ok(),
            "Expected successful DNS resolution with TCP: err: {:?}",
            result.unwrap_err()
        );

        let ips = result.unwrap();
        assert!(!ips.is_empty(), "Expected resolved IP addresses");
    }

    /// Given: A call to hostname()
    /// When: The function is called
    /// Then: The hostname is returned
    #[test]
    fn test_dns_hostname() {
        if is_container() {
            return;
        }

        let result = DNSInfo::hostname();
        assert!(
            result.is_ok(),
            "Expected successful hostname call: err: {:?}",
            result.unwrap_err()
        );

        let hostname = result.unwrap();

        assert!(!hostname.is_empty(), "Expected hostname");
    }
}
