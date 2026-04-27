//! Configuration options for system information operations
//!
//! This module provides configuration structs for various system information
//! operations, each implementing a builder pattern with chainable methods.

use derive_builder::Builder;

/// Configuration parameters for reading kernel ring buffer messages
///
/// # Examples
///
/// ```no_run
/// use rust_safe_system_info::options::DmesgOptionsBuilder;
///
/// let dmesg_options = DmesgOptionsBuilder::default()
///     .human_readable_time(true)
///     .build()
///     .unwrap();
/// ```
#[derive(Builder, Debug, Clone, Copy)]
#[builder(derive(Debug))]
pub struct DmesgOptions {
    /// A bool indicating whether timestamps should be displayed in human-readable format (default: false)
    #[builder(default = "false")]
    pub human_readable_time: bool,
}

/// Protocol to use for resolution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum TransportProtocol {
    /// Automatically choose protocol (UDP with TCP fallback on truncation) - dig default behavior
    #[default]
    Auto,
    /// Force UDP only
    UDP,
    /// Force TCP only
    TCP,
}

/// DNS resolver to use for resolution
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum DnsResolver {
    /// Use system default resolver (from /etc/resolv.conf or OS configuration)
    #[default]
    System,
    /// Use a specific DNS server IP address
    Custom(String),
}

impl From<String> for DnsResolver {
    fn from(ip: String) -> Self {
        DnsResolver::Custom(ip)
    }
}

impl From<&str> for DnsResolver {
    fn from(ip: &str) -> Self {
        DnsResolver::Custom(ip.to_string())
    }
}

/// Configuration parameters for DNS hostname resolution
///
/// # Examples
///
/// ```no_run
/// use rust_safe_system_info::options::{ResolveConfigBuilder, TransportProtocol, DnsResolver};
///
/// // Simple case - use all defaults
/// let config = ResolveConfigBuilder::default()
///     .hostname("example.com")
///     .build()
///     .unwrap();
///
/// // Override resolver to use Google DNS (accepts string directly)
/// let config = ResolveConfigBuilder::default()
///     .hostname("example.com")
///     .resolver("8.8.8.8")
///     .build()
///     .unwrap();
///
/// // Force TCP protocol
/// let config = ResolveConfigBuilder::default()
///     .hostname("example.com")
///     .protocol(TransportProtocol::TCP)
///     .build()
///     .unwrap();
/// ```
#[derive(Builder, Debug, Clone)]
#[builder(derive(Debug))]
pub struct ResolveConfig {
    /// The hostname to resolve (required)
    #[builder(setter(into))]
    pub hostname: String,

    /// DNS protocol to use (default: Auto - UDP with TCP fallback)
    #[builder(default = "TransportProtocol::Auto")]
    pub protocol: TransportProtocol,

    /// DNS resolver to use (default: System - use system default resolver)
    #[builder(default = "DnsResolver::System", setter(into))]
    pub resolver: DnsResolver,

    /// DNS query timeout in seconds (default: 5)
    #[builder(default = "5")]
    pub timeout: u64,
}
