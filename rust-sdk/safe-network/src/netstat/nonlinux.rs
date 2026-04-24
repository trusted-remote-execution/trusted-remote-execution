//! Non-Linux stub implementation of netstat functionality

use super::common::NetworkStats;
use crate::errors::RustNetworkError;
use rex_cedar_auth::cedar_auth::CedarAuth;

/// Get network statistics on non-Linux platforms
///
/// This is a stub implementation that returns an error indicating
/// netstat functionality is only supported on Linux.
pub fn network_stats(_cedar_auth: &CedarAuth) -> Result<NetworkStats, RustNetworkError> {
    Err(RustNetworkError::UnsupportedOperationError {
        reason: "netstat functionality is only available on Linux systems".to_string(),
    })
}
