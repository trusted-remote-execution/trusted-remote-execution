//! # `CedarAuth`
//!
//! Cedar policy authorization for Rex. Provides entity types,
//! actions, and authorization checks for file system, process, systemd,
//! network, sysinfo, and sysctl operations.
//!
//! For a vendor-facing guide on writing Cedar policies, see the
//! [`cedar_policy_guide`] module.

/// Vendor-facing guide for writing Rex Cedar policies.
///
/// Covers namespaces, entity attributes, and example policies.
#[doc = include_str!("../CEDAR_POLICY_GUIDE.md")]
pub mod cedar_policy_guide {}

pub mod cedar_auth;
mod entities;
pub mod fs;
pub mod network;
pub mod process;
pub mod sysctl;
pub mod sysinfo;
pub mod systemd;
pub mod users;

#[cfg(feature = "test-utils")]
pub mod test_utils;
