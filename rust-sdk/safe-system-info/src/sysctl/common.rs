//! Common trait for sysctl operations

use crate::RustSysteminfoError;
use derive_getters::Getters;
use rex_cedar_auth::cedar_auth::CedarAuth;
use serde::Serialize;

/// Represents a single sysctl parameter entry
#[derive(Debug, Clone, Getters, Serialize)]
pub struct SysctlEntry {
    /// Parameter name in dot notation (e.g., "kernel.hostname")
    pub(crate) key: String,
    /// Parameter value
    pub(crate) value: String,
}

impl SysctlEntry {
    /// Creates a new `SysctlEntry`
    pub fn new(key: String, value: String) -> Self {
        Self { key, value }
    }
}

/// Internal trait to ensure platform implementations are aligned.
/// This is not meant to be externally published.
pub(crate) trait SysctlProvider {
    /// Reads a kernel parameter value
    fn read(&self, cedar_auth: &CedarAuth, key: &str) -> Result<String, RustSysteminfoError>;

    /// Writes a kernel parameter value
    fn write(
        &self,
        cedar_auth: &CedarAuth,
        key: &str,
        value: &str,
    ) -> Result<(), RustSysteminfoError>;

    /// Loads sysctl settings from system configuration files
    fn load_system(&self, cedar_auth: &CedarAuth) -> Result<(), RustSysteminfoError>;

    /// Finds sysctl parameters matching the given regex pattern
    fn find(
        &self,
        cedar_auth: &CedarAuth,
        pattern: &str,
    ) -> Result<Vec<SysctlEntry>, RustSysteminfoError>;
}
