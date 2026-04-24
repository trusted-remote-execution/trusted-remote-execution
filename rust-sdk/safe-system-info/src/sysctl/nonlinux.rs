//! Non-Linux stub implementation for sysctl

use super::common::{SysctlEntry, SysctlProvider};
use crate::RustSysteminfoError;
use rex_cedar_auth::cedar_auth::CedarAuth;

/// Sysctl stub for non-Linux systems
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Sysctl;

impl Sysctl {
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn new() -> Result<Self, RustSysteminfoError> {
        Ok(Self)
    }
}

impl SysctlProvider for Sysctl {
    fn read(&self, _cedar_auth: &CedarAuth, _key: &str) -> Result<String, RustSysteminfoError> {
        Err(RustSysteminfoError::UnsupportedOperationError {
            reason: "Sysctl operations are only supported on Linux".to_string(),
        })
    }

    fn write(
        &self,
        _cedar_auth: &CedarAuth,
        _key: &str,
        _value: &str,
    ) -> Result<(), RustSysteminfoError> {
        Err(RustSysteminfoError::UnsupportedOperationError {
            reason: "sysctl operations are only supported on Linux".to_string(),
        })
    }

    fn load_system(&self, _cedar_auth: &CedarAuth) -> Result<(), RustSysteminfoError> {
        Err(RustSysteminfoError::UnsupportedOperationError {
            reason: "sysctl operations are only supported on Linux".to_string(),
        })
    }

    fn find(
        &self,
        _cedar_auth: &CedarAuth,
        _pattern: &str,
    ) -> Result<Vec<SysctlEntry>, RustSysteminfoError> {
        Err(RustSysteminfoError::UnsupportedOperationError {
            reason: "sysctl operations are only supported on Linux".to_string(),
        })
    }
}
