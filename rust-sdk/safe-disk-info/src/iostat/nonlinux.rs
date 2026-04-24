use super::common::{IoStatProvider, IoStatSnapshot};
use crate::RustDiskinfoError;
use rex_cedar_auth::cedar_auth::CedarAuth;

#[derive(Debug, Clone, Copy)]
pub struct IoStat;

impl IoStatProvider for IoStat {
    fn get_snapshot(&self, _cedar_auth: &CedarAuth) -> Result<IoStatSnapshot, RustDiskinfoError> {
        Err(RustDiskinfoError::UnsupportedOperationError {
            operation: "get_snapshot".to_string(),
            reason: "iostat functionality is only available on Linux systems".to_string(),
        })
    }
}
