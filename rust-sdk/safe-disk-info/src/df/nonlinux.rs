use super::common::{Filesystem, FilesystemProvider};
use crate::{FilesystemOptions, RustDiskinfoError};
use rex_cedar_auth::cedar_auth::CedarAuth;

#[derive(Debug, Clone, Copy)]
pub struct Df;

impl FilesystemProvider for Df {
    fn get_filesystems(
        &self,
        _cedar_auth: &CedarAuth,
        _config: &FilesystemOptions,
    ) -> Result<Vec<Filesystem>, RustDiskinfoError> {
        Err(RustDiskinfoError::UnsupportedOperationError {
            operation: "get_filesystems".to_string(),
            reason: "filesystem functionality is only available on Unix systems".to_string(),
        })
    }
}
