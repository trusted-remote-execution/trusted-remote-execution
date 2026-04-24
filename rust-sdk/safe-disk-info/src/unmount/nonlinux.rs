use rex_cedar_auth::cedar_auth::CedarAuth;

use crate::errors::RustDiskinfoError;
use crate::options::UnmountOptions;

#[allow(clippy::needless_pass_by_value)]
pub fn unmount(_cedar_auth: &CedarAuth, _options: UnmountOptions) -> Result<(), RustDiskinfoError> {
    Err(RustDiskinfoError::UnsupportedOperationError {
        operation: "unmount".to_string(),
        reason: "unmount functionality is only available on Linux systems".to_string(),
    })
}
