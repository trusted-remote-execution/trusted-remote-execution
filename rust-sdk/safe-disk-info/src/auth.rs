#[cfg(target_os = "linux")]
use crate::RustDiskinfoError;
#[cfg(target_os = "linux")]
use rex_cedar_auth::cedar_auth::{Action, CedarAuth, CedarRexEntity};
#[cfg(target_os = "linux")]
use rust_sdk_common_utils::cedar_auth::is_authorized as cedar_is_authorized;

#[cfg(target_os = "linux")]
pub(crate) fn is_authorized<T: Action>(
    cedar_auth: &CedarAuth,
    action: &T,
    resource: &dyn CedarRexEntity,
) -> Result<(), RustDiskinfoError> {
    cedar_is_authorized(cedar_auth, action, resource)
}
