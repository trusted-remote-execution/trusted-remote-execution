//! Authorization helper for Cedar policy checks

use rex_cedar_auth::cedar_auth::{Action, CedarAuth, CedarRexEntity};
use rust_sdk_common_utils::cedar_auth::is_authorized as cedar_is_authorized;

use crate::errors::RustSafeProcessMgmtError;

/// Checks if a given principal has permission to perform an action on a process
///
/// This function performs Cedar authorization checks to determine if the current user
/// has permission to perform the specified action on the given process entity.
pub fn is_authorized<T: Action>(
    cedar_auth: &CedarAuth,
    action: &T,
    resource: &dyn CedarRexEntity,
) -> Result<(), RustSafeProcessMgmtError> {
    cedar_is_authorized(cedar_auth, action, resource)
}
