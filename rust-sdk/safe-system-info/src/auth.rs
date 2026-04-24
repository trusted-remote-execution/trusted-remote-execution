use crate::RustSysteminfoError;

use anyhow::Result;
use cedar_policy::Decision;
use rex_cedar_auth::cedar_auth::Action;
use rex_cedar_auth::sysinfo::actions::SysinfoAction;
use rex_cedar_auth::sysinfo::entities::{HostnameEntity, SysinfoEntity};
use rex_cedar_auth::{
    cedar_auth::{CedarAuth, CedarRexEntity, UserEntity},
    users::Username,
};
use rust_sdk_common_utils::cedar_auth::is_authorized as cedar_is_authorized;

fn check_sysinfo_authorization<T: CedarRexEntity>(
    cedar_auth: &CedarAuth,
    action: SysinfoAction,
    resource: &str,
    resource_type: &T,
) -> Result<(), RustSysteminfoError> {
    let user_entity = UserEntity::new(Username::get_username());
    let resource_type_str = resource_type.entity_name().clone();
    let cedar_response =
        cedar_auth.check_sysinfo_permission(&user_entity, action, resource, resource_type);
    match cedar_response {
        Ok(Decision::Allow) => Ok(()),
        Ok(Decision::Deny) => Err(RustSysteminfoError::PermissionDenied {
            principal: user_entity.entity_id(),
            action: action.to_string(),
            resource_type: resource_type_str,
            resource_id: resource.to_string(),
        }),

        Err(_) => Err(RustSysteminfoError::AuthorizationError {
            principal: user_entity.entity_id(),
            action: action.to_string(),
            resource_type: resource_type_str,
            resource_id: resource.to_string(),
        }),
    }
}

pub(crate) fn is_authorized_hostname_lookup(
    cedar_auth: &CedarAuth,
    hostname: &str,
) -> Result<(), RustSysteminfoError> {
    let entity = HostnameEntity::new(hostname.to_string());
    check_sysinfo_authorization(
        cedar_auth,
        SysinfoAction::ResolveHostname,
        &entity.cedar_eid(),
        &entity,
    )
}

pub fn is_authorized_sysinfo(cedar_auth: &CedarAuth) -> Result<(), RustSysteminfoError> {
    let sysinfo_entity = SysinfoEntity::new();
    let resource = sysinfo_entity.cedar_eid();
    check_sysinfo_authorization(
        cedar_auth,
        SysinfoAction::List,
        &resource,
        &SysinfoEntity::new(),
    )
}

pub(crate) fn is_authorized<T: Action>(
    cedar_auth: &CedarAuth,
    action: &T,
    resource: &dyn CedarRexEntity,
) -> Result<(), RustSysteminfoError> {
    cedar_is_authorized(cedar_auth, action, resource)
}
