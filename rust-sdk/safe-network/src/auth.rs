use anyhow::Result;
use cedar_policy::Decision;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::fs::entities::FileEntity;
use rex_cedar_auth::network::actions::NetworkAction;
use rex_cedar_auth::network::entities::NetworkEntity;
use rex_cedar_auth::{
    cedar_auth::{Action, CedarAuth, CedarRexEntity, UserEntity},
    users::Username,
};
use rust_sdk_common_utils::cedar_auth::is_authorized as cedar_is_authorized;

use crate::RustNetworkError;

pub(crate) fn is_authorized<T: Action>(
    cedar_auth: &CedarAuth,
    action: &T,
    resource: &dyn CedarRexEntity,
) -> Result<(), RustNetworkError> {
    cedar_is_authorized(cedar_auth, action, resource)
}

fn check_network_authorization<T: CedarRexEntity>(
    cedar_auth: &CedarAuth,
    action: NetworkAction,
    resource: &str,
    resource_type: &T,
) -> Result<(), RustNetworkError> {
    let user_entity = UserEntity::new(Username::get_username());

    let cedar_response =
        cedar_auth.check_network_permission(&user_entity, action, resource, resource_type);
    match cedar_response {
        Ok(Decision::Allow) => Ok(()),
        Ok(Decision::Deny) => Err(RustNetworkError::PermissionDenied {
            principal: user_entity.entity_id(),
            action: action.to_string(),
            resource_id: resource.to_string(),
        }),

        Err(_) => Err(RustNetworkError::AuthorizationError {
            principal: user_entity.entity_id(),
            action: action.to_string(),
            resource_id: resource.to_string(),
        }),
    }
}

pub(crate) fn is_authorized_url(
    cedar_auth: &CedarAuth,
    action: NetworkAction,
    url: &str,
) -> Result<(), RustNetworkError> {
    let entity = NetworkEntity::new(url.to_string());
    check_network_authorization(cedar_auth, action, &entity.cedar_eid(), &entity)
}

pub(crate) fn is_authorized_file(
    cedar_auth: &CedarAuth,
    action: FilesystemAction,
    file_path: &str,
) -> Result<(), RustNetworkError> {
    let file_entity = FileEntity::from_string_path(file_path)?;
    is_authorized(cedar_auth, &action, &file_entity)
}
