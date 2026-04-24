use crate::errors::RustSafeIoError;

use rex_cedar_auth::cedar_auth::{
    Action, AuthContextBuilder, CedarAuth, CedarRexEntity, Decision, Entity, UserEntity,
};
use rex_cedar_auth::users::Username;

use rex_logger::error;
use rust_sdk_common_utils::cedar_auth::{
    is_authorized as cedar_is_authorized,
    is_authorized_with_context as cedar_is_authorized_with_context,
};

/// Helper function to build authorization error with context
fn build_auth_error<'a, E>(
    resource: &'a dyn CedarRexEntity,
    principal: &'a str,
    action: &'a str,
) -> impl Fn(E) -> RustSafeIoError + 'a {
    move |_| RustSafeIoError::AuthorizationError {
        principal: principal.to_string(),
        action: action.to_string(),
        resource_type: resource.entity_name(),
        resource_id: resource.entity_id(),
    }
}

/// Checks if a given principal has permission to perform an action on a resource with context entities
///
/// This function allows passing Cedar context entities and additional context information to the Cedar authorization request,
/// which can be used by policy constraints to make more informed decisions.
///
pub(crate) fn is_authorized_with_context_entities<T: Action>(
    cedar_auth: &CedarAuth,
    action: &T,
    resource: &dyn CedarRexEntity,
    context_entities_vec: Option<Vec<(String, Entity)>>,
    additional_context: &serde_json::Value,
) -> Result<(), RustSafeIoError> {
    let principal = Username::get_username();

    let context_entities = context_entities_vec.unwrap_or_default();

    let auth_context = AuthContextBuilder::default()
        .principal(
            UserEntity::new(String::from(&principal))
                .to_cedar_entity()?
                .uid()
                .to_string(),
        )
        .action(action.to_string())
        .resource(resource.to_cedar_entity()?.uid().to_string())
        .entities(resource.to_cedar_entities()?)
        .context_entities(context_entities)
        .context(additional_context.clone())
        .build()
        .map_err(build_auth_error(resource, &principal, &action.to_string()))?;
    let cedar_response = cedar_auth.is_authorized(auth_context);
    match cedar_response {
        Ok(Decision::Allow) => Ok(()),
        Ok(Decision::Deny) => Err(RustSafeIoError::PermissionDenied {
            principal,
            action: action.to_string(),
            resource_type: resource.entity_name(),
            resource_id: resource.entity_id(),
            move_details: None,
        }),
        Err(e) => {
            error!("Authorization check failed: {e}");
            Err(build_auth_error(resource, &principal, &action.to_string())(
                e,
            ))
        }
    }
}

/// Checks if a given principal has permission to perform an action on a resource with additional context
///
/// This function allows passing additional context information to the Cedar authorization request,
/// which can be used by policy constraints to make more informed decisions.
///
pub(crate) fn is_authorized_with_context<T: Action>(
    cedar_auth: &CedarAuth,
    action: &T,
    resource: &dyn CedarRexEntity,
    additional_context: &serde_json::Value,
) -> Result<(), RustSafeIoError> {
    cedar_is_authorized_with_context(cedar_auth, action, resource, additional_context)
}

/// Checks if a given principal has permission to perform an action on a resource
pub(crate) fn is_authorized<T: Action>(
    cedar_auth: &CedarAuth,
    action: &T,
    resource: &dyn CedarRexEntity,
) -> Result<(), RustSafeIoError> {
    cedar_is_authorized(cedar_auth, action, resource)
}
