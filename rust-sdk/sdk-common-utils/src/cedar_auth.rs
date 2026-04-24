//! Shared Cedar authorization helper for all Rust-layer SDK packages.

use cedar_policy::Decision;
use rex_cedar_auth::cedar_auth::{
    Action, AuthContextBuilder, CedarAuth, CedarRexEntity, UserEntity,
};
use rex_cedar_auth::users::Username;
use rex_logger::error;

/// Trait that a package's error type implements to use the shared [`is_authorized`] helper.
pub trait CedarAuthorizationError: Sized {
    fn permission_denied(
        principal: String,
        action: String,
        resource_type: String,
        resource_id: String,
    ) -> Self;

    fn authorization_error(
        principal: String,
        action: String,
        resource_type: String,
        resource_id: String,
    ) -> Self;
}

/// Generic Cedar authorization check shared across all Rust-layer SDK packages.
///
/// Builds a Cedar authorization context from the current OS user, the given action,
/// and the given resource, then delegates to [`CedarAuth::is_authorized`].
///
/// # Errors
///
/// Returns [`CedarAuthorizationError::permission_denied`] if Cedar denies the request.
/// Returns [`CedarAuthorizationError::authorization_error`] if Cedar returns an error
/// or if the authorization context cannot be constructed.
///
/// # Examples
///
/// ```no_run
/// use rust_sdk_common_utils::cedar_auth::{is_authorized, CedarAuthorizationError};
/// use rex_cedar_auth::cedar_auth::CedarAuth;
/// ```
pub fn is_authorized<T, E>(
    cedar_auth: &CedarAuth,
    action: &T,
    resource: &dyn CedarRexEntity,
) -> Result<(), E>
where
    T: Action,
    E: CedarAuthorizationError + From<anyhow::Error>,
{
    is_authorized_with_context(cedar_auth, action, resource, &serde_json::json!({}))
}

pub fn is_authorized_with_context<T, E>(
    cedar_auth: &CedarAuth,
    action: &T,
    resource: &dyn CedarRexEntity,
    additional_context: &serde_json::Value,
) -> Result<(), E>
where
    T: Action,
    E: CedarAuthorizationError + From<anyhow::Error>,
{
    let principal = Username::get_username();
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
        .context(additional_context.clone())
        .build()
        .map_err(|_| {
            E::authorization_error(
                principal.clone(),
                action.to_string(),
                resource.entity_name(),
                resource.entity_id(),
            )
        })?;

    let cedar_response = cedar_auth.is_authorized(auth_context);
    match cedar_response {
        Ok(Decision::Allow) => Ok(()),
        Ok(Decision::Deny) => Err(E::permission_denied(
            principal,
            action.to_string(),
            resource.entity_name(),
            resource.entity_id(),
        )),
        Err(e) => {
            error!("Authorization check failed: {e}");
            Err(E::authorization_error(
                principal,
                action.to_string(),
                resource.entity_name(),
                resource.entity_id(),
            ))
        }
    }
}
