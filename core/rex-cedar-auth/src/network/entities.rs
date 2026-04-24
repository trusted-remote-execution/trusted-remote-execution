use crate::cedar_auth::CedarRexEntity;
use crate::network::types::EntityType::Url;
use anyhow::Result;
use cedar_policy::RestrictedExpression;
use std::collections::HashMap;

/// Represents a network entity
///
/// # Attributes
///
/// | Attribute | Type | Description |
/// |-----------|------|-------------|
/// | `url` | `String` | Target URL |
///
/// # Example Policy
///
/// ```cedar
/// // Unrestricted access to all URLs
/// permit(
///   principal,
///   action,
///   resource is network::url
/// );
///
/// // Scoped to health endpoints
/// permit(
///   principal,
///   action == network::Action::"GET",
///   resource is network::url
/// ) when {
///   resource.url like "https://*/health"
/// };
/// ```
#[derive(Clone, Debug, Default)]
pub struct NetworkEntity {
    url: String,
}

impl NetworkEntity {
    pub const fn new(url: String) -> Self {
        Self { url }
    }
}

impl CedarRexEntity for NetworkEntity {
    fn entity_id(&self) -> String {
        self.url.clone()
    }

    fn entity_name(&self) -> String {
        Url.to_string()
    }

    fn parents(&self) -> Vec<&dyn CedarRexEntity> {
        Vec::new()
    }

    fn get_attrs(&self) -> Result<HashMap<String, RestrictedExpression>> {
        let mut attrs = HashMap::new();
        attrs.insert(
            "url".to_string(),
            RestrictedExpression::new_string(self.url.clone()),
        );
        Ok(attrs)
    }
}

#[cfg(test)]
mod tests {
    use crate::{cedar_auth::CedarRexEntity, network::entities::NetworkEntity};

    /// Given: URL
    /// When: Creating a network entity
    /// Then: The entity should have the correct attributes and entity ID
    #[test]
    fn test_process_entity_creation() {
        let url = "https://www.example.com/health";
        let entity = NetworkEntity::new(url.to_string());

        assert_eq!(entity.entity_name(), "network::url");
        assert_eq!(entity.entity_id(), url);
        assert!(entity.parents().is_empty());

        let attrs = entity.get_attrs().unwrap();
        assert_eq!(attrs.len(), 1);
        assert!(attrs.contains_key("url"), "name not in {attrs:?}");
    }
}
