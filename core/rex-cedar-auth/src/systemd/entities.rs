use crate::cedar_auth::CedarRexEntity;
use crate::systemd::types::EntityType::{Service, Systemd};
use anyhow::Result;
use cedar_policy::RestrictedExpression;
use std::collections::HashMap;
use uuid::Uuid;

/// Represents a systemd service entity.
///
/// # Attributes
///
/// | Attribute | Type | Description |
/// |-----------|------|-------------|
/// | `name` | `String` | Unit name (e.g. `nginx.service`) |
///
/// # Example Policy
///
/// ```cedar
/// // Unrestricted access to all services
/// permit(
///   principal,
///   action,
///   resource is systemd::Service
/// );
///
/// // Scoped to a specific service
/// permit(
///   principal,
///   action == systemd::Action::"restart",
///   resource is systemd::Service
/// ) when {
///   resource.name == "nginx.service"
/// };
/// ```
#[derive(Clone, Debug, Default)]
pub struct ServiceEntity {
    name: String,
}

/// Represents the systemd daemon.
///
/// No attributes — singleton resource used for daemon-level actions like `daemon_reload`.
///
/// # Example Policy
///
/// ```cedar
/// // Unrestricted access to systemd daemon
/// permit(
///   principal,
///   action,
///   resource is systemd::Systemd
/// );
///
/// // Scoped to daemon_reload only
/// permit(
///   principal,
///   action == systemd::Action::"daemon_reload",
///   resource is systemd::Systemd
/// );
/// ```
#[derive(Clone, Debug, Default)]
pub struct SystemdEntity {
    id: String,
}

impl ServiceEntity {
    pub const fn new(name: String) -> Self {
        Self { name }
    }
}

impl SystemdEntity {
    pub fn new() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
        }
    }
}

impl CedarRexEntity for ServiceEntity {
    fn entity_id(&self) -> String {
        self.name.clone()
    }

    fn entity_name(&self) -> String {
        Service.to_string()
    }

    /// Systemd services are represented without parent-child relationships
    fn parents(&self) -> Vec<&dyn CedarRexEntity> {
        Vec::new()
    }

    /// Returns the attributes of this entity
    fn get_attrs(&self) -> Result<HashMap<String, RestrictedExpression>> {
        let mut attrs = HashMap::new();
        attrs.insert(
            "name".to_string(),
            RestrictedExpression::new_string(self.name.clone()),
        );
        Ok(attrs)
    }
}

impl CedarRexEntity for SystemdEntity {
    fn entity_id(&self) -> String {
        self.id.clone()
    }

    fn entity_name(&self) -> String {
        Systemd.to_string()
    }

    fn parents(&self) -> Vec<&dyn CedarRexEntity> {
        Vec::new()
    }

    fn get_attrs(&self) -> Result<HashMap<String, RestrictedExpression>> {
        // Systemd entity has no attributes, just a UUID
        Ok(HashMap::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cedar_auth::CedarRexEntity;

    /// Given: Systemd Service information
    /// When: Creating a Service Entity
    /// Then: The entity should have the correct attributes and entity ID
    #[test]
    fn test_service_entity_creation() {
        let service_name = "nginx.service";
        let entity = ServiceEntity::new(service_name.to_string());

        assert_eq!(entity.entity_name(), "systemd::Service");
        assert_eq!(entity.entity_id(), service_name);
        assert!(entity.parents().is_empty());

        let attrs = entity.get_attrs().unwrap();
        assert_eq!(attrs.len(), 1);
        assert!(attrs.contains_key("name"));
    }

    /// Given: Systemd information
    /// When: Creating a Systemd Entity
    /// Then: The entity should have the correct attributes and entity ID
    #[test]
    fn test_systemd_entity_creation() {
        let entity = SystemdEntity::new();

        assert_eq!(entity.entity_name(), "systemd::Systemd");
        assert!(!entity.entity_id().is_empty());
        assert!(entity.parents().is_empty());

        let attrs = entity.get_attrs().unwrap();
        assert_eq!(attrs.len(), 0);
    }
}
