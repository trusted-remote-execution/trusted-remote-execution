use crate::cedar_auth::CedarRexEntity;
use crate::sysinfo::types::EntityType::{Hostname, Sysinfo};
use anyhow::Result;
use cedar_policy::RestrictedExpression;
use std::collections::HashMap;
use uuid::Uuid;

/// Represents a entity in the Cedar authorization system
///
/// No attributes — singleton resource used for system info queries.
///
/// # Example Policy
///
/// ```cedar
/// permit(
///   principal,
///   action,
///   resource is sysinfo::Sysinfo
/// );
/// ```
#[derive(Clone, Debug, Default)]
pub struct SysinfoEntity {
    id: String,
}

/// Represents a hostname entity in DNS
///
/// # Attributes
///
/// | Attribute | Type | Description |
/// |-----------|------|-------------|
/// | `hostname` | `String` | DNS hostname |
///
/// # Example Policy
///
/// ```cedar
/// permit(
///   principal,
///   action == sysinfo::Action::"resolve_hostname",
///   resource is sysinfo::Hostname
/// ) when {
///   resource.hostname like "*host"
/// };
/// ```
#[derive(Clone, Debug, Default)]
pub struct HostnameEntity {
    hostname: String,
}

impl SysinfoEntity {
    pub fn new() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
        }
    }
}

impl HostnameEntity {
    pub const fn new(hostname: String) -> Self {
        Self { hostname }
    }
}

impl CedarRexEntity for SysinfoEntity {
    fn entity_id(&self) -> String {
        self.id.clone()
    }

    fn entity_name(&self) -> String {
        Sysinfo.to_string()
    }

    /// Sysinfo entities are represented without parent-child relationships in this Cedar authorization model.
    fn parents(&self) -> Vec<&dyn CedarRexEntity> {
        Vec::new()
    }

    /// Returns the attributes of this process entity (none for Sysinfo)
    fn get_attrs(&self) -> Result<HashMap<String, RestrictedExpression>> {
        Ok(HashMap::new())
    }
}

impl CedarRexEntity for HostnameEntity {
    fn entity_id(&self) -> String {
        self.hostname.clone()
    }

    fn entity_name(&self) -> String {
        Hostname.to_string()
    }

    /// Systemd services are represented without parent-child relationships
    fn parents(&self) -> Vec<&dyn CedarRexEntity> {
        Vec::new()
    }

    /// Returns the attributes of this entity
    fn get_attrs(&self) -> Result<HashMap<String, RestrictedExpression>> {
        let mut attrs = HashMap::new();
        attrs.insert(
            "hostname".to_string(),
            RestrictedExpression::new_string(self.hostname.clone()),
        );
        Ok(attrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cedar_auth::CedarRexEntity;

    /// Given: Sysinfo information
    /// When: Creating a SysinfoEntity
    /// Then: The entity should have the correct attributes and entity ID
    #[test]
    fn test_process_entity_creation() {
        let entity = SysinfoEntity::new();

        assert_eq!(entity.entity_name(), "sysinfo::Sysinfo");
        assert!(entity.parents().is_empty());
        assert!(
            Uuid::parse_str(&entity.entity_id()).is_ok(),
            "Entity ID should be a valid UUID"
        );
        assert!(entity.get_attrs().unwrap().is_empty());
    }

    /// Given: Hostname
    /// When: Creating a Hostname Entity
    /// Then: The entity should have the correct attributes and entity ID
    #[test]
    fn test_service_entity_creation() {
        let hostname = "www.example.com";
        let entity = HostnameEntity::new(hostname.to_string());

        assert_eq!(entity.entity_name(), "sysinfo::Hostname");
        assert_eq!(entity.entity_id(), hostname);
        assert!(entity.parents().is_empty());

        let attrs = entity.get_attrs().unwrap();
        assert_eq!(attrs.len(), 1);
        assert!(attrs.contains_key("hostname"), "name not in {attrs:?}");
    }
}
