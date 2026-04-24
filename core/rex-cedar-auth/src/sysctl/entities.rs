use crate::cedar_auth::CedarRexEntity;
use crate::sysctl::types::EntityType::Sysctl;
use anyhow::Result;
use cedar_policy::RestrictedExpression;
use std::collections::HashMap;
use uuid::Uuid;

/// Represents a sysctl entity in the Cedar authorization system
///
/// No attributes — singleton resource used for sysctl operations.
///
/// # Example Policy
///
/// ```cedar
/// permit(
///   principal,
///   action == sysctl::Action::"load",
///   resource is sysctl::Sysctl
/// );
/// ```
#[derive(Clone, Debug, Default)]
pub struct SysctlEntity {
    id: String,
}

impl SysctlEntity {
    pub fn new() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
        }
    }
}

impl CedarRexEntity for SysctlEntity {
    fn entity_id(&self) -> String {
        self.id.clone()
    }

    fn entity_name(&self) -> String {
        Sysctl.to_string()
    }

    /// Sysctl entities are represented without parent-child relationships in this Cedar authorization model.
    fn parents(&self) -> Vec<&dyn CedarRexEntity> {
        Vec::new()
    }

    /// Returns the attributes of this entity (none for Sysctl)
    fn get_attrs(&self) -> Result<HashMap<String, RestrictedExpression>> {
        Ok(HashMap::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cedar_auth::CedarRexEntity;

    /// Given: Sysctl information
    /// When: Creating a SysctlEntity
    /// Then: The entity should have the correct attributes and entity ID
    #[test]
    fn test_sysctl_entity_creation() {
        let entity = SysctlEntity::new();

        assert_eq!(entity.entity_name(), "sysctl::Sysctl");
        assert!(entity.parents().is_empty());
        assert!(
            Uuid::parse_str(&entity.entity_id()).is_ok(),
            "Entity ID should be a valid UUID"
        );
        assert!(entity.get_attrs().unwrap().is_empty());
    }
}
