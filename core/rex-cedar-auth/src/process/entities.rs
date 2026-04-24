use crate::cedar_auth::CedarRexEntity;
use crate::process::types::EntityType::Process;
use anyhow::Result;
use cedar_policy::RestrictedExpression;
use std::collections::HashMap;

/// Represents a process entity in the Cedar authorization system
///
/// # Attributes
///
/// | Attribute | Type | Description |
/// |-----------|------|-------------|
/// | `pid` | `String` | Process ID |
/// | `name` | `String` | Process name |
/// | `username` | `String` | Owner username |
/// | `command` | `String` | Full command line |
///
/// # Example Policy
///
/// ```cedar
/// // Unrestricted access to all processes
/// permit(
///   principal,
///   action,
///   resource is process_system::Process
/// );
///
/// // Scoped to list action only
/// permit(
///   principal,
///   action == process_system::Action::"list",
///   resource is process_system::Process
/// );
/// ```
#[derive(Clone, Debug, Default)]
pub struct ProcessEntity {
    pid: String,
    name: String,
    username: String,
    command: String,
}

impl ProcessEntity {
    /// Creates a new `ProcessEntity` with the given name, username, and command
    pub const fn new(pid: String, name: String, username: String, command: String) -> Self {
        Self {
            pid,
            name,
            username,
            command,
        }
    }

    /// Get the process pid
    pub fn pid(&self) -> &str {
        &self.pid
    }

    /// Get the process name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the process username
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Get the process command
    pub fn command(&self) -> &str {
        &self.command
    }
}

impl CedarRexEntity for ProcessEntity {
    fn entity_id(&self) -> String {
        self.pid().to_string()
    }

    fn entity_name(&self) -> String {
        Process.to_string()
    }

    /// Process entities are represented without parent-child relationships in this Cedar authorization model.
    ///
    /// While operating system processes naturally exist in parent-child hierarchies (via ppid),
    /// these relationships are excluded from the Cedar entity model for several reasons:
    ///
    /// 1. Cedar's hierarchical permissions model would imply that having access to a parent process
    ///    automatically grants access to all child processes/threads, which isn't appropriate for our security model
    ///
    /// 2. Process parenting is often arbitrary or system-dependent (e.g., init as parent of orphaned processes)
    ///    and doesn't necessarily reflect meaningful security boundaries
    fn parents(&self) -> Vec<&dyn CedarRexEntity> {
        Vec::new()
    }

    /// Returns the attributes of this process entity.
    ///
    /// # Returns
    ///
    /// A Result containing a `HashMap` of attribute names to `RestrictedExpression` values
    ///
    /// # Errors
    ///
    /// Returns an error if the attribute values cannot be converted to `RestrictedExpression`s
    fn get_attrs(&self) -> Result<HashMap<String, RestrictedExpression>> {
        let mut attrs = HashMap::new();

        attrs.insert(
            "pid".to_string(),
            RestrictedExpression::new_string(self.pid.clone()),
        );
        attrs.insert(
            "name".to_string(),
            RestrictedExpression::new_string(self.name.clone()),
        );
        attrs.insert(
            "username".to_string(),
            RestrictedExpression::new_string(self.username.clone()),
        );
        attrs.insert(
            "command".to_string(),
            RestrictedExpression::new_string(self.command.clone()),
        );

        Ok(attrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cedar_auth::CedarRexEntity;

    /// Given: Process information
    /// When: Creating a ProcessEntity
    /// Then: The entity should have the correct attributes and entity ID
    #[test]
    fn test_process_entity_creation() {
        let pid = "1".to_string();
        let name = "test_process".to_string();
        let username = "test_user".to_string();
        let command = "/usr/bin/test --arg1 --arg2".to_string();

        let entity =
            ProcessEntity::new(pid.clone(), name.clone(), username.clone(), command.clone());

        assert_eq!(entity.pid(), pid);
        assert_eq!(entity.name(), name);
        assert_eq!(entity.username(), username);
        assert_eq!(entity.command(), command);
        assert_eq!(entity.entity_id(), pid);
        assert_eq!(entity.entity_name(), "process_system::Process");
        assert!(entity.parents().is_empty());
    }

    /// Given: A ProcessEntity
    /// When: Getting its attributes
    /// Then: The attributes should contain the expected fields
    #[test]
    fn test_process_entity_attributes() -> Result<()> {
        let pid = "1".to_string();
        let name = "test_process".to_string();
        let username = "test_user".to_string();
        let command = "/usr/bin/test --arg1 --arg2".to_string();

        let entity =
            ProcessEntity::new(pid.clone(), name.clone(), username.clone(), command.clone());
        let attrs = entity.get_attrs()?;

        assert_eq!(attrs.len(), 4);
        assert!(attrs.contains_key("pid"));
        assert!(attrs.contains_key("name"));
        assert!(attrs.contains_key("username"));
        assert!(attrs.contains_key("command"));

        Ok(())
    }
}
