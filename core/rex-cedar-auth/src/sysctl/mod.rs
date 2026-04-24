//! Sysctl entities, actions, and types for Cedar authorization.
pub mod actions;
pub mod entities;
pub mod types;

pub use actions::SysctlAction;
pub use entities::SysctlEntity;
pub use types::EntityType;
