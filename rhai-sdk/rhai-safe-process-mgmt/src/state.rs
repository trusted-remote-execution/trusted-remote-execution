//! Active state type for systemd services
//!
//! This module re-exports the [`rust_safe_process_mgmt::systemctl::State`] type for use in Rhai
use rhai::plugin::{
    Dynamic, FnNamespace, FuncRegistration, Module, NativeCallContext, PluginFunc, RhaiResult,
    TypeId, export_module, mem,
};

#[export_module]
#[allow(non_upper_case_globals)]
pub mod active_state_module {
    use rust_safe_process_mgmt::systemctl::State;

    pub const ACTIVE: State = State::Active;
    pub const INACTIVE: State = State::Inactive;
    pub const FAILED: State = State::Failed;
    pub const ACTIVATING: State = State::Activating;
    pub const DEACTIVATING: State = State::Deactivating;
    pub const MAINTENANCE: State = State::Maintenance;
    pub const RELOADING: State = State::Reloading;
    pub const REFRESHING: State = State::Refreshing;
    pub const UNKNOWN: State = State::Unknown;

    /// '==' operator
    #[rhai_fn(global, name = "==")]
    pub fn eq(type_1: State, type_2: State) -> bool {
        type_1 == type_2
    }

    /// '!=' operator
    #[rhai_fn(global, name = "!=")]
    pub fn neq(type_1: State, type_2: State) -> bool {
        type_1 != type_2
    }

    /// Convert to string
    #[rhai_fn(global, name = "to_string")]
    pub fn to_string(state: State) -> String {
        state.to_string()
    }

    /// Check if the state represents an active unit
    #[rhai_fn(global, name = "is_active", get = "is_active")]
    pub const fn is_active(state: State) -> bool {
        state.is_active()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use active_state_module::*;
    use rstest::rstest;
    use rust_safe_process_mgmt::systemctl::State;

    /// Given: Two State values
    /// When: They are compared using the equals "==" operator
    /// Then: The correct result is returned
    #[rstest]
    #[case(ACTIVE, ACTIVE, true)]
    #[case(INACTIVE, INACTIVE, true)]
    #[case(FAILED, FAILED, true)]
    #[case(ACTIVATING, ACTIVATING, true)]
    #[case(DEACTIVATING, DEACTIVATING, true)]
    #[case(MAINTENANCE, MAINTENANCE, true)]
    #[case(RELOADING, RELOADING, true)]
    #[case(REFRESHING, REFRESHING, true)]
    #[case(UNKNOWN, UNKNOWN, true)]
    #[case(ACTIVE, INACTIVE, false)]
    #[case(FAILED, ACTIVE, false)]
    fn test_rhai_active_state_equals(
        #[case] lhs: State,
        #[case] rhs: State,
        #[case] expected: bool,
    ) {
        assert_eq!(active_state_module::eq(lhs, rhs), expected);
    }

    /// Given: Two State values
    /// When: They are compared using the not equals "!=" operator
    /// Then: The correct result is returned
    #[rstest]
    #[case(ACTIVE, ACTIVE, false)]
    #[case(ACTIVE, INACTIVE, true)]
    #[case(FAILED, ACTIVE, true)]
    fn test_rhai_active_state_not_equals(
        #[case] lhs: State,
        #[case] rhs: State,
        #[case] expected: bool,
    ) {
        assert_eq!(active_state_module::neq(lhs, rhs), expected);
    }

    /// Given: A State value
    /// When: to_string is called
    /// Then: The correct string representation is returned
    #[rstest]
    #[case(ACTIVE, "active")]
    #[case(INACTIVE, "inactive")]
    #[case(FAILED, "failed")]
    #[case(ACTIVATING, "activating")]
    #[case(DEACTIVATING, "deactivating")]
    #[case(MAINTENANCE, "maintenance")]
    #[case(RELOADING, "reloading")]
    #[case(REFRESHING, "refreshing")]
    #[case(UNKNOWN, "unknown")]
    fn test_rhai_active_state_to_string(#[case] state: State, #[case] expected: &str) {
        assert_eq!(active_state_module::to_string(state), expected);
    }

    /// Given: A State value
    /// When: is_active is called
    /// Then: The correct boolean is returned
    #[rstest]
    #[case(ACTIVE, true)]
    #[case(RELOADING, true)]
    #[case(REFRESHING, true)]
    #[case(INACTIVE, false)]
    #[case(FAILED, false)]
    #[case(ACTIVATING, false)]
    #[case(DEACTIVATING, false)]
    #[case(MAINTENANCE, false)]
    #[case(UNKNOWN, false)]
    fn test_rhai_active_state_is_active(#[case] state: State, #[case] expected: bool) {
        assert_eq!(active_state_module::is_active(state), expected);
    }
}
