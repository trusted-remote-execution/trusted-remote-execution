//! Signal type for sending signals to kill
//!
//! This module re-exports the [`rustix::process::Signal`] type for use in Rhai
use rhai::plugin::{
    Dynamic, FnNamespace, FuncRegistration, Module, NativeCallContext, PluginFunc, RhaiResult,
    TypeId, export_module, mem,
};

#[export_module]
pub mod signal_type_mod {
    use rustix::process::Signal;

    pub const SIGTERM: Signal = Signal::TERM;
    pub const SIGQUIT: Signal = Signal::QUIT;
    pub const SIGHUP: Signal = Signal::HUP;
    pub const SIGKILL: Signal = Signal::KILL;

    /// '==' operator
    #[rhai_fn(global, name = "==")]
    pub fn eq(type_1: Signal, type_2: Signal) -> bool {
        type_1 == type_2
    }

    /// '!=' operator
    #[rhai_fn(global, name = "!=")]
    pub fn neq(type_1: Signal, type_2: Signal) -> bool {
        type_1 != type_2
    }
}

#[cfg(test)]
mod test {
    use crate::signal::signal_type_mod::*;

    use super::*;
    use rstest::rstest;
    use rustix::process::Signal;

    /// Given: two Signals
    /// When: they are compared using the equals "==" operator
    /// Then: the correct result is returned
    #[rstest]
    #[case(SIGTERM, SIGTERM, true)]
    #[case(SIGKILL, SIGKILL, true)]
    #[case(SIGQUIT, SIGQUIT, true)]
    #[case(SIGHUP, SIGHUP, true)]
    #[case(SIGTERM, SIGKILL, false)]
    fn test_rhai_signal_equals(#[case] lhs: Signal, #[case] rhs: Signal, #[case] expected: bool) {
        assert_eq!(signal_type_mod::eq(lhs, rhs), expected);
    }

    /// Given: two Signals
    /// When: they are compared using the not equals "!=" operator
    /// Then: the correct result is returned
    #[rstest]
    // Basic types compared with each other
    #[case(SIGTERM, SIGTERM, false)]
    #[case(SIGTERM, SIGKILL, true)]

    fn test_rhai_signal_not_equals(
        #[case] lhs: Signal,
        #[case] rhs: Signal,
        #[case] expected: bool,
    ) {
        assert_eq!(signal_type_mod::neq(lhs, rhs), expected);
    }
}
