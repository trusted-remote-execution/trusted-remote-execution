//! `TransportProtocol` type for configuring DNS resolution protocol
//!
//! This module re-exports the [`rust_safe_system_info::options::TransportProtocol`] type for use in Rhai
use rhai::plugin::{
    Dynamic, FnNamespace, FuncRegistration, Module, NativeCallContext, PluginFunc, RhaiResult,
    TypeId, export_module, mem,
};

#[export_module]
pub mod transport_protocol_type_mod {
    use rust_safe_system_info::options::TransportProtocol;

    pub const AUTO: TransportProtocol = TransportProtocol::Auto;
    pub const UDP: TransportProtocol = TransportProtocol::UDP;
    pub const TCP: TransportProtocol = TransportProtocol::TCP;

    /// '==' operator
    #[rhai_fn(global, name = "==")]
    pub fn eq(type_1: TransportProtocol, type_2: TransportProtocol) -> bool {
        type_1 == type_2
    }

    /// '!=' operator
    #[rhai_fn(global, name = "!=")]
    pub fn neq(type_1: TransportProtocol, type_2: TransportProtocol) -> bool {
        type_1 != type_2
    }
}

#[cfg(test)]
mod test {
    use super::transport_protocol_type_mod::*;
    use rstest::rstest;
    use rust_safe_system_info::options::TransportProtocol;

    /// Given: two TransportProtocols
    /// When: they are compared using the equals "==" operator
    /// Then: the correct result is returned
    #[rstest]
    #[case(AUTO, AUTO, true)]
    #[case(AUTO, TransportProtocol::Auto, true)]
    #[case(UDP, UDP, true)]
    #[case(TCP, TCP, true)]
    #[case(AUTO, UDP, false)]
    #[case(UDP, TCP, false)]
    #[case(AUTO, TCP, false)]
    fn test_rhai_transport_protocol_equals(
        #[case] lhs: TransportProtocol,
        #[case] rhs: TransportProtocol,
        #[case] expected: bool,
    ) {
        assert_eq!(eq(lhs, rhs), expected);
    }

    /// Given: two TransportProtocols
    /// When: they are compared using the not equals "!=" operator
    /// Then: the correct result is returned
    #[rstest]
    #[case(AUTO, AUTO, false)]
    #[case(UDP, UDP, false)]
    #[case(TCP, TCP, false)]
    #[case(AUTO, UDP, true)]
    #[case(UDP, TCP, true)]
    #[case(AUTO, TCP, true)]
    fn test_rhai_transport_protocol_not_equals(
        #[case] lhs: TransportProtocol,
        #[case] rhs: TransportProtocol,
        #[case] expected: bool,
    ) {
        assert_eq!(neq(lhs, rhs), expected);
    }
}
