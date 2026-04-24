use crate::cedar_auth::{Action, convert_pascal_to_snake_case};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProcessAction {
    List,
    MountNamespace,
    NetworkNamespace,
    ListFds,
    Kill,
    Interrupt,
    Trace,
}

impl fmt::Display for ProcessAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let action_str = convert_pascal_to_snake_case(&format!("{self:?}"));
        write!(f, "process_system::Action::\"{action_str}\"")
    }
}

impl Action for ProcessAction {}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use rstest::rstest;

    /// Given: An action to format
    /// When: Formatting is requested
    /// Then: The correct format is returned as a String
    #[rstest]
    #[case::list(ProcessAction::List, r#"process_system::Action::"list""#)]
    #[case::mount_namespace(
        ProcessAction::MountNamespace,
        r#"process_system::Action::"mount_namespace""#
    )]
    #[case::network_namespace(
        ProcessAction::NetworkNamespace,
        r#"process_system::Action::"network_namespace""#
    )]
    #[case::list_fds(ProcessAction::ListFds, r#"process_system::Action::"list_fds""#)]
    #[case::kill(ProcessAction::Kill, r#"process_system::Action::"kill""#)]
    #[case::interrupt(ProcessAction::Interrupt, r#"process_system::Action::"interrupt""#)]
    #[case::trace(ProcessAction::Trace, r#"process_system::Action::"trace""#)]
    fn test_action_formats(
        #[case] action: ProcessAction,
        #[case] action_str: String,
    ) -> Result<()> {
        assert_eq!(action.to_string(), action_str);
        Ok(())
    }
}
