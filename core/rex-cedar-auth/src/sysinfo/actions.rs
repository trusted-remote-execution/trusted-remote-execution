use crate::cedar_auth::{Action, convert_pascal_to_snake_case};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SysinfoAction {
    List,
    ResolveHostname,
}

impl fmt::Display for SysinfoAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let action_str = convert_pascal_to_snake_case(&format!("{self:?}"));
        write!(f, "sysinfo::Action::\"{action_str}\"")
    }
}

impl Action for SysinfoAction {}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use rstest::rstest;

    /// Given: An action to format
    /// When: Formatting is requested
    /// Then: The correct format is returned as a String
    #[rstest]
    #[case::list(SysinfoAction::List, r#"sysinfo::Action::"list""#)]
    #[case::resolve_hostname(
        SysinfoAction::ResolveHostname,
        r#"sysinfo::Action::"resolve_hostname""#
    )]
    fn test_action_formats(
        #[case] action: SysinfoAction,
        #[case] action_str: String,
    ) -> Result<()> {
        assert_eq!(action.to_string(), action_str);
        Ok(())
    }
}
