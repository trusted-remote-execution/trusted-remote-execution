use crate::cedar_auth::{Action, convert_pascal_to_snake_case};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SysctlAction {
    Load,
}

impl fmt::Display for SysctlAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let action_str = convert_pascal_to_snake_case(&format!("{self:?}"));
        write!(f, "sysctl::Action::\"{action_str}\"")
    }
}

impl Action for SysctlAction {}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use rstest::rstest;

    /// Given: An action to format
    /// When: Formatting is requested
    /// Then: The correct format is returned as a String
    #[rstest]
    #[case::load(SysctlAction::Load, r#"sysctl::Action::"load""#)]
    fn test_action_formats(#[case] action: SysctlAction, #[case] action_str: String) -> Result<()> {
        assert_eq!(action.to_string(), action_str);
        Ok(())
    }
}
