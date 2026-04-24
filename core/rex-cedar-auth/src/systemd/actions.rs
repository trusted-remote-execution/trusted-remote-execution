use std::fmt;

use crate::cedar_auth::{Action, convert_pascal_to_snake_case};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SystemdAction {
    Start,
    Stop,
    Restart,
    Status,
    DaemonReload,
}

impl fmt::Display for SystemdAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let action_str = convert_pascal_to_snake_case(&format!("{self:?}"));
        write!(f, "systemd::Action::\"{action_str}\"")
    }
}

impl Action for SystemdAction {}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use rstest::rstest;

    /// Given: An action to format
    /// When: Formatting is requested
    /// Then: The correct format is returned as a String
    #[rstest]
    #[case::start(SystemdAction::Start, r#"systemd::Action::"start""#)]
    #[case::stop(SystemdAction::Stop, r#"systemd::Action::"stop""#)]
    #[case::restart(SystemdAction::Restart, r#"systemd::Action::"restart""#)]
    #[case::status(SystemdAction::Status, r#"systemd::Action::"status""#)]
    #[case::daemon_reload(SystemdAction::DaemonReload, r#"systemd::Action::"daemon_reload""#)]
    fn test_action_formats(
        #[case] action: SystemdAction,
        #[case] action_str: String,
    ) -> Result<()> {
        assert_eq!(action.to_string(), action_str);
        Ok(())
    }
}
