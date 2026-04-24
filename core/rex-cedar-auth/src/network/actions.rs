use crate::cedar_auth::Action;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NetworkAction {
    Connect,
    Get,
}

impl fmt::Display for NetworkAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let verb = match self {
            NetworkAction::Get => "GET",
            NetworkAction::Connect => "connect",
        };

        write!(f, "network::Action::\"{verb}\"")
    }
}

impl Action for NetworkAction {}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use rstest::rstest;

    use crate::network::actions::NetworkAction;

    /// Given: An action to format
    /// When: Formatting is requested
    /// Then: The correct format is returned as a String
    #[rstest]
    #[case::list(NetworkAction::Get, r#"network::Action::"GET""#)]
    #[case::list(NetworkAction::Connect, r#"network::Action::"connect""#)]
    fn test_action_formats(
        #[case] action: NetworkAction,
        #[case] action_str: String,
    ) -> Result<()> {
        assert_eq!(action.to_string(), action_str);
        Ok(())
    }
}
