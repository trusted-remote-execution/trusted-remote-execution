use std::fmt;

use crate::cedar_auth::{Action, convert_pascal_to_snake_case};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[allow(non_camel_case_types)]
pub enum FilesystemAction {
    Read,
    Write,
    Delete,
    Open,
    Create,
    Chmod,
    Chown,
    Stat,
    Move,
    Execute,
    RedactedRead,
    NetworkNamespace,
    Unmount,
    SetXAttr,
}

impl fmt::Display for FilesystemAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let action_str = convert_pascal_to_snake_case(&format!("{self:?}"));
        write!(f, "file_system::Action::\"{action_str}\"")
    }
}

impl Action for FilesystemAction {}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use rstest::rstest;

    /// Given: An action to format
    /// When: Formatting is requested
    /// Then: The correct format is returned as a String
    #[rstest]
    #[case::read(FilesystemAction::Read, r#"file_system::Action::"read""#)]
    #[case::write(FilesystemAction::Write, r#"file_system::Action::"write""#)]
    #[case::delete(FilesystemAction::Delete, r#"file_system::Action::"delete""#)]
    #[case::open(FilesystemAction::Open, r#"file_system::Action::"open""#)]
    #[case::create(FilesystemAction::Create, r#"file_system::Action::"create""#)]
    #[case::chmod(FilesystemAction::Chmod, r#"file_system::Action::"chmod""#)]
    #[case::chown(FilesystemAction::Chown, r#"file_system::Action::"chown""#)]
    #[case::stat(FilesystemAction::Stat, r#"file_system::Action::"stat""#)]
    #[case::move_action(FilesystemAction::Move, r#"file_system::Action::"move""#)]
    #[case::execute(FilesystemAction::Execute, r#"file_system::Action::"execute""#)]
    #[case::redacted_read(
        FilesystemAction::RedactedRead,
        r#"file_system::Action::"redacted_read""#
    )]
    #[case::network_namespace(
        FilesystemAction::NetworkNamespace,
        r#"file_system::Action::"network_namespace""#
    )]
    #[case::unmount(FilesystemAction::Unmount, r#"file_system::Action::"unmount""#)]
    #[case::set_x_attr(FilesystemAction::SetXAttr, r#"file_system::Action::"set_x_attr""#)]
    fn test_action_formats(
        #[case] action: FilesystemAction,
        #[case] action_str: String,
    ) -> Result<()> {
        assert_eq!(action.to_string(), action_str);
        Ok(())
    }
}
