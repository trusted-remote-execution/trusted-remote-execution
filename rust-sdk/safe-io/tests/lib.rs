// Integration tests test your crate's public API. They only have access to items
// in your crate that are marked pub. See the Cargo Targets page of the Cargo Book
// for more information.
//
//   https://doc.rust-lang.org/cargo/reference/cargo-targets.html#integration-tests
//
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{TestCedarAuthBuilder, get_test_rex_principal};
use rex_test_utils::assertions::assert_error_contains;
use rust_safe_io::error_constants::INVALID_REGEX_PATTERN_ERR;
use rust_safe_io::errors::RustSafeIoError;
use rust_safe_io::options::ReplacementOptionsBuilder;
use rust_safe_io::replace_text;

use anyhow::Result;

mod test_common;
use test_common::open_dir_and_file;

mod core_dump_analysis;
mod dir;
mod file;
mod symlink;

mod auth_tests {
    use super::*;

    /// Given: A malformed cedar policy
    /// When: The file is read with safe I/O plugin in Rhai
    /// Then: Authorization check fails with appropriate error message
    #[test]
    fn test_authorization_check_fails() -> Result<()> {
        let principal = get_test_rex_principal();

        let test_policy = format!(
            r#"permit(
            principal == Rex::User::"{principal}",
            action == Rex::Action::"safe_read_file",
            resource
        ) when {{
            context.access_level >= 5
        }};"#
        );

        let test_schema = r#"namespace Rex {
            entity User;
            entity File;
            action safe_read_file appliesTo {
                principal: [User],
                resource: [File],
                context: {
                    access_level: Long
                }
            };
        }"#;

        let test_cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy.to_string())
            .schema(test_schema.to_string())
            .build()
            .unwrap()
            .create();

        let test_contents = open_dir_and_file()?;
        let result = test_contents.file_handle.safe_read(&test_cedar_auth);

        assert_error_contains(result, "Authorization check failed");

        Ok(())
    }

    /// Given: A directory and file with contents
    /// When: Creating a Cedar policy that permits access to files in the directory
    /// Then: The file content should be successfully read and match expected content
    #[test]
    fn test_entity_hierarchy() -> Result<()> {
        let test_contents = open_dir_and_file()?;
        let principal = get_test_rex_principal();
        let dir_name = &test_contents.dir_name;
        let test_policy = format!(
            r#"permit(
            principal == User::"{principal}",
            action == {},
            resource in file_system::Dir::"{dir_name}"
        );"#,
            FilesystemAction::Read
        );

        let test_cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy.to_string())
            .build()
            .unwrap()
            .create();

        let result = test_contents.file_handle.safe_read(&test_cedar_auth)?;

        assert_eq!(result, test_contents._content);
        Ok(())
    }
}

mod replace_tests {
    use super::*;

    /// Given: A string with specific content
    /// When: replace_text is called to replace first instance of " " with "_" using regex
    /// Then: A new string is returned with the first occurence of the search string replaced
    #[test]
    fn test_replace_regex() -> Result<()> {
        let initial_content = "# Application Configuration\napp.name=My Application\nApplication.version=Application1.0.0\n";

        let replacement_options = ReplacementOptionsBuilder::default()
            .is_regex(true)
            .replace_all(false)
            .build()?;

        let modified_string = replace_text(initial_content, "\\s", "_", replacement_options)?;

        assert!(modified_string.contains("#_Application Configuration"));
        assert!(modified_string.contains("app.name=My Application"));
        assert!(modified_string.contains("Application.version=Application1.0.0"));

        Ok(())
    }

    /// Given: A string with specific content
    /// When: replace_text is called to replace all instances of " " with "_" in the string using regex
    /// Then: A new string with all instances of the search string replaced is returned
    #[test]
    fn test_replace_all_regex() -> Result<()> {
        let initial_content = "# Application Configuration\napp.name=My Application\nApplication.version=Application1.0.0\n";

        let replacement_options = ReplacementOptionsBuilder::default()
            .is_regex(true)
            .replace_all(true)
            .build()?;

        let modified_string = replace_text(initial_content, "\\s", "_", replacement_options)?;

        assert!(modified_string.contains("#_Application_Configuration"));
        assert!(modified_string.contains("app.name=My_Application"));
        assert!(modified_string.contains("Application.version=Application1.0.0"));

        Ok(())
    }

    /// Given: A string with specific content
    /// When: replace_text is called to replace first instance of " " with "_"
    /// Then: A new string is returned with the first occurence of the search string replaced
    #[test]
    fn test_replace_text() -> Result<()> {
        let initial_content = "# Application Configuration\napp.name=My Application\nApplication.version=Application1.0.0\n";

        let replacement_options = ReplacementOptionsBuilder::default()
            .is_regex(false)
            .replace_all(false)
            .build()?;

        let modified_string = replace_text(initial_content, " ", "_", replacement_options)?;

        assert!(modified_string.contains("#_Application Configuration"));
        assert!(modified_string.contains("app.name=My Application"));
        assert!(modified_string.contains("Application.version=Application1.0.0"));

        Ok(())
    }

    /// Given: A string with specific content
    /// When: replace_text is called to replace all instances of " " with "_" in the string
    /// Then: A new string with all instances of the search string replaced is returned
    #[test]
    fn test_replace_all() -> Result<()> {
        let initial_content = "# Application Configuration\napp.name=My Application\nApplication.version=Application1.0.0\n";

        let replacement_options = ReplacementOptionsBuilder::default()
            .is_regex(false)
            .replace_all(true)
            .build()?;

        let modified_string = replace_text(initial_content, " ", "_", replacement_options)?;

        assert!(modified_string.contains("#_Application_Configuration"));
        assert!(modified_string.contains("app.name=My_Application"));
        assert!(modified_string.contains("Application.version=Application1.0.0"));

        Ok(())
    }

    /// Given: A string with specific content
    /// When: replace_text is called to replace first instances of "Hi" with "Hey" using regex
    /// Then: A new string is returned with the first occurence of the search string replaced
    #[test]
    fn test_replace_regex_no_matches() -> Result<()> {
        let initial_content = "Hello world";

        let replacement_options = ReplacementOptionsBuilder::default()
            .is_regex(true)
            .replace_all(false)
            .build()?;

        let modified_string = replace_text(initial_content, ".*Hi.*", "Hey", replacement_options)?;

        assert!(modified_string.eq("Hello world"));

        Ok(())
    }

    /// Given: A string with specific content
    /// When: replace_text is called to replace all instances of "Hi" with "Hey" in the string
    /// Then: A new string with all instances of the search string replaced is returned
    #[test]
    fn test_replace_no_matches() -> Result<()> {
        let initial_content = "Hello world";

        let replacement_options = ReplacementOptionsBuilder::default()
            .is_regex(false)
            .replace_all(false)
            .build()?;

        let modified_string = replace_text(initial_content, "Hi", "Hey", replacement_options)?;

        assert!(modified_string.eq("Hello world"));

        Ok(())
    }

    /// Given: An invalid regex pattern (unclosed bracket)
    /// When: Attempting to replace text with regex enabled
    /// Then: Should return ValidationError with appropriate error message
    #[test]
    fn test_replace_text_invalid_regex_error() -> Result<()> {
        let text = "Hello World";
        let invalid_pattern = "[";
        let new_string = "REPLACEMENT";

        let replacement_options = ReplacementOptionsBuilder::default()
            .is_regex(true)
            .replace_all(true)
            .build()?;

        let result = replace_text(text, invalid_pattern, new_string, replacement_options);

        assert!(result.is_err());
        if let Err(RustSafeIoError::ValidationError { reason }) = result {
            assert!(reason.contains(INVALID_REGEX_PATTERN_ERR));
            assert!(reason.contains("["));
        } else {
            panic!(
                "Expected ValidationError for invalid regex, got {:?}",
                result
            );
        }

        Ok(())
    }
}

mod fd_trait_tests {
    use super::*;
    use std::os::fd::{AsFd, AsRawFd};

    /// Given: A file opened through RcFileHandle
    /// When: Calling as_raw_fd()
    /// Then: Returns a valid non-negative file descriptor
    #[test]
    fn test_as_raw_fd_returns_valid_fd() -> Result<()> {
        let test_contents = open_dir_and_file()?;
        let raw_fd = test_contents.file_handle.as_raw_fd();

        assert!(raw_fd >= 0, "File descriptor should be non-negative");

        Ok(())
    }

    /// Given: A file opened through RcFileHandle
    /// When: Calling as_fd()
    /// Then: Returns a BorrowedFd that matches the raw fd
    #[test]
    fn test_as_fd_matches_raw_fd() -> Result<()> {
        let test_contents = open_dir_and_file()?;

        let raw_fd = test_contents.file_handle.as_raw_fd();
        let borrowed_fd = test_contents.file_handle.as_fd();

        assert_eq!(borrowed_fd.as_raw_fd(), raw_fd);

        Ok(())
    }
}
