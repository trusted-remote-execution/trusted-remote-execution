use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::io::create_temp_dir_and_path;
use rex_test_utils::random::get_rand_string_of_len;

use anyhow::Result;
use assert_fs::fixture::PathChild;
use rust_safe_io::error_constants::{
    INVALID_START_LINE_ERR, NO_READ_LINE_MODE_SPECIFIED_ERR, READ_FILE_FLAG_ERR,
};
use rust_safe_io::options::{OpenFileOptionsBuilder, ReadLinesOptionsBuilder};
use std::rc::Rc;

use crate::test_common::{
    TestContents, open_dir_and_file, open_dir_and_file_with_contents, open_test_dir_handle,
};

mod safe_read_tests {
    use super::*;
    const SENSITIVE_FILE_CONTENT: &str = "Starting application initialization\nnot recorded\nLoading configuration files\ncould not open file \"config.json\" for reading: Permission denied\nUsing default configuration\nDatabase connection not recorded due to timeout\ncould not read file \"data.bin\": I/O error occurred\ncould not read file \"log.txt\": read 512 of 1024\nApplication startup completed";
    /// Given: A file that is a real file and a real directory and authorized user
    /// When: The file is read with safe I/O
    /// Then: The file is read correctly with no errors
    #[test]
    fn test_reading_normal_file() -> Result<()> {
        let test_contents = open_dir_and_file()?;
        let contents = test_contents
            .file_handle
            .safe_read(&DEFAULT_TEST_CEDAR_AUTH)?;

        assert_eq!(
            contents, test_contents._content,
            "Expected file contents to match original content"
        );

        Ok(())
    }

    /// Given: A binary file that is a real file and a real directory and authorized user
    /// When: The binary file is read with safe I/O
    /// Then: The binary file is read correctly with no errors
    #[test]
    fn test_reading_binary_file() -> Result<()> {
        let binary_data = vec![0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD];
        let binary_string = String::from_utf8_lossy(&binary_data).to_string();

        let test_contents = open_dir_and_file_with_contents(binary_string.clone())?;
        let contents = test_contents
            .file_handle
            .safe_read(&DEFAULT_TEST_CEDAR_AUTH)?;

        assert_eq!(
            contents, binary_string,
            "Expected binary file contents to match original content"
        );

        Ok(())
    }

    /// Given: A file that is a real file and a real directory but unauthorized user
    /// When: The file is read with safe I/O
    /// Then: Access is denied
    #[test]
    fn test_unauthorized_read_file() -> Result<()> {
        let test_contents = open_dir_and_file()?;
        let principal = get_test_rex_principal();
        let test_policy = format!(
            r#"forbid(
                principal == User::"{principal}",
                action == {},
                resource
            );"#,
            FilesystemAction::Read
        );
        let test_cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy)
            .build()
            .expect("Failed to build TestCedarAuth")
            .create();

        let result = test_contents.file_handle.safe_read(&test_cedar_auth);
        let expected_error = format!(
            "Permission denied: {principal} unauthorized to perform {}",
            FilesystemAction::Read
        );
        assert_error_contains(result, &expected_error);

        Ok(())
    }

    /// Given: A file that is a real file and a real directory
    /// When: The file is read with safe I/O twice
    /// Then: The file is read correctly twice with no errors
    #[test]
    fn test_reading_file_twice() -> Result<()> {
        let test_contents = open_dir_and_file()?;
        let contents1 = test_contents
            .file_handle
            .safe_read(&DEFAULT_TEST_CEDAR_AUTH)?;
        let contents2 = test_contents
            .file_handle
            .safe_read(&DEFAULT_TEST_CEDAR_AUTH)?;

        assert!(
            contents1 == test_contents._content,
            "Expected first read contents to match original content"
        );
        assert!(
            contents1 == contents2,
            "Expected second read contents to match first read contents"
        );

        Ok(())
    }

    /// Given: A file opened without read option
    /// When: The file is read
    /// Then: An error is returned
    #[test]
    fn test_read_file_no_read_permission_fails() -> Result<()> {
        let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
        let dir_handle = open_test_dir_handle(&temp_dir_path);

        let test_file = "test_read_file.txt";
        let _ = temp_dir.child(test_file);

        let file_handle = dir_handle
            .safe_open_file(
                &DEFAULT_TEST_CEDAR_AUTH,
                test_file,
                OpenFileOptionsBuilder::default()
                    .create(true)
                    .build()
                    .unwrap(),
            )
            .unwrap();

        let result = file_handle.safe_read(&DEFAULT_TEST_CEDAR_AUTH);

        assert_error_contains(result, READ_FILE_FLAG_ERR);

        Ok(())
    }

    /// Given: A file opened with write permissions only (no read permissions)
    /// When: The file is written to and then an attempt is made to read from it
    /// Then: The read operation should fail with an appropriate error
    #[test]
    fn test_write_then_read_without_read_permission_fails() -> Result<()> {
        let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
        let test_file = "test_write_no_read.txt";
        let test_content = "Test content";

        rex_test_utils::io::create_test_file(&temp_dir, test_file, test_content.as_bytes())?;

        let dir_handle = open_test_dir_handle(&temp_dir_path);

        let file_handle = dir_handle
            .safe_open_file(
                &DEFAULT_TEST_CEDAR_AUTH,
                test_file,
                OpenFileOptionsBuilder::default()
                    .write(true)
                    .build()
                    .unwrap(),
            )
            .unwrap();

        let new_file_handle =
            file_handle.safe_write(&DEFAULT_TEST_CEDAR_AUTH, "Updated content")?;

        let result = new_file_handle.safe_read(&DEFAULT_TEST_CEDAR_AUTH);

        assert_error_contains(result, READ_FILE_FLAG_ERR);

        Ok(())
    }

    /// Given: policy with redacted_read
    /// When: The file is read with safe I/O and the redaction dictionary is missing
    /// Then: Permission denied to open the redaction dir
    #[test]
    fn test_read_policy_redacted_read_dir_permission_deny_error() -> Result<()> {
        let test_contents = open_dir_and_file_with_contents(SENSITIVE_FILE_CONTENT.to_string())?;
        let principal = get_test_rex_principal();
        let test_policy = format!(
            r#"
            permit (
                principal == User::"{principal}",
                action == file_system::Action::"redacted_read",
                resource is file_system::File
            );"#,
        );
        let test_cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy.to_string())
            .build()
            .expect("Failed to build TestCedarAuth")
            .create();

        let contents = test_contents.file_handle.safe_read(&test_cedar_auth);
        assert_error_contains(contents, format!("Permission denied: {} unauthorized to perform file_system::Action::\"open\" for file_system::Dir::/etc/opt/rex", principal).as_str());

        Ok(())
    }

    /// Given: A file with a policy containing redacted context for a different path
    /// When: The file is read with safe I/O
    /// Then: No redaction is applied (normal authorization flow)
    #[test]
    fn test_read_policy_matching_path_unredacted() -> Result<()> {
        let test_contents = open_dir_and_file_with_contents(SENSITIVE_FILE_CONTENT.to_string())?;
        let principal = get_test_rex_principal();
        let test_policy = format!(
            r#"
            permit (
                principal == User::"{principal}",
                action == file_system::Action::"redacted_read",
                resource is file_system::File
            ) when {{
                resource in file_system::Dir::"/different/path"
            }};
            permit (
                principal == User::"{principal}",
                action == file_system::Action::"read",
                resource is file_system::File
            ) when {{
                resource in file_system::Dir::"{}"
            }};"#,
            test_contents.dir_name
        );
        let test_cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy.to_string())
            .build()
            .expect("Failed to build TestCedarAuth")
            .create();

        let contents = test_contents.file_handle.safe_read(&test_cedar_auth)?;
        assert_eq!(contents, test_contents._content);

        Ok(())
    }

    /// Given: A policy that has redacted apply to non-matching user
    /// When: The file is read with safe I/O
    /// Then: No redaction is applied
    #[test]
    fn test_read_policy_non_matching_principal_unredacted() -> Result<()> {
        let test_contents = open_dir_and_file_with_contents(SENSITIVE_FILE_CONTENT.to_string())?;
        let principal = get_test_rex_principal();
        let test_policy = format!(
            r#"
            permit (
                principal == User::"nonexistuser",
                action == file_system::Action::"redacted_read",
                resource is file_system::File
            ) when {{
                resource in file_system::Dir::"{}"
            }};
             permit (
                principal == User::"{principal}",
                action == file_system::Action::"read",
                resource is file_system::File
            );"#,
            test_contents.dir_name
        );

        let test_cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy.to_string())
            .build()
            .expect("Failed to build TestCedarAuth")
            .create();

        let contents = test_contents.file_handle.safe_read(&test_cedar_auth)?;
        assert_eq!(contents, test_contents._content);

        Ok(())
    }

    /// Given: A file with a policy that give permission to redaction config dir and file
    /// When: redacted read a file and the redaction file is missing
    /// Then: file not found error
    #[test]
    fn test_read_policy_redacted_with_file_missing_error() -> Result<()> {
        let test_contents = open_dir_and_file_with_contents(SENSITIVE_FILE_CONTENT.to_string())?;
        let principal = get_test_rex_principal();
        let test_policy = format!(
            r#"
            permit (
                principal == User::"{principal}",
                action == file_system::Action::"redacted_read",
                resource is file_system::File
            ) when {{
                resource in file_system::Dir::"{}"
            }};
            permit(
                principal == User::"{principal}",
                action == file_system::Action::"open",
                resource
            ) when {{
                resource == file_system::Dir::"/etc/opt/rex" ||
                resource == file_system::Dir::"/private/etc/opt/rex"
            }};
            permit(
                principal == User::"{principal}",
                action in [file_system::Action::"open", file_system::Action::"read"],
                resource
            ) when {{
                resource == file_system::File::"/etc/opt/rex/rex_redaction.config" ||
                resource == file_system::File::"/private/etc/opt/rex/rex_redaction.config"
            }};"#,
            test_contents.dir_name
        );
        let test_cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy.to_string())
            .build()
            .expect("Failed to build TestCedarAuth")
            .create();

        let contents = test_contents.file_handle.safe_read(&test_cedar_auth);
        assert_error_contains(contents, "No such file or directory");

        Ok(())
    }
    /// Given: policy that give permission to open redaction config dir
    /// When: redacted read a file and the redaction dictionary dir is missing
    /// Then: file not found error
    #[test]
    fn test_read_policy_redacted_with_dir_missing_error() -> Result<()> {
        let test_contents = open_dir_and_file_with_contents(SENSITIVE_FILE_CONTENT.to_string())?;
        let principal = get_test_rex_principal();
        let test_policy = format!(
            r#"
            permit (
                principal == User::"{principal}",
                action == file_system::Action::"redacted_read",
                resource is file_system::File
            ) when {{
                resource in file_system::Dir::"{}"
            }};
            permit(
                principal == User::"{principal}",
                action == file_system::Action::"open",
                resource
            ) when {{
                resource == file_system::Dir::"/etc/opt/rex" ||
                resource == file_system::Dir::"/private/etc/opt/rex"
            }};
            permit(
                principal == User::"{principal}",
                action in [file_system::Action::"open", file_system::Action::"read"],
                resource
            ) when {{
                resource == file_system::File::"/etc/opt/rex/rex_redaction.config" ||
                resource == file_system::File::"/private/etc/opt/rex/rex_redaction.config"
            }};"#,
            test_contents.dir_name
        );
        let test_cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy.to_string())
            .build()
            .expect("Failed to build TestCedarAuth")
            .create();

        let contents = test_contents.file_handle.safe_read(&test_cedar_auth);
        assert_error_contains(contents, "No such file or directory");
        Ok(())
    }
}

mod safe_read_lines_tests {
    use crate::test_common::run_bash_command;
    use rstest::rstest;
    use rust_safe_io::CHUNK_SIZE;
    use std::{cmp, ops::RangeInclusive};

    use super::*;

    /// Given: A file opened without read permissions
    /// When: safe_read_lines is called
    /// Then: An error is returned with specific message from design doc
    #[test]
    fn test_safe_read_lines_no_read_permission() -> Result<()> {
        let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

        let dir_handle = open_test_dir_handle(&temp_dir_path);

        let test_file = "test_read_file.txt";
        let _ = temp_dir.child(test_file);

        let file_handle = dir_handle
            .safe_open_file(
                &DEFAULT_TEST_CEDAR_AUTH,
                test_file,
                OpenFileOptionsBuilder::default()
                    .create(true)
                    .build()
                    .unwrap(),
            )
            .unwrap();

        let options = ReadLinesOptionsBuilder::default().count(5).build().unwrap();
        let result = file_handle.safe_read_lines(&DEFAULT_TEST_CEDAR_AUTH, options);

        assert_error_contains(result, READ_FILE_FLAG_ERR);

        Ok(())
    }

    /// Given: A user without read authorization
    /// When: safe_read_lines is called
    /// Then: Permission denied error is returned
    #[test]
    fn test_unauthorized_safe_read_lines() -> Result<()> {
        let test_contents = open_dir_and_file()?;
        let principal = get_test_rex_principal();
        let test_policy = format!(
            r#"forbid(
                principal == User::"{principal}",
                action == {},
                resource
            );"#,
            FilesystemAction::Read
        );
        let test_cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy)
            .build()
            .expect("Failed to build TestCedarAuth")
            .create();

        let options = ReadLinesOptionsBuilder::default().count(5).build().unwrap();
        let result = test_contents
            .file_handle
            .safe_read_lines(&test_cedar_auth, options);

        let expected_error = format!(
            "Permission denied: {principal} unauthorized to perform {}",
            FilesystemAction::Read
        );
        assert_error_contains(result, &expected_error);

        Ok(())
    }

    /// Given: A file with multiple lines
    /// When: safe_read_lines without valid options
    /// Then: An error should be returned
    #[rstest]
    #[case::no_options_provided(None, None, NO_READ_LINE_MODE_SPECIFIED_ERR)]
    #[case::zero_start(None, Some(0), INVALID_START_LINE_ERR)]
    fn test_safe_read_lines_invalid_options(
        #[case] count: Option<isize>,
        #[case] start: Option<usize>,
        #[case] expected_err: &str,
    ) -> Result<()> {
        let test_file = create_default_file_with_n_lines(15);

        let mut builder = ReadLinesOptionsBuilder::default();
        count.map(|c| builder.count(c));
        start.map(|s| builder.start(s));

        let result = builder.build().and_then(|opts| {
            test_file
                .file_handle
                .safe_read_lines(&DEFAULT_TEST_CEDAR_AUTH, opts)
        });

        assert_error_contains(result, expected_err);
        Ok(())
    }

    /// Given: A file with multiple lines
    /// When: safe_read_lines is called with count and start parameters
    /// Then: The correct lines are returned and the API behaves the same whether or not the file has a trailing new line character
    #[rstest]
    // Count-only cases
    #[case::count_only_case1(Some(10), None, 1..=10)]
    #[case::count_only_case2(Some(1), None, 1..=1)]
    #[case::count_only_case3(Some(0), None, 1..=0)]
    #[case::count_only_case4(Some(20), None, 1..=15)]
    #[case::count_only_case5(Some(-1), None, 15..=15)]
    #[case::count_only_case6(Some(-10), None, 6..=15)]
    #[case::count_only_case7(Some(-20), None, 1..=15)]
    // Start-only cases
    #[case::start_only_case1(None, Some(1), 1..=15)]
    #[case::start_only_case2(None, Some(5), 5..=15)]
    #[case::start_only_case3(None, Some(15), 15..=15)]
    #[case::start_only_case4(None, Some(16), 16..=15)]
    // Count and start cases (forward)
    #[case::count_and_start_case1(Some(5), Some(6), 6..=10)]
    #[case::count_and_start_case2(Some(10), Some(6), 6..=15)]
    #[case::count_and_start_case3(Some(15), Some(6), 6..=15)]
    #[case::count_and_start_case4(Some(15), Some(20), 1..=0)]
    #[case::count_and_start_case5(Some(15), Some(1), 1..=15)]
    #[case::count_and_start_case6(Some(0), Some(1), 1..=0)]
    // Count and start cases (backward)
    #[case::count_and_start_case7(Some(-5), Some(5), 1..=5)]
    #[case::count_and_start_case8(Some(-10), Some(5), 1..=5)] // count beyond the start of the file behaves as if we read from the start of the file
    #[case::count_and_start_case9(Some(-20), Some(15), 1..=15)]
    #[case::count_and_start_case10(Some(-10), Some(20), 6..=15)] // start_line beyond the end of the file behaves as if we read from the end of the file
    #[case::count_and_start_case11(Some(-1), Some(1), 1..=1)]
    fn test_safe_read_lines_valid_options(
        #[case] count: Option<isize>,
        #[case] start: Option<usize>,
        #[case] expected_lines_range_1_indexed: RangeInclusive<isize>,
    ) -> Result<()> {
        // First test when the file doesn't have a trailing new line
        let test_file = create_default_file_with_n_lines(15);
        let contents = &test_file._content;

        let mut builder = ReadLinesOptionsBuilder::default();
        count.map(|c| builder.count(c));
        start.map(|s| builder.start(s));

        let options = builder.build().unwrap();

        let expected_lines = contents
            .split("\n")
            .skip((*expected_lines_range_1_indexed.start() - 1) as usize)
            .take(expected_lines_range_1_indexed.count())
            .collect::<Vec<_>>();

        let result = test_file
            .file_handle
            .safe_read_lines(&DEFAULT_TEST_CEDAR_AUTH, options)?;

        assert_eq!(result, expected_lines);

        // The API should behave exactly the same when the file has a trailing new line
        let new_file_handle = test_file
            .file_handle
            .safe_write(&DEFAULT_TEST_CEDAR_AUTH, format!("{contents}\n").as_str())?;

        let result = new_file_handle.safe_read_lines(&DEFAULT_TEST_CEDAR_AUTH, options)?;

        assert_eq!(result, expected_lines);

        Ok(())
    }

    /// Given: a file
    /// When: we read multiple times from the same file
    /// Then: it resets to the beginning on each read
    #[test]
    fn test_safe_read_lines_multiple_times_no_pagination() -> Result<()> {
        let test_file = create_default_file_with_n_lines(12);
        let contents = &test_file._content;
        let page_size: isize = 5;

        for _i in 0..2 {
            let options = ReadLinesOptionsBuilder::default()
                .count(page_size)
                .build()
                .unwrap();

            let result = test_file
                .file_handle
                .safe_read_lines(&DEFAULT_TEST_CEDAR_AUTH, options)?;

            let expected_lines = contents
                .split("\n")
                .take(page_size as usize)
                .collect::<Vec<_>>();

            assert_eq!(result, expected_lines);
        }

        Ok(())
    }

    // This test is specifically to validate iteration over multiple chunks.
    /// Given: A file that is bigger than CHUNK_SIZE
    /// When: safe_read_lines is called with line count
    /// Then: last N lines are returned as a vector
    #[test]
    fn test_safe_read_lines_last_lines_big_file() -> Result<()> {
        // Build out the test file such that we encounter the following conditions:
        // 1. Chunk boundary has no adjacent newlines
        // 2. Chunk boundary has an adjacent newline at the start of the chunk
        // 3. Chunk boundary has an adjacent newline at the end of the chunk
        // 4. Chunk boundary has adjacent newlines on both sides

        // This leads to the following structure:
        // Line 6: length CHUNK_SIZE + CHUNK_SIZE / 2 (+ 1 newline) --> condition 1
        // Line 5: length CHUNK_SIZE / 2 - 2 (+ 1 newline)          --> condition 2
        // Line 4: length CHUNK_SIZE (+ 1 newline)                  --> condition 3
        // Line 3: length CHUNK_SIZE - 2 (+ 1 newline)
        // Line 2: length 0 (+ 1 newline)                           --> condition 4
        // Line 1: length > CHUNK_SIZE

        let line6 = get_rand_string_of_len(CHUNK_SIZE + CHUNK_SIZE / 2);
        let line5 = get_rand_string_of_len(CHUNK_SIZE / 2 - 2);
        let line4 = get_rand_string_of_len(CHUNK_SIZE);
        let line3 = get_rand_string_of_len(CHUNK_SIZE - 2);
        let line2 = "".to_string();
        let line1 = get_rand_string_of_len(1234);

        let lines = [line1, line2, line3, line4, line5, line6];
        let test_content = lines.join("\n");
        let test_contents = open_dir_and_file_with_contents(test_content.to_string())?;

        // test each valid count number
        for count in 1..=lines.len() {
            let options = ReadLinesOptionsBuilder::default()
                .count(-(count as isize))
                .build()
                .unwrap();

            let result = test_contents
                .file_handle
                .safe_read_lines(&DEFAULT_TEST_CEDAR_AUTH, options)?;

            assert_eq!(result.len(), count);

            // Expected: take the last `count` lines
            let expected_lines = lines
                .iter()
                .skip(lines.len() - count)
                .take(count)
                .collect::<Vec<_>>();

            for i in 0..result.len() {
                assert_eq!(result[i], *expected_lines[i])
            }
        }

        // Also run some tests to validate the start logic
        // Poor man's rstest - so we don't have to recreate the large file every time
        let start_test_cases: [(usize, isize); 5] = [(1, -1), (4, -3), (6, -6), (3, -4), (8, -2)];

        for (start, count) in start_test_cases {
            let options = ReadLinesOptionsBuilder::default()
                .start(start)
                .count(count)
                .build()
                .unwrap();

            let expected_skip =
                cmp::max(cmp::min(start as isize, lines.len() as isize) + count, 0) as usize;
            let expected_count = cmp::min(start as isize, -count) as usize;
            let expected_lines = lines
                .iter()
                .skip(expected_skip)
                .take(expected_count)
                .collect::<Vec<_>>();

            let result = test_contents
                .file_handle
                .safe_read_lines(&DEFAULT_TEST_CEDAR_AUTH, options)?;

            assert_eq!(result.len(), expected_count);

            for i in 0..result.len() {
                assert_eq!(result[i], *expected_lines[i])
            }
        }

        Ok(())
    }

    /// Given: an empty file
    /// When: safe_read_lines is called on it with start option
    /// Then: an empty vector is returned
    #[test]
    fn test_safe_read_lines_empty_file() -> Result<()> {
        let test_contents = open_dir_and_file_with_contents("".to_string())?;

        let options = ReadLinesOptionsBuilder::default().start(5).build().unwrap();
        let result = test_contents
            .file_handle
            .safe_read_lines(&DEFAULT_TEST_CEDAR_AUTH, options)?;

        assert_eq!(result.len(), 0);

        Ok(())
    }

    /// Given: a file
    /// When: safe_read_lines is called on it
    /// Then: the output corresponds to the `head` unix command
    #[rstest]
    #[case::no_args("", 10)]
    #[case::count_option_smaller_than_file("-n 5", 5)]
    #[case::count_option_larger_than_file("-n 20", 20)]
    fn command_equivalence_test_head(#[case] bash_args: &str, #[case] count: isize) -> Result<()> {
        let test_contents = create_default_file_with_n_lines(15);
        let contents = &test_contents._content;
        let file_path = format!("{}/{}", &test_contents.dir_name, &test_contents.file_name);

        let command_str = format!("head {} {}", bash_args, file_path);
        let bash_stdout = run_bash_command(command_str.as_str())?;

        // head is inconsistent about adding a newline to the end of the output (it depends on how many lines were taken and whether
        // the file ended in a new line or not). We trim the end to normalize the output for the test.
        let bash_stdout = bash_stdout.trim_end();

        let options = ReadLinesOptionsBuilder::default().count(count).build()?;
        let command_output = test_contents
            .file_handle
            .safe_read_lines(&DEFAULT_TEST_CEDAR_AUTH, options)?
            .join("\n");

        assert_eq!(
            bash_stdout, command_output,
            "bash output did not match command output. Bash output: {}, command output: {}",
            bash_stdout, command_output
        );

        // the command should also have the same behaviour when the file ends in a new line
        let trailing_newline_file_handle = test_contents
            .file_handle
            .safe_write(&DEFAULT_TEST_CEDAR_AUTH, format!("{contents}\n").as_str())?;

        let bash_stdout = run_bash_command(command_str.as_str())?;

        // head is inconsistent about adding a newline to the end of the output (it depends on how many lines were taken and whether
        // the file ended in a new line or not). We trim the end to normalize the output for the test.
        let bash_stdout = bash_stdout.trim_end();

        let command_output = trailing_newline_file_handle
            .safe_read_lines(&DEFAULT_TEST_CEDAR_AUTH, options)?
            .join("\n");

        assert_eq!(
            bash_stdout, command_output,
            "bash output did not match command output. Bash output: {}, command output: {}",
            bash_stdout, command_output
        );

        Ok(())
    }

    /// Given: a file
    /// When: safe_read_lines is called on it
    /// Then: the output corresponds to the `tail` unix command
    #[rstest]
    #[case::no_args("", Some(-10), None)]
    #[case::count_option_smaller_than_file("-n 5", Some(-5), None)]
    #[case::count_option_larger_than_file("-n 20", Some(-20), None)]
    #[case::start_option_before_10th_line("-n +4", None, Some(4))]
    #[case::start_option_after_10th_line("-n +12", None, Some(12))]
    fn command_equivalence_test_tail(
        #[case] bash_args: &str,
        #[case] count: Option<isize>,
        #[case] start: Option<usize>,
    ) -> Result<()> {
        let test_contents = create_default_file_with_n_lines(15);
        let contents = &test_contents._content;
        let file_path = format!("{}/{}", &test_contents.dir_name, &test_contents.file_name);

        let command_str = format!("tail {} {}", bash_args, file_path);
        let bash_stdout = run_bash_command(command_str.as_str())?;

        // tail may add a new line to the output if the input file ended in a new line. Since we're interested in which lines were
        // returned rather than the whitespace surrounding them, we trim the output to normalize the test.
        let bash_stdout = bash_stdout.trim_end();

        let mut options_builder = ReadLinesOptionsBuilder::default();
        if count.is_some() {
            options_builder.count(count.unwrap());
        }
        if start.is_some() {
            options_builder.start(start.unwrap());
        }
        let options = options_builder.build()?;
        let command_output = test_contents
            .file_handle
            .safe_read_lines(&DEFAULT_TEST_CEDAR_AUTH, options)?
            .join("\n");

        assert_eq!(
            bash_stdout, command_output,
            "bash output did not match command output. Bash output: {}, command output: {}",
            bash_stdout, command_output
        );

        // the command should also have the same behaviour when the file ends in a new line
        let trailing_newline_file_handle = test_contents
            .file_handle
            .safe_write(&DEFAULT_TEST_CEDAR_AUTH, format!("{contents}\n").as_str())?;

        let bash_stdout = run_bash_command(command_str.as_str())?;

        // tail may add a new line to the output if the input file ended in a new line. Since we're interested in which lines were
        // returned rather than the whitespace surrounding them, we trim the output to normalize the test.
        let bash_stdout = bash_stdout.trim_end();

        let command_output = trailing_newline_file_handle
            .safe_read_lines(&DEFAULT_TEST_CEDAR_AUTH, options)?
            .join("\n");

        assert_eq!(
            bash_stdout, command_output,
            "bash output did not match command output. Bash output: {}, command output: {}",
            bash_stdout, command_output
        );

        Ok(())
    }
}

mod safe_read_page_tests {
    use super::*;
    use rust_safe_io::options::ReadPageOptionsBuilder;

    /// Given: A file opened without read permissions
    /// When: safe_read_page is called
    /// Then: An error is returned with specific message
    #[test]
    fn test_safe_read_page_no_read_permission() -> Result<()> {
        let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
        let dir_handle = open_test_dir_handle(&temp_dir_path);

        let test_file = "test_safe_read_page_file.txt";
        let _ = temp_dir.child(test_file);

        let file_handle = dir_handle
            .safe_open_file(
                &DEFAULT_TEST_CEDAR_AUTH,
                test_file,
                OpenFileOptionsBuilder::default()
                    .create(true)
                    .build()
                    .unwrap(),
            )
            .unwrap();

        let options = ReadPageOptionsBuilder::default()
            .num_lines(5)
            .build()
            .unwrap();
        let result = file_handle.safe_read_page(&DEFAULT_TEST_CEDAR_AUTH, options);

        assert_error_contains(result, READ_FILE_FLAG_ERR);

        Ok(())
    }

    /// Given: A user without read authorization
    /// When: safe_read_page is called
    /// Then: Permission denied error is returned
    #[test]
    fn test_unauthorized_safe_read_page() -> Result<()> {
        let test_contents = open_dir_and_file()?;
        let principal = get_test_rex_principal();
        let test_policy = format!(
            r#"forbid(
                principal == User::"{principal}",
                action == {},
                resource
            );"#,
            FilesystemAction::Read
        );
        let test_cedar_auth = TestCedarAuthBuilder::default()
            .policy(test_policy)
            .build()
            .expect("Failed to build TestCedarAuth")
            .create();

        let options = ReadPageOptionsBuilder::default()
            .num_lines(5)
            .build()
            .unwrap();
        let result = test_contents
            .file_handle
            .safe_read_page(&test_cedar_auth, options);

        let expected_error = format!(
            "Permission denied: {principal} unauthorized to perform {}",
            FilesystemAction::Read
        );
        assert_error_contains(result, &expected_error);

        Ok(())
    }

    /// Given: A file with multiple lines
    /// When: safe_read_page is called multiple times to read the whole file
    /// Then: Each call returns the next page of lines
    #[test]
    fn test_safe_read_page_pagination() -> Result<()> {
        let test_file = create_default_file_with_n_lines(12);
        let contents = &test_file._content;
        let all_lines: Vec<_> = contents.split("\n").collect();

        let page_size = 5;
        let options = ReadPageOptionsBuilder::default()
            .num_lines(page_size)
            .build()
            .unwrap();

        // First page
        let page1 = test_file
            .file_handle
            .safe_read_page(&DEFAULT_TEST_CEDAR_AUTH, options.clone())?;

        assert_eq!(page1, all_lines[0..5]);

        // Second page
        let page2 = test_file
            .file_handle
            .safe_read_page(&DEFAULT_TEST_CEDAR_AUTH, options.clone())?;

        assert_eq!(page2, all_lines[5..10]);

        // Third page (partial)
        let page3 = test_file
            .file_handle
            .safe_read_page(&DEFAULT_TEST_CEDAR_AUTH, options.clone())?;

        assert_eq!(page3, all_lines[10..12]);

        // Fourth page (empty)
        let page4 = test_file
            .file_handle
            .safe_read_page(&DEFAULT_TEST_CEDAR_AUTH, options.clone())?;

        assert_eq!(page4.len(), 0);

        Ok(())
    }

    /// Given: An empty file
    /// When: safe_read_page is called
    /// Then: An empty vector is returned
    #[test]
    fn test_safe_read_page_empty_file() -> Result<()> {
        let test_contents = open_dir_and_file_with_contents("".to_string())?;

        let options = ReadPageOptionsBuilder::default()
            .num_lines(5)
            .build()
            .unwrap();
        let result = test_contents
            .file_handle
            .safe_read_page(&DEFAULT_TEST_CEDAR_AUTH, options)?;

        assert_eq!(result.len(), 0);

        Ok(())
    }
}

/// Given: A file with content
/// When: safe_read_lines is called followed by safe_read
/// Then: safe_read returns the full original content (proving rewind worked)
#[test]
fn test_safe_read_lines_rewinds_file_for_subsequent_read() -> Result<()> {
    let test_content = "line1\nline2\nline3\nline4\nline5";
    let test_contents = open_dir_and_file_with_contents(test_content.to_string())?;

    let options = ReadLinesOptionsBuilder::default().count(3).build()?;
    let _lines = test_contents
        .file_handle
        .safe_read_lines(&DEFAULT_TEST_CEDAR_AUTH, options)?;

    // Verify file was rewound: safe_read should return full content from beginning
    let read_content = test_contents
        .file_handle
        .safe_read(&DEFAULT_TEST_CEDAR_AUTH)?;
    assert_eq!(
        read_content, test_content,
        "File should be rewound after safe_read_lines, allowing full content to be read again"
    );

    Ok(())
}

/// Helper function to create a file with specified number of lines
fn create_default_file_with_n_lines(n: u32) -> Rc<TestContents> {
    let test_content = (1..=n)
        .map(|i| format!("Line {}", i))
        .collect::<Vec<_>>()
        .join("\n");

    open_dir_and_file_with_contents(test_content).unwrap()
}
