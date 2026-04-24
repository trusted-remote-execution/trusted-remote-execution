use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::io::{create_file_with_content, create_temp_dir_and_path};
use rex_test_utils::random::get_rand_string_of_len;
use rust_safe_io::WalkEntry;
use rust_safe_io::error_constants::INVALID_REGEX_PATTERN_ERR;
use rust_safe_io::errors::RustSafeIoError;
use rust_safe_io::options::{FindOptionsBuilder, OpenFileOptionsBuilder, SizeRange, SizeUnit};

use anyhow::Result;
use assert_fs::fixture::{FileWriteStr, PathChild, PathCreateDir, SymlinkToDir, SymlinkToFile};
use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rstest::rstest;

use crate::test_common::{init_test_logger, open_test_dir_handle};

/// Given: a directory structure and a user unauthorized to read at various levels of the structure
/// When: safe_find is called
/// Then: only entries inside the directory the user is authorized to read are returned
#[rstest]
#[case::unauthorized_at_root("", vec![])]
#[case::unauthorized_at_child("child", vec!["child", "foo.txt"])]
#[case::unauthorized_at_grandchild("child/grandchild", vec!["child", "bar.txt", "grandchild", "foo.txt"])]
#[case::unauthorized_at_greatgrandchild("child/grandchild/greatgrandchild", vec!["child", "bar.txt", "grandchild", "baz.txt", "foo.txt"])] // doesn't actually exist
fn test_safe_find_unauthorized_to_read_root_dir(
    #[case] forbidden_level: &str,
    #[case] mut expected_results: Vec<&str>,
) -> Result<()> {
    init_test_logger();
    // The directory structure is the following:
    // temp_dir
    //   foo.txt
    //   child/
    //     bar.txt
    //     grandchild/
    //       baz.txt

    // Note that greatgrandchild doesn't actually exist, so the forbid clause in the policy shouldn't take any effect for that case

    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let root_file_content = "Root file content for safe_find test";
    let root_file = temp_dir.child("foo.txt");
    root_file.write_str(root_file_content)?;

    let child_dir = temp_dir.child("child");
    child_dir.create_dir_all()?;

    let child_file_content = "Child file content for safe_find test";
    let child_file = child_dir.child("bar.txt");
    child_file.write_str(child_file_content)?;

    let grandchild_dir = child_dir.child("grandchild");
    grandchild_dir.create_dir_all()?;

    let grandchild_file_content = "grandchild file content for safe_find test";
    let grandchild_file = grandchild_dir.child("baz.txt");
    grandchild_file.write_str(grandchild_file_content)?;

    let forbidden_dir = vec![temp_dir_path, forbidden_level.to_string()]
        .join("/")
        .trim_end_matches("/")
        .to_string();

    let test_policy = format!(
        r#"
        permit(
            principal,
            action in [{}, {}, {}],
            resource
        );
        forbid(
            principal,
            action == {},
            resource == file_system::Dir::"{forbidden_dir}"
        );
        "#,
        FilesystemAction::Open,
        FilesystemAction::Read,
        FilesystemAction::Stat,
        FilesystemAction::Read
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let mut traversed_entries = vec![];

    let _ = dir_handle.safe_find(
        &test_cedar_auth,
        FindOptionsBuilder::default().name("*").build().unwrap(),
        |entry| match entry {
            WalkEntry::Entry(dir_entry) => {
                traversed_entries.push(dir_entry.name().clone());
                Ok(())
            }
            _ => Ok(()),
        },
    );

    assert_eq!(expected_results.sort(), traversed_entries.sort());

    Ok(())
}

/// Given: A directory structure with multiple files within the root directory and subdirectory
/// When: safe_find is called with a callback that reads file contents using safe_read
/// Then: The two .txt files are found and their contents are successfully read and verified
#[test]
fn test_safe_find_with_safe_read_callback_success() -> Result<()> {
    init_test_logger();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let root_file_content = "Root file content for safe_find test";
    let root_file = temp_dir.child("root_file.txt");
    root_file.write_str(root_file_content)?;

    let other_file_content = "Log to be filtered out";
    let other_file = temp_dir.child("other_file.log");
    other_file.write_str(other_file_content)?;

    let subdir = temp_dir.child("test_subdir");
    subdir.create_dir_all()?;

    let nested_file_content = "Nested file content in subdirectory";
    let nested_file = subdir.child("nested_file.txt");
    nested_file.write_str(nested_file_content)?;

    let mut found_files = Vec::<(String, String)>::new();

    let callback = |entry: &WalkEntry| -> Result<(), RustSafeIoError> {
        match entry {
            WalkEntry::Entry(dir_entry) => {
                if dir_entry.is_file() {
                    let mut owned_entry = dir_entry.clone();
                    let file_handle = owned_entry.open_as_file(
                        &DEFAULT_TEST_CEDAR_AUTH,
                        OpenFileOptionsBuilder::default()
                            .read(true)
                            .build()
                            .unwrap(),
                    )?;

                    let content = file_handle.safe_read(&DEFAULT_TEST_CEDAR_AUTH)?;
                    let file_name = dir_entry.name().to_string();

                    found_files.push((file_name, content));
                }
                Ok(())
            }
            _ => Ok(()),
        }
    };

    let find_options = FindOptionsBuilder::default()
        .iname("*.log")
        .negate_name(true)
        .build()
        .unwrap();

    dir_handle.safe_find(&DEFAULT_TEST_CEDAR_AUTH, find_options, callback)?;

    assert_eq!(found_files.len(), 2, "Expected to find exactly 2 files");

    let nested_result = found_files
        .iter()
        .find(|(name, _)| name == "nested_file.txt")
        .expect("Expected to find nested_file.txt");
    assert_eq!(
        nested_result.1, nested_file_content,
        "Expected nested file content to match"
    );

    let root_result = found_files
        .iter()
        .find(|(name, _)| name == "root_file.txt")
        .expect("Expected to find root_file.txt");
    assert_eq!(
        root_result.1, root_file_content,
        "Expected root file content to match"
    );

    Ok(())
}

/// Given: A callback that fails Cedar authorization checks during file processing
/// When: safe_find is called with the unauthorized callback
/// Then: A CallbackError should be returned wrapping the Cedar authorization failure
#[test]
fn test_safe_find_callback_error() -> Result<()> {
    init_test_logger();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let test_file = temp_dir.child("test.txt");
    test_file.write_str("test content")?;

    let test_policy = format!(
        r#"permit(
            principal,
            action,
            resource
        );
        forbid(
            principal,
            action == {},
            resource
        );"#,
        FilesystemAction::Write
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let callback = |entry: &WalkEntry| -> Result<(), RustSafeIoError> {
        match entry {
            WalkEntry::Entry(dir_entry) => {
                if dir_entry.is_file() {
                    let mut owned_entry = dir_entry.clone();
                    let file_handle = owned_entry.open_as_file(
                        &DEFAULT_TEST_CEDAR_AUTH,
                        OpenFileOptionsBuilder::default()
                            .read(true)
                            .write(true)
                            .build()
                            .unwrap(),
                    )?;
                    file_handle.safe_write(&test_cedar_auth, "test content")?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    };

    let find_options = FindOptionsBuilder::default()
        .name("*Will_Find_Nothing")
        .negate_name(true)
        .size_range(SizeRange::max_only(100, SizeUnit::Megabytes))
        .build()
        .unwrap();
    let result = dir_handle.safe_find(&test_cedar_auth, find_options, callback);

    assert!(result.is_err());
    assert_error_contains(result, "Permission denied");

    Ok(())
}

/// Given: FindOptionsBuilder with invalid glob and regex patterns
/// When: safe_find is called with invalid patterns
/// Then: Appropriate validation errors are returned for each invalid pattern type
#[test]
fn test_safe_find_invalid_patterns() -> Result<()> {
    init_test_logger();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let test_file = temp_dir.child("test.txt");
    test_file.write_str("test content")?;

    {
        let mut found_files = Vec::<String>::new();
        let callback = |entry: &WalkEntry| -> Result<(), RustSafeIoError> {
            if let WalkEntry::Entry(dir_entry) = entry {
                if dir_entry.is_file() {
                    found_files.push(dir_entry.name().to_string());
                }
            }
            Ok(())
        };

        let result = dir_handle.safe_find(
            &DEFAULT_TEST_CEDAR_AUTH,
            FindOptionsBuilder::default()
                .name("[invalid_glob")
                .build()
                .unwrap(),
            callback,
        );
        assert_error_contains(result, "Invalid glob pattern");
    }

    {
        let mut found_files = Vec::<String>::new();
        let callback = |entry: &WalkEntry| -> Result<(), RustSafeIoError> {
            if let WalkEntry::Entry(dir_entry) = entry {
                if dir_entry.is_file() {
                    found_files.push(dir_entry.name().to_string());
                }
            }
            Ok(())
        };

        let result = dir_handle.safe_find(
            &DEFAULT_TEST_CEDAR_AUTH,
            FindOptionsBuilder::default()
                .iname("[invalid_glob")
                .build()
                .unwrap(),
            callback,
        );
        assert_error_contains(result, "Invalid glob pattern");
    }

    {
        let mut found_files = Vec::<String>::new();
        let callback = |entry: &WalkEntry| -> Result<(), RustSafeIoError> {
            if let WalkEntry::Entry(dir_entry) = entry {
                if dir_entry.is_file() {
                    found_files.push(dir_entry.name().to_string());
                }
            }
            Ok(())
        };

        let result = dir_handle.safe_find(
            &DEFAULT_TEST_CEDAR_AUTH,
            FindOptionsBuilder::default()
                .regex("[invalid_regex")
                .build()
                .unwrap(),
            callback,
        );
        assert_error_contains(result, INVALID_REGEX_PATTERN_ERR);
    }

    Ok(())
}

/// Given: Files with different names and sizes
/// When: safe_find is called with both regex pattern and between size range filters
/// Then: Only files matching both the regex pattern and size range are found
#[test]
fn test_safe_find_regex_and_between_size_filter() -> Result<()> {
    init_test_logger();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let small_log = temp_dir.child("app.log");
    small_log.write_str("small")?; // 5 bytes

    let medium_log = temp_dir.child("error.log");
    medium_log.write_str("medium content here")?; // 18 bytes

    let large_log = temp_dir.child("debug.log");
    large_log.write_str(&get_rand_string_of_len(50))?; // 50 bytes

    let medium_txt = temp_dir.child("readme.txt");
    medium_txt.write_str("medium size text file")?; // 21 bytes

    let mut found_files = Vec::<String>::new();
    let callback = |entry: &WalkEntry| -> Result<(), RustSafeIoError> {
        if let WalkEntry::Entry(dir_entry) = entry {
            if dir_entry.is_file() {
                found_files.push(dir_entry.name().to_string());
            }
        }
        Ok(())
    };

    let find_options = FindOptionsBuilder::default()
        .regex(r".*\.log$")
        .size_range(SizeRange::between(10, 30, SizeUnit::Bytes))
        .build()
        .unwrap();

    dir_handle.safe_find(&DEFAULT_TEST_CEDAR_AUTH, find_options, callback)?;

    assert_eq!(found_files.len(), 1);
    assert!(found_files.contains(&"error.log".to_string()));

    Ok(())
}

/// Given: Files of different sizes
/// When: safe_find is called with min_only size range filter
/// Then: Only files with size >= min are found
#[test]
fn test_safe_find_min_only_size_filter() -> Result<()> {
    init_test_logger();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let tiny_file = temp_dir.child("tiny.txt");
    tiny_file.write_str("hi")?; // 2 bytes

    let medium_file = temp_dir.child("medium.txt");
    medium_file.write_str("this is medium content")?; // 22 bytes

    let large_file = temp_dir.child("large.txt");
    large_file.write_str(&get_rand_string_of_len(100))?; // 100 bytes

    let mut found_files = Vec::<String>::new();
    let callback = |entry: &WalkEntry| -> Result<(), RustSafeIoError> {
        if let WalkEntry::Entry(dir_entry) = entry {
            if dir_entry.is_file() {
                found_files.push(dir_entry.name().to_string());
            }
        }
        Ok(())
    };

    let find_options = FindOptionsBuilder::default()
        .size_range(SizeRange::min_only(20, SizeUnit::Bytes))
        .build()
        .unwrap();

    dir_handle.safe_find(&DEFAULT_TEST_CEDAR_AUTH, find_options, callback)?;

    assert_eq!(found_files.len(), 2);
    assert!(found_files.contains(&"medium.txt".to_string()));
    assert!(found_files.contains(&"large.txt".to_string()));
    assert!(!found_files.contains(&"tiny.txt".to_string()));

    Ok(())
}

/// Given: A directory tree with root and 5 levels of nested subdirectories, each containing a text file stating which level it is
/// When: safe_find is called with safe_read as the callback
/// Then: All files are found and their contents are correctly read, verifying the integration of directory traversal and file reading
#[test]
fn test_safe_find_with_safe_read_callback_nested_levels() -> Result<()> {
    init_test_logger();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let _level_1_file = create_file_with_content(&temp_dir_path, "level_1.txt", "Level 1");

    let level1_dir = temp_dir.child("level1");
    level1_dir.create_dir_all()?;
    let _level_2_file = create_file_with_content(&level1_dir.path(), "level_2.txt", "Level 2");

    let level2_dir = level1_dir.child("level2");
    level2_dir.create_dir_all()?;
    let _level_3_file = create_file_with_content(&level2_dir.path(), "level_3.txt", "Level 3");

    let level3_dir = level2_dir.child("level3");
    level3_dir.create_dir_all()?;
    let _level_4_file = create_file_with_content(&level3_dir.path(), "level_4.txt", "Level 4");

    let level4_dir = level3_dir.child("level4");
    level4_dir.create_dir_all()?;
    let _level_5_file = create_file_with_content(&level4_dir.path(), "level_5.txt", "Level 5");

    let level5_dir = level4_dir.child("level5");
    level5_dir.create_dir_all()?;
    let _level_6_file = create_file_with_content(&level5_dir.path(), "level_6.txt", "Level 6");

    let mut found_files = Vec::<(String, String)>::new();

    let callback = |entry: &WalkEntry| -> Result<(), RustSafeIoError> {
        match entry {
            WalkEntry::Entry(dir_entry) => {
                if dir_entry.is_file() {
                    let mut owned_entry = dir_entry.clone();
                    let file_handle = owned_entry.open_as_file(
                        &DEFAULT_TEST_CEDAR_AUTH,
                        OpenFileOptionsBuilder::default()
                            .read(true)
                            .build()
                            .unwrap(),
                    )?;

                    let content = file_handle.safe_read(&DEFAULT_TEST_CEDAR_AUTH)?;
                    let file_name = dir_entry.name().to_string();
                    found_files.push((file_name, content));
                }
                Ok(())
            }
            _ => Ok(()),
        }
    };

    let find_options = FindOptionsBuilder::default()
        .min_depth(2)
        .max_depth(4)
        .build()
        .unwrap();
    dir_handle.safe_find(&DEFAULT_TEST_CEDAR_AUTH, find_options, callback)?;

    assert_eq!(found_files.len(), 3, "Expected to find exactly 3 files");

    let expected_files = vec![
        ("level_2.txt", "Level 2"),
        ("level_3.txt", "Level 3"),
        ("level_4.txt", "Level 4"),
    ];

    for (expected_name, expected_content) in expected_files {
        let found_file = found_files
            .iter()
            .find(|(name, _)| name == expected_name)
            .unwrap_or_else(|| panic!("Expected to find file: {}", expected_name));

        assert_eq!(
            found_file.1, expected_content,
            "Expected file {} to contain '{}', but found '{}'",
            expected_name, expected_content, found_file.1
        );
    }

    Ok(())
}

/// Given: A directory structure with accessible and Cedar-denied subdirectories at depth 1
/// When: safe_find is called with safe_read as callback and Cedar denies access to one subdirectory during traversal
/// Then: Only files from accessible directories are found and read
#[test]
fn test_safe_find_with_safe_read_callback_denied_subdir_below_min_depth() -> Result<()> {
    init_test_logger();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let level1_allowed = temp_dir.child("level1_allowed");
    level1_allowed.create_dir_all()?;
    let level1_denied = temp_dir.child("level1_denied");
    level1_denied.create_dir_all()?;

    let level2_allowed = level1_allowed.child("level2_allowed");
    level2_allowed.create_dir_all()?;
    let level2_denied = level1_denied.child("level2_denied");
    level2_denied.create_dir_all()?;

    let _ = create_file_with_content(
        &level2_allowed.path(),
        "level3_allowed_file.txt",
        "allowed content",
    );
    let _ = create_file_with_content(
        &level2_denied.path(),
        "level3_denied_file.txt",
        "denied content",
    );

    let principal = get_test_rex_principal();
    let level1_denied_path = level1_denied.path().to_string_lossy();
    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action,
            resource
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::Dir::"{level1_denied_path}"
        );"#,
        FilesystemAction::Read
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let mut found_files = Vec::<(String, String)>::new();

    let callback = |entry: &WalkEntry| -> Result<(), RustSafeIoError> {
        match entry {
            WalkEntry::Entry(dir_entry) => {
                if dir_entry.is_file() {
                    let mut owned_entry = dir_entry.clone();
                    let file_handle = owned_entry.open_as_file(
                        &test_cedar_auth,
                        OpenFileOptionsBuilder::default()
                            .read(true)
                            .build()
                            .unwrap(),
                    )?;

                    let content = file_handle.safe_read(&test_cedar_auth)?;
                    let file_name = dir_entry.name().to_string();
                    found_files.push((file_name, content));
                }
                Ok(())
            }
            _ => Ok(()),
        }
    };

    let find_options = FindOptionsBuilder::default().min_depth(2).build().unwrap();
    let _ = dir_handle.safe_find(&test_cedar_auth, find_options, callback);

    assert_eq!(found_files.len(), 1, "Expected to find exactly 1 files");
    assert_eq!(found_files[0].0, "level3_allowed_file.txt");
    assert_eq!(found_files[0].1, "allowed content");

    Ok(())
}

/// Given: A directory with a file, a symlink to that file, a directory, and a symlink to that directory
/// When: safe_find is called with follow_symlinks=true
/// Then: Files are deduplicated by inode and only one path to each file is returned
#[test]
#[cfg(unix)]
fn test_symlink_deduplication_by_inode() -> Result<()> {
    init_test_logger();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let target_file = temp_dir.child("target.txt");
    target_file.write_str("target file content")?;

    let target_dir = temp_dir.child("target_dir");
    target_dir.create_dir_all()?;
    let nested_file = target_dir.child("nested.txt");
    nested_file.write_str("nested file content")?;

    temp_dir.child("file_link").symlink_to_file("target.txt")?;

    let mut found_files = Vec::<String>::new();

    let callback = |entry: &WalkEntry| -> Result<(), RustSafeIoError> {
        if let WalkEntry::Entry(dir_entry) = entry {
            if dir_entry.is_file() {
                found_files.push(dir_entry.name().to_string());

                if dir_entry.name() == "file_link" {
                    let mut owned_entry = dir_entry.clone();
                    let file_handle = owned_entry.open_as_file(
                        &DEFAULT_TEST_CEDAR_AUTH,
                        OpenFileOptionsBuilder::default()
                            .read(true)
                            .build()
                            .unwrap(),
                    )?;
                    let content = file_handle.safe_read(&DEFAULT_TEST_CEDAR_AUTH)?;
                    assert_eq!(content, "target file content");
                }
            }
        }
        Ok(())
    };

    let find_options = FindOptionsBuilder::default()
        .follow_symlinks(true)
        .build()
        .unwrap();

    dir_handle.safe_find(&DEFAULT_TEST_CEDAR_AUTH, find_options, callback)?;

    assert_eq!(found_files.len(), 2);

    let target_content_found = found_files
        .iter()
        .any(|name| name == "target.txt" || name == "file_link");
    assert!(
        target_content_found,
        "Should find target file through at least one path"
    );

    assert!(found_files.iter().any(|name| name == "nested.txt"));

    Ok(())
}

/// Given: A symlink at depth below min_depth
/// When: safe_find is called with min_depth=3 and follow_symlinks=true
/// Then: The original file and both symlinks at depth 1 are filtered out
#[test]
#[cfg(unix)]
fn test_safe_find_symlink_filtered_out_by_depth() -> Result<()> {
    init_test_logger();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let target_file = temp_dir.child("target.txt");
    target_file.write_str("target content")?;

    let parent = temp_dir.child("parent");
    parent.create_dir_all()?;
    let subdir = parent.child("subdir");
    subdir.create_dir_all()?;
    let nested_file = subdir.child("nested.txt");
    nested_file.write_str("nested content")?;

    temp_dir.child("root_link").symlink_to_file("target.txt")?;
    temp_dir.child("dir_link").symlink_to_dir(subdir.path())?;

    let mut found_files = Vec::<String>::new();
    let callback = |entry: &WalkEntry| -> Result<(), RustSafeIoError> {
        if let WalkEntry::Entry(dir_entry) = entry {
            if dir_entry.is_file() {
                found_files.push(dir_entry.name().to_string());
            }
        }
        Ok(())
    };

    let find_options = FindOptionsBuilder::default()
        .follow_symlinks(true)
        .min_depth(3)
        .build()
        .unwrap();

    dir_handle.safe_find(&DEFAULT_TEST_CEDAR_AUTH, find_options, callback)?;

    assert_eq!(found_files.len(), 1);
    assert_eq!(found_files[0], "nested.txt");
    assert!(!found_files.contains(&"root_link".to_string()));

    Ok(())
}

/// Given: A symlink to a deeply nested directory that's unreachable by normal traversal
/// When: safe_find is called with max_depth=2 and follow_symlinks=true
/// Then: The file is found at depth 2 through the symlink shortcut
#[test]
#[cfg(target_os = "linux")]
fn test_symlink_reaches_unreachable_directory() -> Result<()> {
    init_test_logger();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let level1 = temp_dir.child("level1");
    level1.create_dir_all()?;
    let level2 = level1.child("level2");
    level2.create_dir_all()?;
    let level3 = level2.child("level3");
    level3.create_dir_all()?;
    let target_file = level3.child("deep_file.txt");
    target_file.write_str("deep content")?;

    temp_dir.child("shortcut").symlink_to_dir(level3.path())?;

    let mut found_files = Vec::<String>::new();
    let callback = |entry: &WalkEntry| -> Result<(), RustSafeIoError> {
        if let WalkEntry::Entry(dir_entry) = entry {
            if dir_entry.is_file() {
                found_files.push(dir_entry.name().to_string());
            }
        }
        Ok(())
    };

    let find_options = FindOptionsBuilder::default()
        .follow_symlinks(true)
        .max_depth(2)
        .build()
        .unwrap();

    dir_handle.safe_find(&DEFAULT_TEST_CEDAR_AUTH, find_options, callback)?;

    assert_eq!(found_files.len(), 1);
    assert_eq!(found_files[0], "deep_file.txt");

    Ok(())
}

/// Given: A symlink to target directory which the user is unauthorized to open
/// When: safe_find is called with follow_symlinks=true
/// Then: handle_symlink fails gracefully when trying to open target directory and the symlink entry is skipped
#[test]
#[cfg(unix)]
fn test_symlink_target_directory_access_denied() -> Result<()> {
    init_test_logger();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let target_dir = temp_dir.child("secret_dir");
    target_dir.create_dir_all()?;
    let target_file = target_dir.child("secret.txt");
    target_file.write_str("secret content")?;

    temp_dir.child("link").symlink_to_dir("secret_dir")?;

    let principal = get_test_rex_principal();
    let secret_path = target_dir.path().to_string_lossy();
    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action,
            resource
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::Dir::"{secret_path}"
        );"#,
        FilesystemAction::Open
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let mut found_entries = Vec::<String>::new();
    let callback = |entry: &WalkEntry| -> Result<(), RustSafeIoError> {
        if let WalkEntry::Entry(dir_entry) = entry {
            found_entries.push(dir_entry.name().to_string());
        }
        Ok(())
    };

    let find_options = FindOptionsBuilder::default()
        .follow_symlinks(true)
        .build()
        .unwrap();

    dir_handle.safe_find(&test_cedar_auth, find_options, callback)?;

    assert_eq!(found_entries.len(), 0);

    Ok(())
}

/// Given: A symlink to target file which the user is unauthorized to stat
/// When: safe_find is called with follow_symlinks=true
/// Then: symlink_target_metadata fails, a warning is logged, and no entries are returned
#[test]
#[cfg(unix)]
fn test_symlink_target_metadata_access_denied() -> Result<()> {
    init_test_logger();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let subdir1 = temp_dir.child("subdir1");
    subdir1.create_dir_all()?;
    let subdir2 = subdir1.child("subdir2");
    subdir2.create_dir_all()?;
    let target_file = subdir2.child("protected.txt");
    target_file.write_str("protected content")?;

    temp_dir.child("link").symlink_to_file("protected.txt")?;

    let principal = get_test_rex_principal();
    let protected_path = target_file.path().to_string_lossy();
    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action,
            resource
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{protected_path}"
        );"#,
        FilesystemAction::Stat // Deny getting metadata of target
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let mut found_entries = Vec::<String>::new();
    let callback = |entry: &WalkEntry| -> Result<(), RustSafeIoError> {
        if let WalkEntry::Entry(dir_entry) = entry {
            if dir_entry.is_file() {
                found_entries.push(dir_entry.name().to_string());
            }
        }
        Ok(())
    };

    let find_options = FindOptionsBuilder::default()
        .follow_symlinks(true)
        .max_depth(2)
        .build()
        .unwrap();

    dir_handle.safe_find(&test_cedar_auth, find_options, callback)?;

    assert_eq!(found_entries.len(), 0);

    Ok(())
}

/// Given: Two symlinks at pointing to the same nested directory
/// When: safe_find is called with follow_symlinks=true
/// Then: The target directory is traversed only once and the file is found only once
#[test]
#[cfg(unix)]
fn test_symlink_duplicate_directory_inode_detection() -> Result<()> {
    init_test_logger();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let subdir = temp_dir.child("subdir");
    subdir.create_dir_all()?;
    let target_dir = subdir.child("target");
    target_dir.create_dir_all()?;
    let target_file = target_dir.child("file.txt");
    target_file.write_str("content")?;

    temp_dir.child("symlink1").symlink_to_dir("subdir/target")?;
    subdir.child("symlink2").symlink_to_dir(subdir.path())?;

    let mut found_files = Vec::<String>::new();
    let callback = |entry: &WalkEntry| -> Result<(), RustSafeIoError> {
        if let WalkEntry::Entry(dir_entry) = entry {
            if dir_entry.is_file() {
                found_files.push(dir_entry.name().to_string());
            }
        }
        Ok(())
    };

    let find_options = FindOptionsBuilder::default()
        .follow_symlinks(true)
        .build()
        .unwrap();

    dir_handle.safe_find(&DEFAULT_TEST_CEDAR_AUTH, find_options, callback)?;

    assert_eq!(found_files.len(), 1);
    assert!(found_files.contains(&"file.txt".to_string()));

    Ok(())
}

/// Given: A file in the root directory and a symlink in a subdirectory pointing to that file
/// When: safe_find is called with follow_symlinks=true
/// Then: Only one entry is returned
#[test]
#[cfg(unix)]
fn test_symlink_cross_directory_within_sandbox() -> Result<()> {
    init_test_logger();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let subdir = temp_dir.child("subdir");
    subdir.create_dir_all()?;

    let target_file = temp_dir.child("target.txt");
    target_file.write_str("target content")?;

    subdir.child("link").symlink_to_file(target_file.path())?;
    let mut found_files = Vec::<String>::new();

    let callback = |entry: &WalkEntry| -> Result<(), RustSafeIoError> {
        if let WalkEntry::Entry(dir_entry) = entry {
            if dir_entry.is_file() {
                found_files.push(dir_entry.name().to_string());
            }
        }
        Ok(())
    };

    let find_options = FindOptionsBuilder::default()
        .follow_symlinks(true)
        .build()
        .unwrap();

    dir_handle.safe_find(&DEFAULT_TEST_CEDAR_AUTH, find_options, callback)?;

    assert_eq!(found_files.len(), 1);

    let found_name = &found_files[0];
    assert!(
        found_name == "link" || found_name == "target.txt",
        "Should find target file through one path"
    );

    Ok(())
}

/// Given: A file nested in a subdirectory with a distinctive name
/// When: safe_find is called with a regex that matches the directory path but not the filename
/// Then: The file is found because regex matching uses the full path
#[test]
fn test_safe_find_regex_matches_path_not_name() -> Result<()> {
    init_test_logger();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let root_file = temp_dir.child("other.txt");
    root_file.write_str("other content")?;

    let special_dir = temp_dir.child("special_dir");
    special_dir.create_dir_all()?;

    let target_file = special_dir.child("file.txt");
    target_file.write_str("content")?;

    let mut found_files = Vec::<String>::new();
    let callback = |entry: &WalkEntry| -> Result<(), RustSafeIoError> {
        if let WalkEntry::Entry(dir_entry) = entry {
            if dir_entry.is_file() {
                found_files.push(dir_entry.name().to_string());
            }
        }
        Ok(())
    };

    let find_options = FindOptionsBuilder::default()
        .regex(r".*special_dir.*")
        .build()
        .unwrap();

    dir_handle.safe_find(&DEFAULT_TEST_CEDAR_AUTH, find_options, callback)?;

    assert_eq!(found_files.len(), 1);
    assert_eq!(found_files[0], "file.txt");

    Ok(())
}
