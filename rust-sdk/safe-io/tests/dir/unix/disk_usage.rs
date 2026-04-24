#![cfg(target_os = "linux")]
use crate::test_common::open_test_dir_handle;
use anyhow::Result;
use assert_fs::prelude::*;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::io::{create_file_with_content, create_temp_dir_and_path};
use rstest::rstest;
use rust_safe_io::DirConfigBuilder;
use rust_safe_io::options::{DiskUsageOptionsBuilder, OpenDirOptionsBuilder};
use std::fs::{Permissions, hard_link, metadata, set_permissions};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::process::Command;
use tracing::Level;
use tracing_subscriber::fmt;

fn init_test_logger() {
    let _ = fmt::Subscriber::builder()
        .with_max_level(Level::WARN)
        .with_test_writer()
        .try_init();
}

fn create_hard_link_structure(
    temp_dir: &assert_fs::TempDir,
    num_links: usize,
    content_size: usize,
) -> Result<(
    assert_fs::fixture::ChildPath,
    Vec<std::path::PathBuf>,
    usize,
)> {
    let original = temp_dir.child("original.txt");
    let content = "X".repeat(content_size);
    original.write_str(&content)?;

    let mut link_paths = Vec::new();

    let subdir1 = temp_dir.child("subdir1");
    subdir1.create_dir_all()?;
    let subdir2 = temp_dir.child("subdir2");
    subdir2.create_dir_all()?;

    for i in 1..num_links {
        let link_path = if i % 3 == 1 {
            temp_dir.path().join(format!("link{}.txt", i))
        } else if i % 3 == 2 {
            subdir1.path().join(format!("link{}.txt", i))
        } else {
            subdir2.path().join(format!("link{}.txt", i))
        };
        hard_link(original.path(), &link_path)?;
        link_paths.push(link_path);
    }

    let expected_link_count = num_links;

    Ok((original, link_paths, expected_link_count))
}

/// Helper to compare safe_disk_usage results with actual du command
fn compare_with_du(
    test_path: &str,
    apparent_size: bool,
    all_files: bool,
    summarize: bool,
    max_depth: Option<i64>,
    one_file_system: bool,
    count_links: bool,
    inodes: bool,
) -> Result<()> {
    let dir_handle = DirConfigBuilder::default()
        .path(test_path.to_string())
        .build()?
        .safe_open(
            &DEFAULT_TEST_CEDAR_AUTH,
            OpenDirOptionsBuilder::default().build()?,
        )?;

    let mut options_builder = DiskUsageOptionsBuilder::default();
    options_builder
        .apparent_size(apparent_size)
        .all_files(all_files)
        .summarize(summarize)
        .one_file_system(one_file_system)
        .count_hard_links(count_links);

    if let Some(depth) = max_depth {
        options_builder.max_depth(depth);
    }

    let options = options_builder.build()?;

    let result = dir_handle.safe_disk_usage(&DEFAULT_TEST_CEDAR_AUTH, options)?;
    let safe_results = result.entries();
    let mut cmd = Command::new("du");
    if inodes {
        cmd.arg("--inodes");
    } else {
        cmd.arg("--block-size=1");
        if apparent_size {
            cmd.arg("--apparent-size");
        }
    }
    if all_files {
        cmd.arg("-a");
    }
    if summarize {
        cmd.arg("-s");
    }
    if let Some(depth) = max_depth {
        cmd.arg(format!("--max-depth={}", depth));
    }
    if one_file_system {
        cmd.arg("-x");
    }
    if count_links {
        cmd.arg("--count-links");
    }
    cmd.arg(test_path);

    let du_output = cmd.output()?;
    let stdout = String::from_utf8(du_output.stdout)?;

    let du_ordered: Vec<(String, u64)> = stdout
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let size: u64 = parts[0].parse().ok()?;
                let path = parts[1..].join(" ");
                Some((path, size))
            } else {
                None
            }
        })
        .collect();

    let metric_name = if inodes { "inode count" } else { "size" };

    assert_eq!(
        safe_results.len(),
        du_ordered.len(),
        "Result count mismatch: safe_disk_usage has {} items, du has {} items",
        safe_results.len(),
        du_ordered.len()
    );

    for (i, (safe_entry, (du_path, du_value))) in
        safe_results.iter().zip(du_ordered.iter()).enumerate()
    {
        assert_eq!(
            safe_entry.path(),
            du_path,
            "Order mismatch at position {}: safe_disk_usage='{}' vs du='{}'",
            i,
            safe_entry.path(),
            du_path
        );

        let safe_value = if inodes {
            *safe_entry.inode_count()
        } else {
            *safe_entry.size_bytes()
        };

        assert_eq!(
            safe_value,
            *du_value,
            "{} mismatch at position {} for {}: safe_disk_usage={}, du={}",
            metric_name,
            i,
            safe_entry.path(),
            safe_value,
            du_value
        );
    }

    Ok(())
}

/// Given: A directory with subdirectories and files
/// When: safe_disk_usage is called with default options
/// Then: Results match the actual du command output
#[test]
fn test_safe_disk_usage_basic() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let subdir1 = temp_dir.child("subdir1");
    subdir1.create_dir_all()?;
    create_file_with_content(
        &subdir1.path(),
        "nested1.txt",
        &"Nested content 1".repeat(100),
    )?;

    let subdir2 = temp_dir.child("subdir2");
    subdir2.create_dir_all()?;
    create_file_with_content(&subdir2.path(), "nested2.txt", "Nested content 2")?;

    let deep_dir = subdir1.child("deep");
    deep_dir.create_dir_all()?;
    create_file_with_content(&deep_dir.path(), "deep.txt", "Deep content")?;

    compare_with_du(
        &temp_dir_path,
        false,
        false,
        false,
        None,
        false,
        false,
        false,
    )?;

    Ok(())
}

/// Given: A directory structure
/// When: safe_disk_usage is called with apparent_size=true
/// Then: Results match du --apparent-size output
#[test]
fn test_safe_disk_usage_apparent_size() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    create_file_with_content(&temp_dir.path(), "small.txt", "x")?;
    create_file_with_content(&temp_dir.path(), "medium.txt", &"y".repeat(1000))?;

    compare_with_du(
        &temp_dir_path,
        true,
        false,
        false,
        None,
        false,
        false,
        false,
    )?;

    Ok(())
}

/// Given: A directory structure
/// When: safe_disk_usage is called with all_files=true
/// Then: Results include all files and match du -a output
#[test]
fn test_safe_disk_usage_all_files() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    create_file_with_content(&temp_dir.path(), "root.txt", "Root file")?;

    let subdir = temp_dir.child("subdir");
    subdir.create_dir_all()?;
    create_file_with_content(&subdir.path(), "sub.txt", "Sub file")?;

    compare_with_du(
        &temp_dir_path,
        false,
        true,
        false,
        None,
        false,
        false,
        false,
    )?;

    Ok(())
}

/// Given: A directory structure
/// When: safe_disk_usage is called with summarize=true
/// Then: Results show only the total and match du -s output
#[test]
fn test_safe_disk_usage_summarize() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    create_file_with_content(&temp_dir.path(), "file1.txt", "Content 1")?;

    let subdir = temp_dir.child("subdir");
    subdir.create_dir_all()?;
    create_file_with_content(&subdir.path(), "file2.txt", "Content 2")?;

    compare_with_du(
        &temp_dir_path,
        false,
        false,
        true,
        None,
        false,
        false,
        false,
    )?;

    Ok(())
}

/// Given: A deep directory structure
/// When: safe_disk_usage is called with max_depth set
/// Then: Results max_depth and match du --max-depth output
#[rstest]
#[case::depth_0(0)]
#[case::depth_1(1)]
#[case::depth_2(2)]
fn test_safe_disk_usage_max_depth(#[case] depth: i64) -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    create_file_with_content(&temp_dir.path(), "root.txt", "Root")?;

    let level1 = temp_dir.child("level1");
    level1.create_dir_all()?;
    create_file_with_content(&level1.path(), "l1.txt", "Level 1")?;

    let level2 = level1.child("level2");
    level2.create_dir_all()?;
    create_file_with_content(&level2.path(), "l2.txt", "Level 2")?;

    let level3 = level2.child("level3");
    level3.create_dir_all()?;
    create_file_with_content(&level3.path(), "l3.txt", "Level 3")?;

    compare_with_du(
        &temp_dir_path,
        false,
        false,
        false,
        Some(depth),
        false,
        false,
        false,
    )?;

    Ok(())
}

/// Given: A directory with specified number of hard links across subdirectories
/// When: safe_disk_usage is called with and without count_hard_links
/// Then: Results match du behavior with and without --count-links flag
#[rstest]
#[case::two_links_no_count(2, 1000, false)]
#[case::two_links_with_count(2, 1000, true)]
#[case::four_links_no_count(4, 2000, false)]
#[case::four_links_with_count(4, 2000, true)]
fn test_safe_disk_usage_hard_link_counting(
    #[case] num_links: usize,
    #[case] content_size: usize,
    #[case] count_links: bool,
) -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let (original, link_paths, expected_link_count) =
        create_hard_link_structure(&temp_dir, num_links, content_size)?;

    let original_metadata = metadata(original.path())?;
    for link_path in &link_paths {
        let link_metadata = metadata(link_path)?;
        assert_eq!(
            original_metadata.ino(),
            link_metadata.ino(),
            "Link should point to same inode as original"
        );
    }

    assert_eq!(
        original_metadata.nlink(),
        expected_link_count as u64,
        "Should have {} hard links",
        expected_link_count
    );

    compare_with_du(
        &temp_dir_path,
        false,
        false,
        false,
        None,
        false,
        count_links,
        false,
    )?;

    Ok(())
}

/// Given: A directory with empty (0-byte) files
/// When: safe_disk_usage is called with apparent_size=true and false
/// Then: apparent_size=true shows 0, apparent_size=false shows block size
#[rstest]
#[case::with_apparent_size(true)]
#[case::without_apparent_size(false)]
fn test_safe_disk_usage_empty_files(#[case] apparent_size: bool) -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    temp_dir.child("empty.txt").write_str("")?;
    temp_dir.child("empty2.txt").write_str("")?;

    compare_with_du(
        &temp_dir_path,
        apparent_size,
        true,
        false,
        None,
        false,
        false,
        false,
    )?;

    Ok(())
}

/// Given: A directory structure spanning multiple filesystems
/// When: safe_disk_usage is called with one_file_system=true
/// Then: Only files on the same filesystem are counted
#[test]
fn test_safe_disk_usage_one_file_system() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    create_file_with_content(&temp_dir.path(), "test.txt", "Test content")?;

    compare_with_du(
        &temp_dir_path,
        false,
        false,
        false,
        None,
        true,
        false,
        false,
    )?;

    Ok(())
}

/// Given: An empty directory
/// When: safe_disk_usage is called
/// Then: Results show only the directory itself with minimal size
#[test]
fn test_safe_disk_usage_empty_directory() -> Result<()> {
    let (_temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    compare_with_du(
        &temp_dir_path,
        false,
        false,
        false,
        None,
        false,
        false,
        false,
    )?;

    Ok(())
}

/// Given: A directory with symbolic links
/// When: safe_disk_usage is called
/// Then: Symbolic links themselves are counted, not their targets
#[test]
fn test_safe_disk_usage_with_symlinks() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let target = temp_dir.child("target.txt");
    target.write_str("Target file content")?;

    let symlink = temp_dir.child("link.txt");
    symlink.symlink_to_file(target.path())?;

    compare_with_du(
        &temp_dir_path,
        false,
        false,
        false,
        None,
        false,
        false,
        false,
    )?;

    Ok(())
}

/// Given: A directory structure
/// When: safe_disk_usage is called
/// Then: Inode counts are tracked correctly (matching du --inodes)
#[test]
fn test_safe_disk_usage_inode_counts() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    create_file_with_content(&temp_dir.path(), "file1.txt", "File 1")?;
    create_file_with_content(&temp_dir.path(), "file2.txt", "File 2")?;

    let subdir = temp_dir.child("subdir");
    subdir.create_dir_all()?;
    create_file_with_content(&subdir.path(), "file3.txt", "File 3")?;

    compare_with_du(
        &temp_dir_path,
        false,
        false,
        false,
        None,
        false,
        false,
        true,
    )?;

    Ok(())
}

/// Given: A directory with all_files and max_depth options
/// When: safe_disk_usage is called
/// Then: File entries respect max_depth constraint (matching du -a --max-depth)
#[test]
fn test_safe_disk_usage_all_files_with_max_depth() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    create_file_with_content(&temp_dir.path(), "root.txt", "Root")?;

    let level1 = temp_dir.child("level1");
    level1.create_dir_all()?;
    create_file_with_content(&level1.path(), "l1.txt", "L1")?;

    let level2 = level1.child("level2");
    level2.create_dir_all()?;
    create_file_with_content(&level2.path(), "l2.txt", "L2")?;

    compare_with_du(
        &temp_dir_path,
        false,
        true,
        false,
        Some(1),
        false,
        false,
        false,
    )?;

    Ok(())
}

/// Given: A directory containing special file types (FIFO, socket)
/// When: safe_disk_usage is called with different options
/// Then: Special files are handled correctly (0 bytes for sockets/FIFOs, 1 inode, matching du behavior)
#[rstest]
#[case::block_size(false)]
#[case::apparent_size(true)]
fn test_safe_disk_usage_special_files(#[case] apparent_size: bool) -> Result<()> {
    let (_temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    create_file_with_content(&_temp_dir.path(), "regular.txt", "Regular file")?;

    // Create FIFO
    let fifo_path = _temp_dir.path().join("test.fifo");
    let fifo_path_str = fifo_path.to_string_lossy().to_string();
    Command::new("mkfifo")
        .arg(&fifo_path_str)
        .status()
        .expect("Failed to create FIFO");

    // Create Unix socket
    let socket_path = _temp_dir.path().join("test.sock");
    let _listener = UnixListener::bind(&socket_path)?;

    compare_with_du(
        &temp_dir_path,
        apparent_size,
        true,
        false,
        None,
        false,
        false,
        false,
    )?;

    Ok(())
}

/// Given: Root directory Stat permission denied by Cedar  
/// When: safe_disk_usage is called
/// Then: An authorization error (matches GNU du: "cannot access .: Permission denied")
#[test]
fn test_safe_disk_usage_root_inaccessible() -> Result<()> {
    let (_temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action,
            resource
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::Dir::"{temp_dir_path}"
        );"#,
        FilesystemAction::Stat
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()?
        .create();

    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let options = DiskUsageOptionsBuilder::default().build()?;
    let result = dir_handle.safe_disk_usage(&test_cedar_auth, options);

    assert!(result.is_err());

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Stat
    );

    assert_error_contains(result, &expected_error);

    Ok(())
}

/// Given: Various Cedar policy restrictions on different filesystem actions
/// When: safe_disk_usage encounters denied actions during traversal
/// Then: Appropriate errors are returned or warnings are logged
#[rstest]
#[case::open_denied(FilesystemAction::Open)]
#[case::stat_denied(FilesystemAction::Stat)]
#[case::read_denied(FilesystemAction::Read)]
fn test_safe_disk_usage_authorization_denials(
    #[case] denied_action: FilesystemAction,
) -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    create_file_with_content(&temp_dir.path(), "accessible.txt", "Accessible")?;

    let subdir = temp_dir.child("restricted_subdir");
    subdir.create_dir_all()?;
    create_file_with_content(&subdir.path(), "restricted.txt", "Restricted")?;

    let principal = get_test_rex_principal();
    let subdir_path = subdir.path().to_string_lossy();

    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action,
            resource
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::Dir::"{subdir_path}"
        );"#,
        denied_action
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()?
        .create();

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let options = DiskUsageOptionsBuilder::default().build()?;
    let result = dir_handle.safe_disk_usage(&test_cedar_auth, options)?;

    let root_entry = result
        .entries()
        .iter()
        .find(|e| e.path() == &temp_dir_path)
        .expect("Root should be in results");

    assert!(*root_entry.size_bytes() > 0);

    let subdir_entry = result
        .entries()
        .iter()
        .find(|e| e.path() == subdir_path.as_ref());
    assert!(subdir_entry.is_none());

    let restricted_file_path = format!("{}/restricted.txt", subdir_path);
    assert!(
        !result
            .entries()
            .iter()
            .any(|e| e.path() == &restricted_file_path)
    );

    Ok(())
}

/// Given: A directory with unreadable subdirectory (OS-level permission error)
/// When: safe_disk_usage is called
/// Then: Accessible parts are counted, inaccessible directory is skipped with warning and still calculated correctly
#[test]
fn test_safe_disk_usage_with_permission_errors() -> Result<()> {
    init_test_logger();

    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    create_file_with_content(&temp_dir.path(), "accessible.txt", "Accessible file")?;

    let restricted = temp_dir.child("restricted");
    restricted.create_dir_all()?;
    create_file_with_content(&restricted.path(), "hidden.txt", "Hidden file")?;

    set_permissions(restricted.path(), Permissions::from_mode(0o000))?;

    let dir_handle = DirConfigBuilder::default()
        .path(temp_dir_path.clone())
        .build()?
        .safe_open(
            &DEFAULT_TEST_CEDAR_AUTH,
            OpenDirOptionsBuilder::default().build()?,
        )?;

    let options = DiskUsageOptionsBuilder::default().build()?;
    let result = dir_handle.safe_disk_usage(&DEFAULT_TEST_CEDAR_AUTH, options);

    assert!(result.is_ok());

    let results = result?;

    assert!(results.entries().iter().any(|e| e.path() == &temp_dir_path));

    let restricted_path = restricted.path().to_string_lossy().to_string();
    assert!(
        !results
            .entries()
            .iter()
            .any(|e| e.path() == &restricted_path),
    );

    Ok(())
}

/// Given: A file within an accessible directory has Cedar Open permission denied
/// When: safe_disk_usage attempts to get file metadata during traversal
/// Then: File is skipped with warning in Entry handler, directory total still calculated correctly
#[test]
fn test_safe_disk_usage_file_open_denied_in_entry() -> Result<()> {
    init_test_logger();

    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    create_file_with_content(&temp_dir.path(), "accessible_file.txt", "Accessible")?;
    create_file_with_content(&temp_dir.path(), "restricted_file.txt", "Restricted")?;

    let principal = get_test_rex_principal();
    let restricted_file_path = temp_dir.path().join("restricted_file.txt");
    let restricted_file_path_str = restricted_file_path.to_string_lossy();

    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action,
            resource
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{restricted_file_path_str}"
        );"#,
        FilesystemAction::Open
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()?
        .create();

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let options = DiskUsageOptionsBuilder::default().all_files(true).build()?;
    let results = dir_handle.safe_disk_usage(&test_cedar_auth, options)?;

    let root_entry = results
        .entries()
        .iter()
        .find(|e| e.path() == &temp_dir_path);
    assert!(root_entry.is_some(), "Expected root directory in results");

    assert!(
        results
            .entries()
            .iter()
            .any(|e| e.path().ends_with("accessible_file.txt"))
    );
    assert!(
        !results
            .entries()
            .iter()
            .any(|e| e.path().ends_with("restricted_file.txt"))
    );

    Ok(())
}

/// Given: A subdirectory has Cedar Stat permission denied
/// When: safe_disk_usage attempts to get directory metadata during WalkEntry::DirPost traversal
/// Then: Directory is skipped with warning in DirPost handler
#[test]
fn test_safe_disk_usage_dir_stat_denied_in_dirpost() -> Result<()> {
    init_test_logger();

    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    create_file_with_content(&temp_dir.path(), "root_file.txt", "Root")?;

    let subdir = temp_dir.child("restricted_subdir");
    subdir.create_dir_all()?;
    create_file_with_content(&subdir.path(), "subdir_file.txt", "In subdir")?;

    let principal = get_test_rex_principal();
    let subdir_path = subdir.path().to_string_lossy();

    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action,
            resource
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::Dir::"{subdir_path}"
        );"#,
        FilesystemAction::Stat
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()?
        .create();

    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let options = DiskUsageOptionsBuilder::default().build()?;

    let result = dir_handle.safe_disk_usage(&test_cedar_auth, options);

    assert!(result.is_ok());

    let results = result?;

    let root_entry = results
        .entries()
        .iter()
        .find(|e| e.path() == &temp_dir_path);
    assert!(root_entry.is_some(), "Expected root directory in results");

    let subdir_path_str = subdir.path().to_string_lossy().to_string();
    let has_subdir = results
        .entries()
        .iter()
        .any(|e| e.path() == &subdir_path_str);
    assert!(
        !has_subdir,
        "Expected restricted subdirectory to be skipped"
    );

    Ok(())
}

/// Given: A directory structure with subdirectories of varying sizes
/// When: safe_disk_usage is called with track_largest_subdir=true
/// Then: The largest subdirectory is tracked and accessible via handle
#[test]
fn test_track_largest_subdir_excludes_root() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    create_file_with_content(&temp_dir.path(), "root_file.txt", &"X".repeat(10))?;

    let small_dir = temp_dir.child("small_subdir");
    small_dir.create_dir_all()?;
    create_file_with_content(&small_dir.path(), "small.txt", "small")?;

    let large_dir = temp_dir.child("large_subdir");
    large_dir.create_dir_all()?;
    create_file_with_content(&large_dir.path(), "large.txt", &"Y".repeat(50))?;

    let medium_dir = temp_dir.child("medium_subdir");
    medium_dir.create_dir_all()?;
    create_file_with_content(&medium_dir.path(), "medium.txt", &"Z".repeat(20))?;

    let dir_handle = DirConfigBuilder::default()
        .path(temp_dir_path.clone())
        .build()?
        .safe_open(
            &DEFAULT_TEST_CEDAR_AUTH,
            OpenDirOptionsBuilder::default().build()?,
        )?;

    let options = DiskUsageOptionsBuilder::default()
        .track_largest_subdir(true)
        .build()?;

    let result = dir_handle.safe_disk_usage(&DEFAULT_TEST_CEDAR_AUTH, options)?;

    assert!(result.entries().iter().any(|e| e.path() == &temp_dir_path));
    let small_path = small_dir.path().to_string_lossy().to_string();
    let large_path = large_dir.path().to_string_lossy().to_string();
    let medium_path = medium_dir.path().to_string_lossy().to_string();

    assert!(result.entries().iter().any(|e| e.path() == &small_path));
    assert!(result.entries().iter().any(|e| e.path() == &large_path));
    assert!(result.entries().iter().any(|e| e.path() == &medium_path));

    let root_size = result
        .entries()
        .iter()
        .find(|e| e.path() == &temp_dir_path)
        .unwrap()
        .size_bytes();
    let large_size = result
        .entries()
        .iter()
        .find(|e| e.path() == &large_path)
        .unwrap()
        .size_bytes();

    assert!(*root_size > *large_size, "Root should be largest overall");

    assert!(
        result.largest_subdir_handle().is_some(),
        "Should have largest_dir_handle"
    );
    let largest_handle = result.largest_subdir_handle().as_ref().unwrap();

    let metadata = largest_handle.metadata(&DEFAULT_TEST_CEDAR_AUTH)?;
    assert!(
        metadata.device() > 0,
        "Should be able to get metadata from handle"
    );

    Ok(())
}

/// Given: A three-level hierarchy where parent and child are accessible but grandchild is denied
/// When: safe_disk_usage traverses the directory structure
/// Then: Parent and child are counted, grandchild is skipped with warning
#[test]
fn test_safe_disk_usage_nested_authorization() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    create_file_with_content(&temp_dir.path(), "root_file.txt", "Root")?;

    let child_dir = temp_dir.child("child_dir");
    child_dir.create_dir_all()?;
    create_file_with_content(&child_dir.path(), "child_file.txt", "Child")?;

    let grandchild_dir = child_dir.child("grandchild_dir");
    grandchild_dir.create_dir_all()?;
    create_file_with_content(&grandchild_dir.path(), "grandchild_file.txt", "Grandchild")?;

    let principal = get_test_rex_principal();
    let grandchild_path = grandchild_dir.path().to_string_lossy();

    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action,
            resource
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::Dir::"{grandchild_path}"
        );"#,
        FilesystemAction::Read
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()?
        .create();

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let options = DiskUsageOptionsBuilder::default().build()?;
    let results = dir_handle.safe_disk_usage(&test_cedar_auth, options)?;

    let child_path_str = child_dir.path().to_string_lossy().to_string();
    let grandchild_path_str = grandchild_dir.path().to_string_lossy().to_string();

    assert!(results.entries().iter().any(|e| e.path() == &temp_dir_path));
    assert!(
        results
            .entries()
            .iter()
            .any(|e| e.path() == &child_path_str)
    );
    assert!(
        !results
            .entries()
            .iter()
            .any(|e| e.path() == &grandchild_path_str)
    );

    Ok(())
}
