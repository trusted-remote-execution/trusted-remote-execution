use rex_cedar_auth::test_utils::DEFAULT_TEST_CEDAR_AUTH;
use rex_test_utils::io::create_temp_dir;
use rust_safe_io::DirConfigBuilder;
use rust_safe_io::options::OpenDirOptionsBuilder;

use anyhow::Result;
use assert_fs::fixture::SymlinkToDir;
use assert_fs::prelude::{PathChild, PathCreateDir};

/// Given: A path that is a symlink pointing to a real directory, and follow_symlinks=true
/// When: DirConfig::safe_open is called with follow_symlinks=true
/// Then: The returned handle's path is the resolved real directory path (via F_GETPATH on macOS),
///       not the symlink path itself
#[test]
fn test_safe_open_dir_follow_symlink_resolves_real_path() -> Result<()> {
    let temp_dir = create_temp_dir()?;
    let real_dir = temp_dir.child("real_dir");
    real_dir.create_dir_all()?;

    let symlink_dir = temp_dir.child("link_to_real_dir");
    symlink_dir.symlink_to_dir(real_dir.path())?;

    let real_dir_path = real_dir.path().to_string_lossy().to_string();
    let symlink_path = symlink_dir.path().to_string_lossy().to_string();

    // Open via the symlink path with follow_symlinks=true
    let dir_handle = DirConfigBuilder::default()
        .path(symlink_path.clone())
        .build()?
        .safe_open(
            &DEFAULT_TEST_CEDAR_AUTH,
            OpenDirOptionsBuilder::default()
                .follow_symlinks(true)
                .build()?,
        )?;

    // The handle's path should be the real resolved path, not the symlink path
    let handle_path = dir_handle.to_string();
    assert_eq!(
        handle_path, real_dir_path,
        "Expected resolved path '{}' but got '{}'",
        real_dir_path, handle_path
    );

    Ok(())
}
