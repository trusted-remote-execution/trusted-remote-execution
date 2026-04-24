use rex_cedar_auth::test_utils::DEFAULT_TEST_CEDAR_AUTH;
use rex_test_utils::io::create_temp_dir_and_path;
use rust_safe_io::error_constants::NOT_A_DIR;

use anyhow::Result;
use rstest::rstest;
use std::path::Path;

use crate::test_common::open_test_dir_handle;

/// Given: Various path inputs including traversal attempts and trailing slashes
/// When: safe_create_sub_directories is called
/// Then: Path traversal is prevented and trailing slashes are handled correctly
#[rstest]
#[case::path_traversal_simple("../../../etc", true)]
#[case::path_traversal_mixed("subdir/../../../etc", true)]
#[case::absolute_path("/etc/passwd", true)]
#[case::absolute_trailing_single("/testdir/", true)]
#[case::trailing_slash("parent/child/", false)]
#[case::normal_path("parent/child", false)]
#[case::empty_path("", false)]
fn test_safe_create_sub_directories_path_validation(
    #[case] path: &str,
    #[case] should_fail: bool,
) -> Result<()> {
    let (_temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let result = dir_handle.safe_create_sub_directories(&DEFAULT_TEST_CEDAR_AUTH, path);

    if should_fail {
        assert!(result.is_err());

        let error_result = result.as_ref();
        let contains_traversal = error_result
            .map_err(|e| e.to_string())
            .unwrap_err()
            .contains("Path traversal detected");
        let contains_symlink = error_result
            .map_err(|e| e.to_string())
            .unwrap_err()
            .contains(NOT_A_DIR);

        assert!(contains_traversal || contains_symlink);
    } else {
        assert!(result.is_ok());

        if !path.is_empty() {
            let created_path = Path::new(&temp_dir_path).join(path);
            assert!(created_path.exists() && created_path.is_dir());
        }
    }

    Ok(())
}
