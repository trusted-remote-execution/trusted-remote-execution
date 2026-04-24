//! `touch` — Create an empty file or update its timestamp
//!
//! # Example (Rhai)
//! ```rhai
//! touch("/tmp/newfile.txt");
//! ```

use rex_cedar_auth::cedar_auth::CedarAuth;
use rust_safe_io::DirConfigBuilder;
use rust_safe_io::errors::RustSafeIoError;
use rust_safe_io::options::{OpenDirOptionsBuilder, OpenFileOptionsBuilder};
use std::path::Path;

/// Creates an empty file (or opens an existing one) at the given path.
pub(crate) fn touch(path: &str, cedar_auth: &CedarAuth) -> Result<(), RustSafeIoError> {
    let path_obj = Path::new(path);

    let dir_path = path_obj
        .parent()
        .map_or_else(|| ".".to_string(), |p| p.to_string_lossy().to_string());

    let file_name = path_obj
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .ok_or_else(|| RustSafeIoError::InvalidArguments {
            reason: format!("Invalid file path: {path}"),
        })?;

    let dir_handle = DirConfigBuilder::default()
        .path(dir_path)
        .build()
        .map_err(|e| RustSafeIoError::InvalidArguments {
            reason: e.to_string(),
        })?
        .safe_open(
            cedar_auth,
            OpenDirOptionsBuilder::default().build().map_err(|e| {
                RustSafeIoError::InvalidArguments {
                    reason: e.to_string(),
                }
            })?,
        )?;

    let _file = dir_handle.safe_open_file(
        cedar_auth,
        &file_name,
        OpenFileOptionsBuilder::default()
            .write(true)
            .create(true)
            .build()
            .map_err(|e| RustSafeIoError::InvalidArguments {
                reason: e.to_string(),
            })?,
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_fs::TempDir;
    use rex_test_utils::rhai::common::create_default_test_cedar_auth;
    use std::fs;

    /// Given: A path to a non-existent file
    /// When: Calling touch
    /// Then: The file is created and is empty
    #[test]
    fn test_touch_creates_file() {
        let temp = TempDir::new().unwrap();
        let target = fs::canonicalize(temp.path()).unwrap().join("new.txt");
        let target_str = target.to_str().unwrap();
        let cedar_auth = create_default_test_cedar_auth();

        touch(target_str, &cedar_auth).unwrap();
        assert!(target.exists());
        assert_eq!(fs::read_to_string(&target).unwrap(), "");
    }
}
