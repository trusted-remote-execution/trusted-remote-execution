//! Builder options for filesystem access
use derive_builder::Builder;

/// Configuration parameters for filesystem operations.
///
/// This struct is used to specify how filesystem information should be retrieved.
/// It uses the builder pattern for construction via the derived `FilesystemOptionsBuilder`.
///
/// # Arguments
///
/// * `targets` - Vector of specific paths to query. If None, shows all filesystems
/// * `local` - Whether to include only local filesystems (equivalent to df -l)
///
/// # Examples
///
/// ```no_run
/// use rust_disk_info::options::FilesystemOptionsBuilder;
///
/// // Get all filesystems
/// let fs_opts = FilesystemOptionsBuilder::default()
///     .local(true)
///     .build()
///     .unwrap();
///
/// // Get specific filesystems
/// let fs_opts = FilesystemOptionsBuilder::default()
///     .targets(vec!["/".to_string(), "/tmp".to_string()])
///     .build()
///     .unwrap();
/// ```
#[derive(Builder, Debug, Clone, Default)]
#[builder(derive(Debug))]
pub struct FilesystemOptions {
    /// Specific paths to query. If None, shows all filesystems
    #[builder(default)]
    pub targets: Vec<String>,

    /// Include only local filesystems (equivalent to df -l flag)
    #[builder(default = "false")]
    pub local: bool,
}

/// Configuration parameters for unmounting a filesystem
///
/// This struct is used to specify how a filesystem should be unmounted
///
/// # Arguments
///
/// * `path` - The path to the mount point to unmount
///
/// # Important Note on Path vs File Descriptor
///
/// unmount must accept a path string because:
/// 1. The unmount(2) syscall only accepts a path, not a file descriptor
/// 2. Opening a file descriptor to the mount point would make it busy, causing unmount to fail
///
/// # Examples
///
/// ```no_run
/// use rust_disk_info::UnmountOptionsBuilder;
/// # use rex_cedar_auth::cedar_auth::CedarAuth;
/// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
/// #
/// # let cedar_auth = CedarAuth::new(
/// #     &get_default_test_rex_policy(),
/// #     get_default_test_rex_schema(),
/// #     "[]"
/// # ).unwrap().0;
///
/// let options = UnmountOptionsBuilder::default()
///     .path("/data".to_string())
///     .build()
///     .unwrap();
///
/// rust_disk_info::unmount(&cedar_auth, options).unwrap();
/// ```
#[derive(Builder, Debug, Clone)]
#[builder(derive(Debug))]
pub struct UnmountOptions {
    pub path: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Given: A valid UnmountOptionsBuilder with a path
    /// When: Building UnmountOptions
    /// Then: Should successfully create UnmountOptions with the correct path
    #[test]
    #[cfg(target_os = "linux")]
    fn test_unmount_options_build_success() {
        let result = UnmountOptionsBuilder::default()
            .path("/data".to_string())
            .build();

        assert!(result.is_ok(), "Expected build to succeed");
        let options = result.unwrap();
        assert_eq!(options.path, "/data");
    }

    /// Given: An UnmountOptionsBuilder without setting the required path
    /// When: Attempting to build UnmountOptions
    /// Then: Should return an error indicating missing path field
    #[test]
    #[cfg(target_os = "linux")]
    fn test_unmount_options_build_error() {
        let result = UnmountOptionsBuilder::default().build();

        assert!(result.is_err(), "Expected build to fail without path");
        let error = result.unwrap_err().to_string();
        assert!(
            error.contains("path"),
            "Error should mention missing path field"
        );
    }
}
