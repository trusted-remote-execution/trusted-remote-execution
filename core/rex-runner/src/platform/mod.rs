#[cfg(target_family = "unix")]
pub const SYSLOG_IDENTITY: &str = "rex_runner";

use std::path::Path;

/// Checks that the file or directory at `path` has exactly `expected_mode` permissions (lower 9 bits).
///
/// On Linux, reads the actual permission bits and returns an error if they don't match.
/// On non-Linux platforms, this is a no-op and always returns `Ok(())`.
///
/// # Example
/// ```no_run
/// use std::path::Path;
/// use rex_runner::platform::check_permissions;
///
/// let result = check_permissions(Path::new("/tmp"), 0o755);
/// assert!(result.is_ok());
/// ```
pub fn check_permissions(path: &Path, expected_mode: u32) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(path)
            .map_err(|e| format!("Failed to read metadata for {}: {}", path.display(), e))?;

        let mode = metadata.permissions().mode() & 0o777;
        if mode != expected_mode {
            return Err(format!(
                "Expected permissions {:03o}, got {:03o} for {}",
                expected_mode,
                mode,
                path.display()
            ));
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, expected_mode);
    }
    Ok(())
}
