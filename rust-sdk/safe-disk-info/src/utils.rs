//! Utility functions shared across the diskinfo crate

#[cfg(target_os = "linux")]
use crate::errors::RustDiskinfoError;
#[cfg(target_os = "linux")]
use procfs::{Current, Uptime};
#[cfg(unix)]
use sysinfo::{Disk, DiskKind};

#[inline]
#[allow(clippy::cast_precision_loss)]
pub fn safe_divide_u64_by_u64(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

#[inline]
#[allow(clippy::cast_precision_loss)]
pub fn safe_divide_u64_by_f64(numerator: u64, denominator: f64) -> f64 {
    if denominator == 0.0 {
        0.0
    } else {
        numerator as f64 / denominator
    }
}

#[inline]
pub fn safe_divide_f64_by_f64(numerator: f64, denominator: f64) -> f64 {
    if denominator == 0.0 {
        0.0
    } else {
        numerator / denominator
    }
}

#[cfg(target_os = "linux")]
pub fn system_uptime_seconds() -> Result<f64, RustDiskinfoError> {
    Ok(Uptime::current()
        .map_err(RustDiskinfoError::from)?
        .uptime_duration()
        .as_secs_f64())
}

/// Determines if a disk represents a local filesystem
///
/// This is a simplified implementation - in a real system this would need
/// more sophisticated logic to determine local vs network filesystems
///
/// # Arguments
///
/// * `disk` - The disk to check
///
/// # Returns
///
/// * `bool` - true if the disk represents a local filesystem
#[cfg(unix)]
pub fn is_local_filesystem(disk: &Disk) -> bool {
    match disk.kind() {
        DiskKind::HDD | DiskKind::SSD => true,
        DiskKind::Unknown(_) => {
            // Check filesystem type for common local types
            let name = disk.name().to_string_lossy();
            let fs_name = name.to_lowercase();

            // Common local filesystem patterns
            !fs_name.contains("nfs")
                && !fs_name.contains("smb")
                && !fs_name.contains("cifs")
                && !fs_name.contains("efs")
                && !fs_name.starts_with("//")
                && !fs_name.contains(':')
                && !fs_name.contains("autofs")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Given: safe_divide_u64_by_u64 is called
    /// When: denominator is zero
    /// Then: Division by zero returns 0.0
    #[test]
    fn test_safe_divide_u64_by_u64_zero_denominator() {
        assert_eq!(safe_divide_u64_by_u64(10, 0), 0.0);
    }
    /// Given: safe_divide_f64_by_f64 is called
    /// When: denominator is zero
    /// Then: Division by zero returns 0.0
    #[test]
    fn test_safe_divide_f64_by_f64_zero_denominator() {
        assert_eq!(safe_divide_f64_by_f64(10.0, 0.0), 0.0);
    }

    /// Given: safe_divide_u64_by_f64 is called
    /// When: denominator is zero
    /// Then: Division by zero returns 0.0
    #[test]
    fn test_safe_divide_u64_by_f64_zero_denominator() {
        assert_eq!(safe_divide_u64_by_f64(10, 0.0), 0.0);
    }
}
