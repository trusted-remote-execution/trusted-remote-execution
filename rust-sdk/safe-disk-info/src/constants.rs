//! Constants and types for disk information operations

pub const BYTES_PER_SECTOR: u64 = 512;
pub const BYTES_PER_KIBIBYTE: f64 = 1024.0;

/// Formatting fs sizes
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub enum Unit {
    #[default]
    Bytes,
    Kilobytes,
    Megabytes,
}
