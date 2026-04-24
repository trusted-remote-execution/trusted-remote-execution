use crate::RustSysteminfoError;
use crate::options::DmesgOptions;
use derive_getters::Getters;
use serde::Serialize;
use std::fmt;

/// Represents a single kernel log entry
#[derive(Debug, Clone, Getters, Serialize)]
pub struct DmesgEntry {
    /// Timestamp from system start (seconds.microseconds like "0.000000" or human-readable like "Sat Sep 13 03:59:45 2025")
    pub(crate) timestamp_from_system_start: String,
    /// The kernel log message
    pub(crate) message: String,
}

impl fmt::Display for DmesgEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.timestamp_from_system_start, self.message)
    }
}

pub(crate) trait DmesgProvider {
    fn dmesg_info(&self, options: DmesgOptions) -> Result<Vec<DmesgEntry>, RustSysteminfoError>;
}
