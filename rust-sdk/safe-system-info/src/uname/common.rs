use derive_getters::Getters;
use serde::Serialize;
use std::fmt;

use crate::RustSysteminfoError;

/// Represents RAM info common to all OS platforms.
#[derive(Debug, Clone, Getters, Serialize)]
pub struct UnameInfo {
    /// Kernel name, e.g. Linux
    pub(crate) kernel_name: String,
    /// Hostname - the hostname
    pub(crate) nodename: String,
    /// Kernel release, e.g. "25.3.0"
    pub(crate) kernel_release: String,
    /// Kernel version, e.g. "#1 SMP Tue Sep 9 14:55:36 UTC 2025"
    pub(crate) kernel_version: String,
    /// The machine architecture, e.g. `x86_64`
    pub(crate) machine: String,
    /// The machine architecture, e.g. `x86_64`
    pub(crate) processor: String,
    /// The machine architecture, e.g. `x86_64`
    pub(crate) hardware_platform: String,
    /// The operating system, e.g. GNU/Linux
    pub(crate) operating_system: String,
}

impl fmt::Display for UnameInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {} {} {} {}",
            self.kernel_name,
            self.nodename,
            self.kernel_release,
            self.kernel_version,
            self.machine,
            self.processor,
            self.hardware_platform,
            self.operating_system
        )
    }
}

pub(crate) trait UnameProvider {
    fn uname_info(&self) -> Result<UnameInfo, RustSysteminfoError>;
}
