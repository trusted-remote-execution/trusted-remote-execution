use super::MeminfoExt;
use crate::RustSysteminfoError;

use derive_getters::Getters;
use serde::Serialize;
use serde::ser::SerializeStruct;
use std::fmt;

/// Represents RAM info common to all OS platforms.
#[derive(Debug, Clone, Copy, Getters)]
pub struct Meminfo {
    /// The total amount of system RAM.
    pub(crate) total: u64,
    /// The amount of system RAM not currently used for anything.
    pub(crate) free: u64,
    /// The amount of system RAM that can be claimed for use by the system. On Linux systems, this includes `free` + `buffer` + `cache` + `SReclaimable`.
    pub(crate) available: u64,
    /// Other platform-dependent fields.
    #[getter(skip)]
    pub(crate) ext: MeminfoExt,
}

impl Meminfo {
    /// For RAM, `used` is simply the difference between `total` and `available`. Historically this field has been calculated differently,
    /// but the latest versions of the `free` command perform the calculation this way.
    #[inline]
    pub fn used(&self) -> u64 {
        self.total - self.available
    }
}

impl fmt::Display for Meminfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Memory Info:\n  Total: {} bytes\n  Free: {} bytes\n  Available: {} bytes\n  Used: {} bytes{}",
            self.total,
            self.free,
            self.available,
            self.used(),
            self.ext
        )
    }
}

// This trait is just to ensure that the internal interface for multiple platforms is aligned. It's not meant to be externally published.
pub(crate) trait MeminfoProvider {
    /// Reload RAM info and return a `Meminfo` object with the result, or an error if the operation failed.
    fn memory_info(&mut self) -> Result<Meminfo, RustSysteminfoError>;
    /// Reload Swap info and return a `Swapinfo` object with the result, or an error if the operation failed.
    fn swap_info(&mut self) -> Result<Swapinfo, RustSysteminfoError>;
}

/// Represents swap memory info.
#[derive(Debug, Clone, Copy, Getters)]
pub struct Swapinfo {
    /// The total amount of swap memory.
    pub(crate) total: u64,
    /// The amount of free swap memory.
    pub(crate) free: u64,
}

impl Swapinfo {
    /// For swap, `used` is the difference between `total` and `free`.
    #[inline]
    pub fn used(&self) -> u64 {
        self.total - self.free
    }
}

// Since `used` is a method (albeit inline) we can't use the `#derive(Serialize)` macro here.
impl Serialize for Swapinfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("Swapinfo", 3)?;
        state.serialize_field("total", &self.total)?;
        state.serialize_field("free", &self.free)?;
        state.serialize_field("used", &self.used())?;
        state.end()
    }
}

impl fmt::Display for Swapinfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Swap Info:\n  Total: {} bytes\n  Free: {} bytes\n  Used: {} bytes",
            self.total,
            self.free,
            self.used()
        )
    }
}
