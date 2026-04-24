use super::{Meminfo, MeminfoProvider, Swapinfo};
use crate::RustSysteminfoError;

use procfs::{Current, Meminfo as ProcMeminfo};
use serde::Serialize;
use serde::ser::SerializeStruct;
use std::fmt;

/// This struct performs Cedar auth and provides `Meminfo` and `Swapinfo` value objects.
#[derive(Clone, Debug)]
pub(crate) struct Memory {
    proc_meminfo: ProcMeminfo,
}

/// A private struct to store Linux-specific RAM info.
#[derive(Debug, Clone, Copy)]
pub(crate) struct MeminfoExt {
    buffers: u64,
    cached: u64,
    shared: u64,
}

impl fmt::Display for MeminfoExt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "\n  Buffers: {} bytes\n  Cached: {} bytes\n  Shared: {} bytes",
            self.buffers, self.cached, self.shared
        )
    }
}

// For linux systems, we rely exclusively on /proc/meminfo to get data. If we partially relied on `Sysinfo` as well, it would not be possible to
// atomically reload the two data sources, leading to inconsistent data returned to the user.
impl Memory {
    pub(crate) fn new() -> Result<Self, RustSysteminfoError> {
        Ok(Memory {
            proc_meminfo: Self::reload()?,
        })
    }

    fn reload() -> Result<ProcMeminfo, RustSysteminfoError> {
        ProcMeminfo::current().map_err(RustSysteminfoError::from)
    }
}

impl MeminfoProvider for Memory {
    fn memory_info(&mut self) -> Result<Meminfo, RustSysteminfoError> {
        self.proc_meminfo = Self::reload()?;

        Ok(Meminfo {
            total: self.proc_meminfo.mem_total,
            free: self.proc_meminfo.mem_free,
            available: self.proc_meminfo.mem_available.unwrap_or(0),
            ext: MeminfoExt {
                buffers: self.proc_meminfo.buffers,
                cached: self.proc_meminfo.cached,
                shared: self.proc_meminfo.shmem.unwrap_or(0),
            },
        })
    }

    fn swap_info(&mut self) -> Result<Swapinfo, RustSysteminfoError> {
        self.proc_meminfo = Self::reload()?;

        Ok(Swapinfo {
            total: self.proc_meminfo.swap_total,
            free: self.proc_meminfo.swap_free,
        })
    }
}

// Note: these getters for `Meminfo` are referencing the `ext` object, so we can't autogenerate them using `derive_getters`
impl Meminfo {
    /// The amount of memory used for I/O buffers.
    pub const fn buffers(&self) -> &u64 {
        &self.ext.buffers
    }

    /// The amount of memory used for cache (e.g. cached disk pages).
    pub const fn cached(&self) -> &u64 {
        &self.ext.cached
    }

    /// The amount of memory used by tmpfs and other shared memory.
    pub const fn shared(&self) -> &u64 {
        &self.ext.shared
    }
}

impl Serialize for Meminfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("Meminfo", 7)?;
        state.serialize_field("total", &self.total)?;
        state.serialize_field("free", &self.free)?;
        state.serialize_field("available", &self.available)?;
        state.serialize_field("used", &self.used())?;
        state.serialize_field("buffers", &self.ext.buffers)?;
        state.serialize_field("cached", &self.ext.cached)?;
        state.serialize_field("shared_mem", &self.ext.shared)?; // `shared` is a keyword in Rhai, so we set its Rhai getter to "shared_mem" instead
        state.end()
    }
}
