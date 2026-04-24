use super::{Meminfo, MeminfoProvider, Swapinfo};
use crate::RustSysteminfoError;

use std::fmt;
use sysinfo::{MemoryRefreshKind, RefreshKind, System};

/// This struct performs Cedar auth and provides `Meminfo` and `Swapinfo` value objects.
#[derive(Debug)]
pub(crate) struct Memory {
    sysinfo_system: System,
}

/// No additional data to display for non-linux systems.
#[derive(Debug, Clone, Copy)]
pub(crate) struct MeminfoExt {}

impl fmt::Display for MeminfoExt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "")
    }
}

impl Memory {
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn new() -> Result<Self, RustSysteminfoError> {
        let sysinfo_system = System::new_with_specifics(
            RefreshKind::default().with_memory(MemoryRefreshKind::default().with_ram()),
        );
        Ok(Self { sysinfo_system })
    }
}

// We define cloning memory to be creating an entirely new object. The alternative would be using an Rc or something to share a reference, which
// doesn't work with needing to refresh the System, since that takes a mutable reference to self.
impl Clone for Memory {
    fn clone(&self) -> Self {
        let sysinfo_system = System::new_with_specifics(
            RefreshKind::default().with_memory(MemoryRefreshKind::default().with_ram()),
        );
        Self { sysinfo_system }
    }
}

impl MeminfoProvider for Memory {
    fn memory_info(&mut self) -> Result<Meminfo, RustSysteminfoError> {
        self.sysinfo_system
            .refresh_memory_specifics(MemoryRefreshKind::default().with_ram());

        Ok(Meminfo {
            total: self.sysinfo_system.total_memory(),
            free: self.sysinfo_system.free_memory(),
            available: self.sysinfo_system.available_memory(),
            ext: MeminfoExt {},
        })
    }

    fn swap_info(&mut self) -> Result<Swapinfo, RustSysteminfoError> {
        self.sysinfo_system
            .refresh_memory_specifics(MemoryRefreshKind::default().with_swap());

        Ok(Swapinfo {
            total: self.sysinfo_system.total_swap(),
            free: self.sysinfo_system.free_swap(),
        })
    }
}
