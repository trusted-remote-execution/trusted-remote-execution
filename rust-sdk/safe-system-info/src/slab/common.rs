use crate::RustSysteminfoError;

use derive_getters::Getters;
use rustix::param;
use serde::Serialize;
use std::fmt;

use rex_cedar_auth::cedar_auth::CedarAuth;

#[derive(Debug, Clone, Getters, Serialize)]
pub struct SlabEntry {
    /// Slab cache name (e.g., `buffer_head`, `dentry`)
    pub(crate) name: String,
    /// Total number of allocated objects (OBJS column)
    pub(crate) objs: u64,
    /// Number of active objects (ACTIVE column)
    pub(crate) active: u64,
    /// Size of each object in bytes (from objsize field)
    pub(crate) obj_size_bytes: u64,
    /// Total number of slabs (SLABS column)
    pub(crate) slabs: u64,
    /// Objects per slab (OBJ/SLAB column)
    pub(crate) obj_per_slab: u64,
    /// Pages per slab
    pub(crate) pages_per_slab: u64,
}

impl SlabEntry {
    /// Percentage of objects that are currently in use
    #[inline]
    pub fn use_percent(&self) -> u64 {
        (self.active * 100).checked_div(self.objs).unwrap_or(0)
    }

    #[inline]
    #[allow(clippy::cast_precision_loss)]
    pub fn obj_size_kb(&self) -> f64 {
        const BYTES_PER_KB: f64 = 1024.0;
        self.obj_size_bytes as f64 / BYTES_PER_KB
    }

    #[inline]
    pub fn cache_size_kb(&self) -> u64 {
        // Page size can vary across Linux platforms depending on the CPU architecture and kernel configuration:
        // We use rustix::param::page_size() to dynamically get the system's page size for portability.
        let page_size_kb = param::page_size() as u64 / 1024;
        self.slabs * self.pages_per_slab * page_size_kb
    }

    #[inline]
    #[allow(clippy::cast_precision_loss)]
    pub fn active_size_kb(&self) -> f64 {
        if self.objs > 0 {
            self.cache_size_kb() as f64 * (self.active as f64 / self.objs as f64)
        } else {
            0.0
        }
    }
}

#[derive(Debug, Clone, Copy, Getters, Serialize)]
pub struct SlabSummary {
    /// Total active objects across all slabs
    pub(crate) active_objects: u64,
    /// Total objects (active + inactive)
    pub(crate) total_objects: u64,
    /// Percentage of objects in use
    pub(crate) objects_usage_percent: f64,

    /// Total active slabs
    pub(crate) active_slabs: u64,
    /// Total slabs (active + inactive)
    pub(crate) total_slabs: u64,
    /// Percentage of slabs in use
    pub(crate) slabs_usage_percent: f64,

    /// Number of active cache types
    pub(crate) active_caches: u64,
    /// Total number of cache types
    pub(crate) total_caches: u64,
    /// Percentage of cache types in use
    pub(crate) caches_usage_percent: f64,

    /// Total active size in KB
    pub(crate) active_size_kb: f64,
    /// Total size in KB
    pub(crate) total_size_kb: f64,
    /// Percentage of size in use
    pub(crate) size_usage_percent: f64,

    /// Minimum object size in KB
    pub(crate) min_obj_size_kb: f64,
    /// Average object size in KB
    pub(crate) avg_obj_size_kb: f64,
    /// Maximum object size in KB
    pub(crate) max_obj_size_kb: f64,
}

impl fmt::Display for SlabSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Active / Total Objects (% used)    : {} / {} ({:.1}%)\n\
             Active / Total Slabs (% used)      : {} / {} ({:.1}%)\n\
             Active / Total Caches (% used)     : {} / {} ({:.1}%)\n\
             Active / Total Size (% used)       : {:.2}K / {:.0}K ({:.1}%)\n\
             Minimum / Average / Maximum Object : {:.2}K / {:.2}K / {:.2}K",
            self.active_objects,
            self.total_objects,
            self.objects_usage_percent,
            self.active_slabs,
            self.total_slabs,
            self.slabs_usage_percent,
            self.active_caches,
            self.total_caches,
            self.caches_usage_percent,
            self.active_size_kb,
            self.total_size_kb,
            self.size_usage_percent,
            self.min_obj_size_kb,
            self.avg_obj_size_kb,
            self.max_obj_size_kb
        )
    }
}

#[derive(Debug, Clone, Getters, Serialize)]
pub struct SlabInfo {
    pub(crate) slabs: Vec<SlabEntry>,
    pub(crate) summary: SlabSummary,
}

pub(crate) trait SlabInfoProvider {
    fn slab_info(&mut self, cedar_auth: &CedarAuth) -> Result<SlabInfo, RustSysteminfoError>;
}
