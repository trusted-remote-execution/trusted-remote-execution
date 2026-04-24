use super::{SlabEntry, SlabInfo, SlabInfoProvider, SlabSummary};
use crate::RustSysteminfoError;
use crate::slab::parser::{RawSlabData, parse_version};
use crate::system::open_proc_fd;
use rex_cedar_auth::cedar_auth::CedarAuth;
use std::cmp::Reverse;

const PROC_SLABINFO_PATH: &str = "slabinfo";

/// This struct performs Cedar auth and provides `SlabInfo` value object.
#[derive(Clone, Debug)]
pub(crate) struct Slab;

impl Slab {
    fn reload(cedar_auth: &CedarAuth) -> Result<RawSlabData, RustSysteminfoError> {
        let file_handle = open_proc_fd(cedar_auth, PROC_SLABINFO_PATH)?;
        let content = file_handle.safe_read(cedar_auth)?;

        Self::validate_slabinfo_version(&content)?;

        RawSlabData::parse(&content).ok_or_else(|| RustSysteminfoError::SlabinfoParseError {
            reason: "Failed to parse /proc/slabinfo content".to_string(),
        })
    }

    fn to_slab_entry(raw_data: &RawSlabData, name: &str) -> Result<SlabEntry, RustSysteminfoError> {
        let active_objs = raw_data.fetch(name, "active_objs").ok_or_else(|| {
            RustSysteminfoError::SlabinfoParseError {
                reason: format!("Missing active_objs field for slab: {name}"),
            }
        })?;
        let num_objs = raw_data.fetch(name, "num_objs").ok_or_else(|| {
            RustSysteminfoError::SlabinfoParseError {
                reason: format!("Missing num_objs field for slab: {name}"),
            }
        })?;
        let obj_size = raw_data.fetch(name, "objsize").ok_or_else(|| {
            RustSysteminfoError::SlabinfoParseError {
                reason: format!("Missing objsize field for slab: {name}"),
            }
        })?;
        let obj_per_slab = raw_data.fetch(name, "objperslab").ok_or_else(|| {
            RustSysteminfoError::SlabinfoParseError {
                reason: format!("Missing objperslab field for slab: {name}"),
            }
        })?;
        let pages_per_slab = raw_data.fetch(name, "pagesperslab").ok_or_else(|| {
            RustSysteminfoError::SlabinfoParseError {
                reason: format!("Missing pagesperslab field for slab: {name}"),
            }
        })?;
        let active_slabs = raw_data.fetch(name, "active_slabs").ok_or_else(|| {
            RustSysteminfoError::SlabinfoParseError {
                reason: format!("Missing active_slabs field for slab: {name}"),
            }
        })?;

        Ok(SlabEntry {
            name: name.to_string(),
            objs: num_objs,
            active: active_objs,
            obj_size_bytes: obj_size,
            slabs: active_slabs,
            obj_per_slab,
            pages_per_slab,
        })
    }

    fn to_slab_info(raw_data: &RawSlabData) -> Result<SlabInfo, RustSysteminfoError> {
        let mut slabs = Vec::new();

        for name in raw_data.names() {
            let entry = Self::to_slab_entry(raw_data, name)?;
            slabs.push(entry);
        }

        slabs.sort_by_key(|entry| Reverse(entry.objs));

        let summary = Self::build_summary(raw_data)?;

        Ok(SlabInfo { slabs, summary })
    }

    #[allow(clippy::cast_precision_loss)]
    fn build_summary(raw_data: &RawSlabData) -> Result<SlabSummary, RustSysteminfoError> {
        const BYTES_TO_KB: f64 = 1024.0;

        if raw_data.data.is_empty() {
            return Err(RustSysteminfoError::SlabinfoParseError {
                reason: "No slab entries found".to_string(),
            });
        }

        let active_objects = raw_data.total_active_objs();
        let total_objects = raw_data.total_objs();
        let active_slabs = raw_data.total_active_slabs();
        let total_slabs = raw_data.total_slabs();

        let active_caches = raw_data
            .names()
            .iter()
            .filter(|name| raw_data.fetch(name, "active_objs").unwrap_or(0) > 0)
            .count() as u64;
        let total_caches = raw_data.names().len() as u64;

        let active_size_kb = raw_data.total_active_size() as f64 / BYTES_TO_KB;
        let total_size_kb = raw_data.total_size() as f64 / BYTES_TO_KB;

        let objects_usage_percent =
            Self::calculate_percentage(active_objects as f64, total_objects as f64);
        let slabs_usage_percent =
            Self::calculate_percentage(active_slabs as f64, total_slabs as f64);
        let caches_usage_percent =
            Self::calculate_percentage(active_caches as f64, total_caches as f64);
        let size_usage_percent = Self::calculate_percentage(active_size_kb, total_size_kb);

        let min_obj_size_kb = raw_data.object_minimum() as f64 / BYTES_TO_KB;
        let max_obj_size_kb = raw_data.object_maximum() as f64 / BYTES_TO_KB;
        let avg_obj_size_kb = if total_objects > 0 {
            raw_data.total_size() as f64 / total_objects as f64 / BYTES_TO_KB
        } else {
            0.0
        };

        Ok(SlabSummary {
            active_objects,
            total_objects,
            objects_usage_percent,
            active_slabs,
            total_slabs,
            slabs_usage_percent,
            active_caches,
            total_caches,
            caches_usage_percent,
            active_size_kb,
            total_size_kb,
            size_usage_percent,
            min_obj_size_kb,
            avg_obj_size_kb,
            max_obj_size_kb,
        })
    }

    fn calculate_percentage(numerator: f64, denominator: f64) -> f64 {
        if denominator > 0.0 {
            (numerator / denominator) * 100.0
        } else {
            0.0
        }
    }

    fn validate_slabinfo_version(content: &str) -> Result<(), RustSysteminfoError> {
        const SUPPORTED_SLABINFO_VERSION: &str = "2.1";

        let first_line =
            content
                .lines()
                .next()
                .ok_or_else(|| RustSysteminfoError::SlabinfoParseError {
                    reason: "Missing version line in /proc/slabinfo".to_string(),
                })?;

        let version =
            parse_version(first_line).ok_or_else(|| RustSysteminfoError::SlabinfoParseError {
                reason: "Unable to parse version from /proc/slabinfo".to_string(),
            })?;

        if version != SUPPORTED_SLABINFO_VERSION {
            return Err(RustSysteminfoError::UnsupportedSlabinfoVersion {
                version,
                supported: SUPPORTED_SLABINFO_VERSION.to_string(),
            });
        }

        Ok(())
    }
}

impl SlabInfoProvider for Slab {
    fn slab_info(&mut self, cedar_auth: &CedarAuth) -> Result<SlabInfo, RustSysteminfoError> {
        let raw_data = Self::reload(cedar_auth)?;
        Self::to_slab_info(&raw_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Given: a SlabInfo with specific slab entries
    /// When: summary is called
    /// Then: summary statistics are calculated correctly
    #[test]
    fn test_slabinfo_summary_calculation() {
        let slab_info = SlabInfo {
            slabs: vec![SlabEntry {
                name: "test_cache".to_string(),
                objs: 1000,
                active: 800,
                obj_size_bytes: 512,
                slabs: 100,
                obj_per_slab: 10,
                pages_per_slab: 1,
            }],
            summary: SlabSummary {
                active_objects: 800,
                total_objects: 1000,
                objects_usage_percent: 80.0,
                active_slabs: 100,
                total_slabs: 100,
                slabs_usage_percent: 100.0,
                active_caches: 1,
                total_caches: 1,
                caches_usage_percent: 100.0,
                active_size_kb: 320.0,
                total_size_kb: 400.0,
                size_usage_percent: 80.0,
                min_obj_size_kb: 0.5,
                avg_obj_size_kb: 0.5,
                max_obj_size_kb: 0.5,
            },
        };

        let summary = slab_info.summary();

        assert_eq!(summary.active_objects, 800);
        assert_eq!(summary.total_objects, 1000);
        assert_eq!(summary.objects_usage_percent, 80.0);
        assert_eq!(summary.active_caches, 1);
        assert_eq!(summary.total_caches, 1);
        assert_eq!(summary.active_size_kb, 320.0);
        assert_eq!(summary.total_size_kb, 400.0);
        assert_eq!(summary.min_obj_size_kb, 0.5);
        assert_eq!(summary.max_obj_size_kb, 0.5);
        assert_eq!(summary.avg_obj_size_kb, 0.5);
    }

    /// Given: an empty RawSlabData
    /// When: build_summary is called
    /// Then: a SlabinfoParseError is returned for "No slab entries found"
    #[test]
    fn test_slabinfo_summary_empty_entries() {
        let raw_data = RawSlabData {
            meta: vec![],
            data: vec![],
        };
        let result = Slab::build_summary(&raw_data);

        assert!(result.is_err());
        match result.unwrap_err() {
            RustSysteminfoError::SlabinfoParseError { reason } => {
                assert_eq!(reason, "No slab entries found");
            }
            error => {
                assert!(false, "Expected SlabinfoParseError, got: {:?}", error);
            }
        }
    }

    /// Given: a RawSlabData with valid slab cache information
    /// When: to_slab_entry is called
    /// Then: a properly calculated SlabEntry is returned
    #[test]
    fn test_to_slab_entry_calculation() {
        let raw_data = RawSlabData {
            meta: vec![
                "active_objs".to_string(),
                "num_objs".to_string(),
                "objsize".to_string(),
                "objperslab".to_string(),
                "pagesperslab".to_string(),
                "active_slabs".to_string(),
                "num_slabs".to_string(),
            ],
            data: vec![(
                "test_cache".to_string(),
                vec![800, 1000, 512, 32, 1, 100, 100],
            )],
        };

        let entry = Slab::to_slab_entry(&raw_data, "test_cache").unwrap();

        assert_eq!(entry.name, "test_cache");
        assert_eq!(entry.objs, 1000);
        assert_eq!(entry.active, 800);
        assert_eq!(entry.use_percent(), 80);
        assert_eq!(entry.obj_size_kb(), 0.5); // 512 bytes / 1024 = 0.5 KB
        assert_eq!(entry.slabs, 100);
        assert_eq!(entry.obj_per_slab, 32);
        assert_eq!(entry.cache_size_kb(), 400); // 100 slabs * 1 page * 4KB = 400KB
        assert_eq!(entry.active_size_kb(), 320.0); // 400KB * (800/1000) = 320KB
    }

    /// Given: a RawSlabData with zero objects (edge case)
    /// When: to_slab_entry is called
    /// Then: percentage and active size calculations handle zero division correctly
    #[test]
    fn test_to_slab_entry_zero_objects() {
        let raw_data = RawSlabData {
            meta: vec![
                "active_objs".to_string(),
                "num_objs".to_string(),
                "objsize".to_string(),
                "objperslab".to_string(),
                "pagesperslab".to_string(),
                "active_slabs".to_string(),
                "num_slabs".to_string(),
            ],
            data: vec![("empty_cache".to_string(), vec![0, 0, 512, 32, 1, 100, 100])],
        };

        let entry = Slab::to_slab_entry(&raw_data, "empty_cache").unwrap();

        assert_eq!(entry.use_percent(), 0);
        assert_eq!(entry.active_size_kb(), 0.0);
    }

    /// Given: a RawSlabData with multiple slab entries
    /// When: to_slab_info is called
    /// Then: slabs are sorted by objs descending
    #[test]
    fn test_to_slab_info_integration() {
        let raw_data = RawSlabData {
            meta: vec![
                "active_objs".to_string(),
                "num_objs".to_string(),
                "objsize".to_string(),
                "objperslab".to_string(),
                "pagesperslab".to_string(),
                "active_slabs".to_string(),
                "num_slabs".to_string(),
            ],
            data: vec![
                // active  objs  objsize  per_slab  pages  active_slabs  num_slabs
                (
                    "buffer_head".to_string(),
                    vec![1500, 2000, 1024, 32, 1, 200, 200],
                ),
                ("dentry".to_string(), vec![4000, 5000, 128, 32, 1, 10, 10]),
                ("task_struct".to_string(), vec![400, 500, 2048, 16, 1, 8, 8]),
                (
                    "inode_cache".to_string(),
                    vec![2500, 3000, 512, 32, 1, 100, 100],
                ),
                ("filp".to_string(), vec![80, 100, 256, 32, 1, 2, 2]),
            ],
        };

        let slab_info = Slab::to_slab_info(&raw_data).unwrap();

        assert_eq!(slab_info.slabs.len(), 5);

        assert!(
            slab_info.slabs.windows(2).all(|w| w[0].objs >= w[1].objs),
            "Slabs should be sorted by objs descending, got: {:?}",
            slab_info
                .slabs
                .iter()
                .map(|s| (&s.name, s.objs))
                .collect::<Vec<_>>()
        );

        let names: Vec<&str> = slab_info.slabs.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "dentry",
                "inode_cache",
                "buffer_head",
                "task_struct",
                "filp"
            ]
        );

        let summary = slab_info.summary();
        assert_eq!(summary.total_objects, 10600);
        assert_eq!(summary.active_objects, 8480);
        assert_eq!(summary.total_caches, 5);
        assert_eq!(summary.active_caches, 5);
    }

    /// Given: /proc/slabinfo content with version 2.1
    /// When: validate_slabinfo_version is called
    /// Then: validation succeeds
    #[test]
    fn test_validate_slabinfo_version_valid() {
        let content = "slabinfo - version: 2.1\n# name <active_objs> <num_objs>";
        let result = Slab::validate_slabinfo_version(content);
        assert!(result.is_ok());
    }

    /// Given: /proc/slabinfo content with unsupported version 2.0
    /// When: validate_slabinfo_version is called
    /// Then: UnsupportedSlabinfoVersion error is returned
    #[test]
    fn test_validate_slabinfo_version_unsupported() {
        let content = "slabinfo - version: 2.0\n# name <active_objs> <num_objs>";
        let result = Slab::validate_slabinfo_version(content);

        assert!(result.is_err());
        match result.unwrap_err() {
            RustSysteminfoError::UnsupportedSlabinfoVersion { version, supported } => {
                assert_eq!(version, "2.0");
                assert_eq!(supported, "2.1");
            }
            error => {
                assert!(
                    false,
                    "Expected UnsupportedSlabinfoVersion, got: {:?}",
                    error
                );
            }
        }
    }

    /// Given: /proc/slabinfo content with invalid version format
    /// When: validate_slabinfo_version is called
    /// Then: SlabinfoParseError is returned
    #[test]
    fn test_validate_slabinfo_version_invalid_format() {
        let content = ":::\n# name <active_objs> <num_objs>";
        let result = Slab::validate_slabinfo_version(content);

        assert!(result.is_err());
        match result.unwrap_err() {
            RustSysteminfoError::SlabinfoParseError { reason } => {
                assert_eq!(reason, "Unable to parse version from /proc/slabinfo");
            }
            error => {
                assert!(false, "Expected SlabinfoParseError, got: {:?}", error);
            }
        }
    }

    /// Given: empty /proc/slabinfo content (no lines)
    /// When: validate_slabinfo_version is called
    /// Then: SlabinfoParseError is returned for missing version line
    #[test]
    fn test_validate_slabinfo_version_missing_line() {
        let content = "";
        let result = Slab::validate_slabinfo_version(content);

        assert!(result.is_err());
        match result.unwrap_err() {
            RustSysteminfoError::SlabinfoParseError { reason } => {
                assert_eq!(reason, "Missing version line in /proc/slabinfo");
            }
            error => {
                assert!(false, "Expected SlabinfoParseError, got: {:?}", error);
            }
        }
    }

    /// Given: RawSlabData missing specific fields
    /// When: to_slab_entry is called
    /// Then: appropriate SlabinfoParseError is returned for each missing field
    #[rstest]
    #[case("active_objs", "Missing active_objs field for slab: test_cache")]
    #[case("num_objs", "Missing num_objs field for slab: test_cache")]
    #[case("objsize", "Missing objsize field for slab: test_cache")]
    #[case("objperslab", "Missing objperslab field for slab: test_cache")]
    #[case("pagesperslab", "Missing pagesperslab field for slab: test_cache")]
    #[case("active_slabs", "Missing active_slabs field for slab: test_cache")]
    fn test_to_slab_entry_missing_fields(
        #[case] missing_field: &str,
        #[case] expected_error: &str,
    ) {
        let mut meta = vec![
            "active_objs".to_string(),
            "num_objs".to_string(),
            "objsize".to_string(),
            "objperslab".to_string(),
            "pagesperslab".to_string(),
            "active_slabs".to_string(),
            "num_slabs".to_string(),
        ];

        meta.retain(|field| field != missing_field);

        let raw_data = RawSlabData {
            meta,
            data: vec![("test_cache".to_string(), vec![800, 1000, 512, 32, 1, 100])],
        };

        let result = Slab::to_slab_entry(&raw_data, "test_cache");

        assert!(result.is_err());
        match result.unwrap_err() {
            RustSysteminfoError::SlabinfoParseError { reason } => {
                assert_eq!(reason, expected_error);
            }
            error => {
                assert!(false, "Expected SlabinfoParseError, got: {:?}", error);
            }
        }
    }
}
