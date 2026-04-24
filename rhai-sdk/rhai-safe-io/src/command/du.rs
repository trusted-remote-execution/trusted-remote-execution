//! `du` — Disk usage for a directory (Unix only)
//!
//! # Example (Rhai)
//! ```rhai
//! let usage = du("/path/to/dir");
//! for entry in usage.entries {
//!     print(`${entry.path}: ${entry.size_bytes} bytes`);
//! }
//!
//! // Summarize only
//! let usage = du([du::summarize], "/path/to/dir");
//!
//! // Max depth
//! let usage = du([du::max_depth(2)], "/path/to/dir");
//! ```

#[cfg(unix)]
use super::open_dir_from_path;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::{Array, Dynamic, Map};
#[cfg(unix)]
use rhai_sdk_common_utils::args::{extract_flags, find_flag_value, has_flag};

/// Flags for the `du` command.
#[derive(Debug, Clone)]
pub(crate) enum DuFlag {
    Summarize,
    AllFiles,
    ApparentSize,
    MaxDepth(i64),
}

/// Returns disk usage for a directory.
#[cfg(unix)]
pub(crate) fn du(path: &str, cedar_auth: &CedarAuth) -> Result<Map, String> {
    du_with_flags(path, &Array::new(), cedar_auth)
}

/// Returns disk usage with flags.
#[cfg(unix)]
pub(crate) fn du_with_flags(
    path: &str,
    flags_arr: &Array,
    cedar_auth: &CedarAuth,
) -> Result<Map, String> {
    use rust_safe_io::options::DiskUsageOptionsBuilder;

    let flags = extract_flags::<DuFlag>(flags_arr).map_err(|e| e.to_string())?;
    let summarize = has_flag(&flags, |f| matches!(f, DuFlag::Summarize));
    let all_files = has_flag(&flags, |f| matches!(f, DuFlag::AllFiles));
    let apparent_size = has_flag(&flags, |f| matches!(f, DuFlag::ApparentSize));
    let max_depth = find_flag_value(&flags, |f| match f {
        DuFlag::MaxDepth(n) => Some(*n),
        _ => None,
    });

    let mut builder = DiskUsageOptionsBuilder::default();
    builder.summarize(summarize);
    builder.all_files(all_files);
    builder.apparent_size(apparent_size);
    if let Some(depth) = max_depth {
        builder.max_depth(depth);
    }

    let dir_handle = open_dir_from_path(path, cedar_auth).map_err(|e| e.to_string())?;
    let options = builder.build().map_err(|e| e.to_string())?;
    let result = dir_handle
        .safe_disk_usage(cedar_auth, options)
        .map_err(|e| e.to_string())?;

    let mut total_size: u64 = 0;
    let mut total_inodes: u64 = 0;
    let entries: Array = result
        .entries()
        .iter()
        .map(|entry| {
            total_size += *entry.size_bytes();
            total_inodes += *entry.inode_count();
            let mut m = Map::new();
            m.insert("path".into(), Dynamic::from(entry.path().clone()));
            #[allow(clippy::cast_possible_wrap)]
            m.insert(
                "size_bytes".into(),
                Dynamic::from(*entry.size_bytes() as i64),
            );
            #[allow(clippy::cast_possible_wrap)]
            m.insert(
                "inode_count".into(),
                Dynamic::from(*entry.inode_count() as i64),
            );
            Dynamic::from(m)
        })
        .collect();

    let mut map = Map::new();
    map.insert("entries".into(), Dynamic::from(entries));
    #[allow(clippy::cast_possible_wrap)]
    map.insert("total_size_bytes".into(), Dynamic::from(total_size as i64));
    #[allow(clippy::cast_possible_wrap)]
    map.insert(
        "total_inode_count".into(),
        Dynamic::from(total_inodes as i64),
    );
    Ok(map)
}

#[cfg(not(unix))]
pub(crate) fn du(_path: &str, _cedar_auth: &CedarAuth) -> Result<Map, String> {
    Err("du is only supported on Unix".to_string())
}

#[cfg(not(unix))]
pub(crate) fn du_with_flags(
    _path: &str,
    _flags_arr: &Array,
    _cedar_auth: &CedarAuth,
) -> Result<Map, String> {
    Err("du is only supported on Unix".to_string())
}
