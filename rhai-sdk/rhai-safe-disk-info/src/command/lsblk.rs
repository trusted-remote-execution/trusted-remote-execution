//! `lsblk` - List block devices (Linux only)
//!
//! Reads `/proc/partitions`, `/sys/dev/block`, `/dev/disk/by-id`, `/proc/mounts`,
//! and `/proc/swaps` to enumerate block devices with attributes.
//!
//! # Example (Rhai)
//! ```rhai
//! let devices = lsblk();
//! for dev in devices.values() {
//!     print(`${dev.name} ${dev.type} ${dev.size_kib} KiB`);
//! }
//! ```

use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::{Dynamic, Map};
use rust_safe_io::errors::RustSafeIoError;
use std::collections::HashMap;

use rust_safe_io::{
    DirConfigBuilder,
    options::{OpenDirOptionsBuilder, OpenFileOptionsBuilder, ReadLinesOptionsBuilder},
};

/// A parsed block device from `/proc/partitions`.
struct DeviceInfo {
    name: String,
    maj: String,
    min: String,
    size_kib: i64,
}

/// Open a directory with optional symlink following via safe I/O.
fn open_dir(
    path: &str,
    follow_symlinks: bool,
    cedar_auth: &CedarAuth,
) -> Result<rust_safe_io::RcDirHandle, RustSafeIoError> {
    let config = DirConfigBuilder::default()
        .path(path.to_string())
        .build()
        .map_err(|e| RustSafeIoError::InvalidArguments {
            reason: e.to_string(),
        })?;
    let options = OpenDirOptionsBuilder::default()
        .follow_symlinks(follow_symlinks)
        .build()
        .map_err(|e| RustSafeIoError::InvalidArguments {
            reason: e.to_string(),
        })?;
    config.safe_open(cedar_auth, options)
}

/// Read a file's contents via safe I/O.
fn read_file(
    dir: &rust_safe_io::RcDirHandle,
    file_name: &str,
    cedar_auth: &CedarAuth,
) -> Result<String, RustSafeIoError> {
    let file_opts = OpenFileOptionsBuilder::default()
        .read(true)
        .build()
        .map_err(|e| RustSafeIoError::InvalidArguments {
            reason: e.to_string(),
        })?;
    let fh = dir.safe_open_file(cedar_auth, file_name, file_opts)?;
    fh.safe_read(cedar_auth)
}

/// Read lines from a file, skipping the first `skip` header lines.
fn read_lines_skip(
    dir: &rust_safe_io::RcDirHandle,
    file_name: &str,
    skip: usize,
    cedar_auth: &CedarAuth,
) -> Result<Vec<String>, RustSafeIoError> {
    let file_opts = OpenFileOptionsBuilder::default()
        .read(true)
        .follow_symlinks(true) // needed to open `/proc/mounts` which is a symlink to `/proc/self/mounts`
        .build()
        .map_err(|e| RustSafeIoError::InvalidArguments {
            reason: e.to_string(),
        })?;
    let fh = dir.safe_open_file(cedar_auth, file_name, file_opts)?;
    let read_opts = ReadLinesOptionsBuilder::default()
        .start(skip + 1) // 1-indexed, so skip+1 starts after `skip` lines
        .build()
        .map_err(|e| RustSafeIoError::InvalidArguments {
            reason: e.to_string(),
        })?;
    fh.safe_read_lines(cedar_auth, read_opts)
}

/// Parse `/proc/partitions` into a map of device name -> `DeviceInfo`.
fn get_device_and_partition_info(
    cedar_auth: &CedarAuth,
) -> Result<HashMap<String, DeviceInfo>, RustSafeIoError> {
    // Data starts on line 3 (first 2 are header + blank)
    let lines = read_lines_skip(
        &open_dir("/proc", false, cedar_auth)?,
        "partitions",
        2,
        cedar_auth,
    )?;

    let mut devices = HashMap::new();
    for line in &lines {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let name = (*parts.get(3).unwrap_or(&"")).to_string();
        devices.insert(
            name.clone(),
            DeviceInfo {
                name,
                maj: (*parts.first().unwrap_or(&"")).to_string(),
                min: (*parts.get(1).unwrap_or(&"")).to_string(),
                size_kib: parts
                    .get(2)
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(0),
            },
        );
    }
    Ok(devices)
}

/// Read `/dev/disk/by-id` to build LVM device-mapper name -> logical volume name mapping.
/// e.g. "dm-3" -> "dbbin01-lvdbbin01"
fn get_lvm_to_device_mapping(
    cedar_auth: &CedarAuth,
) -> Result<HashMap<String, String>, RustSafeIoError> {
    let dir = open_dir("/dev/disk/by-id", false, cedar_auth)?;
    let entries = dir.safe_list_dir(cedar_auth)?;

    let mut lvms = HashMap::new();
    for entry in &entries {
        let entry_name = entry.name().clone();
        if !entry_name.starts_with("dm-name-") {
            continue;
        }
        let target = dir.safe_read_link_target(cedar_auth, &entry_name)?;
        let device_name = basename(&target);
        let lvm_name = entry_name
            .strip_prefix("dm-name-")
            .unwrap_or(&entry_name)
            .to_string();
        lvms.insert(device_name, lvm_name);
    }
    Ok(lvms)
}

/// Build a mapping of device name -> mount point from `/proc/mounts` and `/proc/swaps`.
fn get_device_mountpoint_mapping(
    lvm_mapping: &HashMap<String, String>,
    cedar_auth: &CedarAuth,
) -> Result<HashMap<String, String>, RustSafeIoError> {
    let mut mapping = HashMap::new();

    // Normal filesystems from /proc/mounts (same as /proc/self/mounts)
    let proc_dir = open_dir("/proc", false, cedar_auth)?;
    let mount_lines = read_lines_skip(&proc_dir, "mounts", 0, cedar_auth)?;
    for line in &mount_lines {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let Some(fs_device) = parts.first() else {
            continue;
        };
        if !fs_device.starts_with("/dev") {
            continue;
        }
        // Strip /dev/, /dev/mapper/ prefix to get device name
        let dev_name = fs_device
            .strip_prefix("/dev/mapper/")
            .or_else(|| fs_device.strip_prefix("/dev/"))
            .unwrap_or(fs_device);
        let mount_point = (*parts.get(1).unwrap_or(&"")).to_string();
        mapping.insert(dev_name.to_string(), mount_point);
    }

    // Swap devices from /proc/swaps (header on line 1)
    let swap_lines = read_lines_skip(&proc_dir, "swaps", 1, cedar_auth)?;
    for line in &swap_lines {
        let parts: Vec<&str> = line.split_whitespace().collect();
        let Some(device_path) = parts.first() else {
            continue;
        };
        let device_name = device_path.strip_prefix("/dev/").unwrap_or(device_path);
        let name = lvm_mapping
            .get(device_name)
            .cloned()
            .unwrap_or_else(|| device_name.to_string());
        mapping.insert(name, "[SWAP]".to_string());
    }

    Ok(mapping)
}

fn basename(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_string()
}

fn dirname(path: &str) -> String {
    match path.rsplit_once('/') {
        Some((parent, _)) if !parent.is_empty() => parent.to_string(),
        Some(("", _)) => "/".to_string(),
        _ => path.to_string(),
    }
}

/// List all block devices with attributes.
///
/// Returns a Rhai Map keyed by device name. Each value is a Map with:
/// name, type, maj, min, `size_kib`, removable, `read_only`, `mount_point`, children.
///
/// # Example
/// ```rhai
/// let devices = lsblk();
/// let root_dev = devices["nvme0n1"];
/// print(root_dev.size_kib);
/// ```
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_lines)]
pub(crate) fn lsblk(cedar_auth: &CedarAuth) -> Result<Map, RustSafeIoError> {
    let device_info = get_device_and_partition_info(cedar_auth)?;
    let lvm_mapping = get_lvm_to_device_mapping(cedar_auth)?;
    let mountpoints = get_device_mountpoint_mapping(&lvm_mapping, cedar_auth)?;

    let mut output = Map::new();

    for device in device_info.values() {
        let (name, dev_type) = if let Some(lvm_name) = lvm_mapping.get(&device.name) {
            (lvm_name.clone(), "lvm".to_string())
        } else {
            (device.name.clone(), String::new())
        };

        let dev_info_path = format!("/sys/dev/block/{}:{}", device.maj, device.min);
        let dev_dir = open_dir(&dev_info_path, true, cedar_auth)?;

        // Determine device type from sysfs uevent if not LVM
        let dev_type = if dev_type.is_empty() {
            let uevent = read_file(&dev_dir, "uevent", cedar_auth)?;
            uevent
                .lines()
                .find(|l| l.starts_with("DEVTYPE"))
                .and_then(|l| l.split('=').next_back())
                .unwrap_or("unknown")
                .to_string()
        } else {
            dev_type
        };

        // Removable flag (only for non-partitions)
        let removable = if dev_type == "partition" {
            "0".to_string()
        } else {
            read_file(&dev_dir, "removable", cedar_auth)
                .map_or("0".to_string(), |s| s.trim().to_string())
        };

        // Read-only flag
        let read_only =
            read_file(&dev_dir, "ro", cedar_auth).map_or("0".to_string(), |s| s.trim().to_string());

        let mount_point = mountpoints.get(&name).cloned().unwrap_or_default();

        let mut dev_map = Map::new();
        dev_map.insert("name".into(), Dynamic::from(name.clone()));
        dev_map.insert("type".into(), Dynamic::from(dev_type.clone()));
        dev_map.insert("maj".into(), Dynamic::from(device.maj.clone()));
        dev_map.insert("min".into(), Dynamic::from(device.min.clone()));
        dev_map.insert("size_kib".into(), Dynamic::from(device.size_kib));
        dev_map.insert("removable".into(), Dynamic::from(removable));
        dev_map.insert("read_only".into(), Dynamic::from(read_only));
        dev_map.insert("mount_point".into(), Dynamic::from(mount_point));
        dev_map.insert("children".into(), Dynamic::from(rhai::Array::new()));

        output.insert(name.into(), Dynamic::from(dev_map));
    }

    // Populate children
    populate_children(&mut output, &device_info, &lvm_mapping, cedar_auth)?;

    Ok(output)
}

/// Populate the children adjacency list for each device.
/// LVM children are found via `/sys/dev/block/<maj:min>/slaves`.
/// Partition children are found by resolving the symlink parent directory.
#[cfg(target_os = "linux")]
fn populate_children(
    output: &mut Map,
    device_info: &HashMap<String, DeviceInfo>,
    lvm_mapping: &HashMap<String, String>,
    cedar_auth: &CedarAuth,
) -> Result<(), RustSafeIoError> {
    // Collect device types and maj:min for iteration
    let device_entries: Vec<(String, String, String, String)> = output
        .iter()
        .filter_map(|(key, val)| {
            let map = val.clone().try_cast::<Map>()?;
            let dev_type = map.get("type")?.clone().into_string().ok()?;
            let maj = map.get("maj")?.clone().into_string().ok()?;
            let min = map.get("min")?.clone().into_string().ok()?;
            Some((key.to_string(), dev_type, maj, min))
        })
        .collect();

    for (name, dev_type, maj, min) in &device_entries {
        if dev_type == "lvm" {
            // For LVMs, parents are listed as symlinks in the "slaves" directory
            let slaves_path = format!("/sys/dev/block/{maj}:{min}/slaves");
            let Ok(slaves_dir) = open_dir(&slaves_path, true, cedar_auth) else {
                continue;
            };
            let Ok(entries) = slaves_dir.safe_list_dir(cedar_auth) else {
                continue;
            };
            for entry in &entries {
                let parent_name = entry.name().clone();
                append_child(output, &parent_name, name);
            }
        } else if dev_type == "partition" {
            // For partitions, resolve the symlink in /sys/dev/block to find the parent
            let block_dir = open_dir("/sys/dev/block", false, cedar_auth)?;
            let link_name = format!("{maj}:{min}");
            if let Ok(actual_location) = block_dir.safe_read_link_target(cedar_auth, &link_name) {
                let parent_dir = dirname(&actual_location);
                let parent_name = basename(&parent_dir);
                // The parent might be a dm- device that maps to an LVM name
                let resolved_parent = lvm_mapping
                    .get(&parent_name)
                    .cloned()
                    .unwrap_or(parent_name);
                // Only look up in device_info to confirm it's a real device
                if device_info.contains_key(&resolved_parent)
                    || output.contains_key(resolved_parent.as_str())
                {
                    append_child(output, &resolved_parent, name);
                }
            }
        }
    }
    Ok(())
}

/// Append a child device name to a parent device's children array.
fn append_child(output: &mut Map, parent_name: &str, child_name: &str) {
    if let Some(parent_val) = output.get_mut(parent_name)
        && let Some(mut parent_map) = parent_val.write_lock::<Map>()
    {
        let mut children = parent_map
            .get("children")
            .and_then(|v| v.clone().into_typed_array::<Dynamic>().ok())
            .unwrap_or_default();
        children.push(Dynamic::from(child_name.to_string()));
        parent_map.insert("children".into(), Dynamic::from(children));
    }
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::unnecessary_wraps, unused_variables)]
pub(crate) fn lsblk(cedar_auth: &CedarAuth) -> Result<Map, RustSafeIoError> {
    Err(RustSafeIoError::InvalidArguments {
        reason: "lsblk: only supported on Linux".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Given: A path like "/sys/dev/block/259:0/../../nvme0n1"
    /// When: Calling basename
    /// Then: Returns "nvme0n1"
    #[test]
    fn test_basename() {
        assert_eq!(basename("/sys/dev/block/259:0"), "259:0");
        assert_eq!(basename("../../nvme0n1"), "nvme0n1");
        assert_eq!(basename("dm-3"), "dm-3");
    }

    /// Given: A path like "../../devices/pci0000:00/nvme0n1"
    /// When: Calling dirname
    /// Then: Returns "../../devices/pci0000:00"
    #[test]
    fn test_dirname() {
        assert_eq!(
            dirname("../../devices/pci0000:00/nvme0n1"),
            "../../devices/pci0000:00"
        );
        assert_eq!(dirname("/a/b"), "/a");
        assert_eq!(dirname("single"), "single");
    }

    #[cfg(not(target_os = "linux"))]
    /// Given: A non-Linux platform
    /// When: Calling lsblk
    /// Then: An error is returned
    #[test]
    fn test_lsblk_not_supported_on_non_linux() {
        let cedar_auth = rex_test_utils::rhai::common::create_default_test_cedar_auth();
        let result = lsblk(&cedar_auth);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("only supported on Linux")
        );
    }
}
