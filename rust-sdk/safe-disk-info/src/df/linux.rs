use super::common::{Filesystem, FilesystemProvider};
use crate::utils::safe_divide_u64_by_u64;
use crate::{FilesystemOptions, RustDiskinfoError, is_authorized};
use nix::errno::Errno;
use nix::sys::statvfs::statvfs;
use procfs::mounts;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::fs::entities::{DirEntity, FileEntity};
use sysinfo::{Disk, DiskKind, Disks};

const PROC_MOUNTS: &str = "/proc/mounts";
const PROC_DISKSTATS: &str = "/proc/diskstats";

#[derive(Clone, Copy, Debug)]
pub struct Df;

impl FilesystemProvider for Df {
    fn get_filesystems(
        &self,
        cedar_auth: &CedarAuth,
        config: &FilesystemOptions,
    ) -> Result<Vec<Filesystem>, RustDiskinfoError> {
        is_authorized(
            cedar_auth,
            &FilesystemAction::Read,
            &FileEntity::from_string_path(PROC_MOUNTS)?,
        )?;
        is_authorized(
            cedar_auth,
            &FilesystemAction::Read,
            &FileEntity::from_string_path(PROC_DISKSTATS)?,
        )?;
        let disks = Disks::new_with_refreshed_list();
        let all_disks: Vec<&Disk> = disks.list().iter().collect();

        // Apply target filtering
        let filtered_disks = if config.targets.is_empty() {
            all_disks
        } else {
            all_disks
                .into_iter()
                .filter(|disk| {
                    let mount_point = disk.mount_point().to_string_lossy();
                    config.targets.iter().any(|target| {
                        mount_point.starts_with(target)
                            || mount_point.starts_with(&format!("{target}/"))
                    })
                })
                .collect()
        };

        // Apply local filesystem filtering if needed
        let final_disks = if config.local {
            filtered_disks
                .into_iter()
                .filter(|disk| is_local_filesystem(disk))
                .collect()
        } else {
            filtered_disks
        };

        // Convert to Filesystem structs, skipping inaccessible mount points.
        // Some mount points (e.g., Docker overlays, credential dirs) may return
        // EACCES from statvfs even though the user has valid Cedar permissions.
        // This mirrors the behavior of `df`, which silently skips unreachable
        // filesystems rather than failing entirely.
        let mut filesystems = Vec::new();
        for disk in final_disks {
            match convert_disk_to_filesystem(cedar_auth, disk) {
                Ok(fs) => filesystems.push(fs),
                Err(RustDiskinfoError::NixError(Errno::EACCES)) => {}
                Err(e) => return Err(e),
            }
        }

        Ok(filesystems)
    }
}

/// Determines if a disk represents a local filesystem
///
/// This is a simplified implementation - in a real system this would need
/// more sophisticated logic to determine local vs network filesystems
fn is_local_filesystem(disk: &Disk) -> bool {
    match disk.kind() {
        DiskKind::HDD | DiskKind::SSD => true,
        DiskKind::Unknown(_) => {
            // Check filesystem type for common local types
            let name = disk.name().to_string_lossy();
            let fs_name = name.to_lowercase();

            // Common local filesystem patterns
            !fs_name.contains("nfs")
                && !fs_name.contains("smb")
                && !fs_name.contains("cifs")
                && !fs_name.contains("efs")
                && !fs_name.starts_with("//")
                && !fs_name.contains(':')
                && !fs_name.contains("autofs")
        }
    }
}

/// Converts a `sysinfo::Disk` to our `Filesystem` struct
///
/// Inode calculation is platform-specific. On Unix systems, statvfs provides
/// accurate inode information directly from the filesystem. On non-Unix systems,
/// this function returns an error as filesystem information is not supported.
#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::cast_sign_loss)]
#[allow(clippy::cast_precision_loss)]
#[allow(clippy::cast_lossless)]
#[allow(clippy::useless_conversion)]
fn convert_disk_to_filesystem(
    cedar_auth: &CedarAuth,
    disk: &Disk,
) -> Result<Filesystem, RustDiskinfoError> {
    let (total_space, available_space, used_space, total_inodes, used_inodes, free_inodes) = {
        is_authorized(
            cedar_auth,
            &FilesystemAction::Stat,
            &DirEntity::new(disk.mount_point())?,
        )?;
        let stats = statvfs(disk.mount_point())?;
        let total_space = u64::from(stats.blocks()) * stats.fragment_size();
        let available_space = u64::from(stats.blocks_available()) * stats.fragment_size();
        let used_space = total_space - available_space;

        let total_inodes = stats.files();
        let free_inodes = stats.files_free();
        let used_inodes = total_inodes - free_inodes;

        (
            total_space,
            available_space,
            used_space,
            total_inodes,
            used_inodes,
            free_inodes,
        )
    };

    // Calculate percentages using the safe_divide function
    let block_use_percent = safe_divide_u64_by_u64(used_space, total_space) * 100.0;
    let inode_use_percent = safe_divide_u64_by_u64(used_inodes, total_inodes) * 100.0;

    // Calculate block information
    let kb_blocks = total_space / 1024;
    let mb_blocks = total_space / (1024 * 1024);

    let mount_point = disk.mount_point().to_string_lossy().to_string();
    let mount_options = get_mount_options(cedar_auth, &mount_point)?;

    let filesystem = Filesystem::new(
        disk.name().to_string_lossy().to_string(), // fs_device
        disk.file_system().to_string_lossy().to_string(), // fs_kind
        u64::from(total_inodes),                   // inodes
        u64::from(used_inodes),                    // iused
        u64::from(free_inodes),                    // ifree
        inode_use_percent,                         // iuse_percent
        used_space,                                // block_used
        available_space,                           // block_available
        block_use_percent,                         // block_use_percent
        mount_point,                               // mounted_on
        kb_blocks,                                 // k1_blocks
        mb_blocks,                                 // m1_blocks
        total_space,                               // raw_size
        mount_options,
    );

    Ok(filesystem)
}

#[allow(clippy::unwrap_used)]
fn get_mount_options(
    cedar_auth: &CedarAuth,
    mount_path: &str,
) -> Result<Vec<String>, RustDiskinfoError> {
    is_authorized(
        cedar_auth,
        &FilesystemAction::Read,
        &FileEntity::from_string_path(PROC_MOUNTS)?,
    )?;
    // when backlog task REX-2300 to switch from sysinfo to procfs for df API is finished

    let mount_list = mounts()?;

    let mount_entry = mount_list
        .into_iter()
        .find(|entry| entry.fs_file == mount_path)
        .unwrap();

    let mount_options: Vec<String> = mount_entry
        .fs_mntops
        .into_iter()
        .map(|(key, value)| {
            if let Some(val) = value {
                format!("{key}={val}")
            } else {
                key
            }
        })
        .collect();

    Ok(mount_options)
}
