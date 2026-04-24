use super::common::{CpuStats, DeviceStats, IoStatProvider, IoStatSnapshot};
use crate::constants::{BYTES_PER_KIBIBYTE, BYTES_PER_SECTOR};
use crate::utils::{
    safe_divide_f64_by_f64, safe_divide_u64_by_f64, safe_divide_u64_by_u64, system_uptime_seconds,
};
use crate::{RustDiskinfoError, is_authorized};
use procfs::{CurrentSI, DiskStat, KernelStats, diskstats};
use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::fs::entities::FileEntity;

pub(super) const PROC_STAT_PATH: &str = "/proc/stat";
const PROC_DISKSTATS: &str = "/proc/diskstats";

#[derive(Clone, Copy, Debug)]
pub struct IoStat;

impl IoStatProvider for IoStat {
    fn get_snapshot(&self, cedar_auth: &CedarAuth) -> Result<IoStatSnapshot, RustDiskinfoError> {
        is_authorized(
            cedar_auth,
            &FilesystemAction::Read,
            &FileEntity::from_string_path(PROC_STAT_PATH)?,
        )?;
        is_authorized(
            cedar_auth,
            &FilesystemAction::Read,
            &FileEntity::from_string_path(PROC_DISKSTATS)?,
        )?;

        let kernel_stats = KernelStats::current().map_err(RustDiskinfoError::from)?;
        let disk_stats = diskstats().map_err(RustDiskinfoError::from)?;

        let cpu_stats = convert_cpu_stats_to_iostat(&kernel_stats);
        let device_stats = convert_device_stats_to_iostat(disk_stats)?;

        Ok(IoStatSnapshot::new(cpu_stats, device_stats))
    }
}

/// Convert procfs `KernelStats` to iostat-style CPU statistics
#[allow(clippy::cast_precision_loss)]
fn convert_cpu_stats_to_iostat(kernel_stats: &KernelStats) -> CpuStats {
    let cpu_total = &kernel_stats.total;

    let total_time = cpu_total.user
        + cpu_total.nice
        + cpu_total.system
        + cpu_total.idle
        + cpu_total.iowait.unwrap_or(0)
        + cpu_total.irq.unwrap_or(0)
        + cpu_total.softirq.unwrap_or(0)
        + cpu_total.steal.unwrap_or(0);

    CpuStats::new(
        safe_divide_u64_by_u64(cpu_total.user, total_time) * 100.0,
        safe_divide_u64_by_u64(cpu_total.nice, total_time) * 100.0,
        safe_divide_u64_by_u64(
            cpu_total.system + cpu_total.irq.unwrap_or(0) + cpu_total.softirq.unwrap_or(0),
            total_time,
        ) * 100.0,
        safe_divide_u64_by_u64(cpu_total.iowait.unwrap_or(0), total_time) * 100.0,
        safe_divide_u64_by_u64(cpu_total.steal.unwrap_or(0), total_time) * 100.0,
        safe_divide_u64_by_u64(cpu_total.idle, total_time) * 100.0,
    )
}

/// Convert procfs `Vec<DiskStat>` to iostat-style device statistics
#[allow(clippy::cast_precision_loss)]
fn convert_device_stats_to_iostat(
    disk_stats: Vec<DiskStat>,
) -> Result<Vec<DeviceStats>, RustDiskinfoError> {
    let mut devices = Vec::new();

    let uptime_seconds = system_uptime_seconds()?;

    for stats in disk_stats {
        let device_name = stats.name;
        let reads_per_sec = safe_divide_u64_by_f64(stats.reads, uptime_seconds);
        let writes_per_sec = safe_divide_u64_by_f64(stats.writes, uptime_seconds);
        let reads_merged_per_sec = safe_divide_u64_by_f64(stats.merged, uptime_seconds);
        let writes_merged_per_sec = safe_divide_u64_by_f64(stats.writes_merged, uptime_seconds);

        let rkb_per_sec = safe_divide_f64_by_f64(
            (stats.sectors_read * BYTES_PER_SECTOR) as f64 / BYTES_PER_KIBIBYTE,
            uptime_seconds,
        );
        let wkb_per_sec = safe_divide_f64_by_f64(
            (stats.sectors_written * BYTES_PER_SECTOR) as f64 / BYTES_PER_KIBIBYTE,
            uptime_seconds,
        );

        let total_ios = stats.reads + stats.writes;
        let total_sectors = stats.sectors_read + stats.sectors_written;
        let avg_request_size = safe_divide_u64_by_u64(total_sectors, total_ios);
        let avg_queue_size =
            safe_divide_u64_by_f64(stats.weighted_time_in_progress, uptime_seconds * 1000.0);
        let avg_wait = safe_divide_u64_by_u64(stats.time_reading + stats.time_writing, total_ios);
        let avg_read_wait = safe_divide_u64_by_u64(stats.time_reading, stats.reads);
        let avg_write_wait = safe_divide_u64_by_u64(stats.time_writing, stats.writes);
        let svctm = safe_divide_u64_by_u64(stats.time_in_progress, total_ios);
        let util_percent =
            safe_divide_u64_by_f64(stats.time_in_progress, uptime_seconds * 1000.0) * 100.0;
        // Clamp utilization to 100% (can exceed due to parallel I/O)
        let util_percent = util_percent.min(100.0);

        let device_stats = DeviceStats::new(
            device_name,
            reads_merged_per_sec,
            writes_merged_per_sec,
            reads_per_sec,
            writes_per_sec,
            rkb_per_sec,
            wkb_per_sec,
            avg_request_size,
            avg_queue_size,
            avg_wait,
            avg_read_wait,
            avg_write_wait,
            svctm,
            util_percent,
        );

        devices.push(device_stats);
    }

    Ok(devices)
}
