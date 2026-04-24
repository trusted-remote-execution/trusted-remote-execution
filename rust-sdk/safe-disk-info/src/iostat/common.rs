use crate::RustDiskinfoError;
use derive_getters::Getters;
use rex_cedar_auth::cedar_auth::CedarAuth;
use serde::Serialize;
use std::fmt;

pub trait IoStatProvider {
    /// Get a snapshot of I/O statistics
    fn get_snapshot(&self, cedar_auth: &CedarAuth) -> Result<IoStatSnapshot, RustDiskinfoError>;
}

/// Complete iostat -x output snapshot
#[derive(Debug, Clone, Getters, Serialize)]
pub struct IoStatSnapshot {
    /// CPU utilization statistics (avg-cpu section)
    cpu_stats: CpuStats,
    /// Per-device I/O statistics (Device section)
    device_stats: Vec<DeviceStats>,
}

impl IoStatSnapshot {
    pub const fn new(cpu_stats: CpuStats, device_stats: Vec<DeviceStats>) -> Self {
        Self {
            cpu_stats,
            device_stats,
        }
    }
}

impl fmt::Display for IoStatSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // CPU section
        writeln!(f, "avg-cpu:  %user   %nice %system %iowait  %steal   %idle")?;
        writeln!(
            f,
            "          {:6.2}  {:6.2}  {:6.2}  {:6.2}  {:6.2}  {:6.2}",
            self.cpu_stats.user_percent(),
            self.cpu_stats.nice_percent(),
            self.cpu_stats.system_percent(),
            self.cpu_stats.iowait_percent(),
            self.cpu_stats.steal_percent(),
            self.cpu_stats.idle_percent()
        )?;

        // Empty line between sections
        writeln!(f)?;

        // Device section header
        writeln!(
            f,
            "Device:         rrqm/s   wrqm/s     r/s     w/s    rkB/s    wkB/s avgrq-sz avgqu-sz   await r_await w_await  svctm  %util"
        )?;

        // Device data
        for device in &self.device_stats {
            writeln!(
                f,
                "{:<15} {:8.2} {:8.2} {:7.2} {:7.2} {:8.2} {:8.2} {:8.2} {:8.2} {:7.2} {:7.2} {:7.2} {:6.2} {:6.2}",
                device.device_name(),
                device.rrqm_per_sec(),
                device.wrqm_per_sec(),
                device.read_requests_per_sec(),
                device.write_requests_per_sec(),
                device.rkb_per_sec(),
                device.wkb_per_sec(),
                device.avg_request_size(),
                device.avg_queue_size(),
                device.avg_wait(),
                device.avg_read_wait(),
                device.avg_write_wait(),
                device.svctm(),
                device.util_percent()
            )?;
        }

        Ok(())
    }
}

/// CPU statistics from iostat -x avg-cpu section
#[allow(clippy::struct_field_names)]
#[derive(Debug, Copy, Clone, Getters, Serialize)]
pub struct CpuStats {
    /// %user - Percentage of CPU time spent in user mode
    user_percent: f64,
    /// %nice - Percentage of CPU time spent in user mode with low priority
    nice_percent: f64,
    /// %system - Percentage of CPU time spent in system mode
    system_percent: f64,
    /// %iowait - Percentage of CPU time spent waiting for I/O operations
    iowait_percent: f64,
    /// %steal - Percentage of CPU time stolen by hypervisor
    steal_percent: f64,
    /// %idle - Percentage of CPU time spent idle
    idle_percent: f64,
}

impl CpuStats {
    pub const fn new(
        user_percent: f64,
        nice_percent: f64,
        system_percent: f64,
        iowait_percent: f64,
        steal_percent: f64,
        idle_percent: f64,
    ) -> Self {
        Self {
            user_percent,
            nice_percent,
            system_percent,
            iowait_percent,
            steal_percent,
            idle_percent,
        }
    }
}

/// Device statistics from iostat -x Device section
#[derive(Debug, Clone, Getters, Serialize)]
pub struct DeviceStats {
    /// Device name (e.g., "nvme0n1", "sda")
    device_name: String,
    /// `rrqm/s` - Read requests merged per second
    rrqm_per_sec: f64,
    /// `wrqm/s` - Write requests merged per second
    wrqm_per_sec: f64,
    /// `r/s` - Read requests per second
    read_requests_per_sec: f64,
    /// `w/s` - Write requests per second
    write_requests_per_sec: f64,
    /// `rkB/s` - Kilobytes read per second
    rkb_per_sec: f64,
    /// `wkB/s` - Kilobytes written per second
    wkb_per_sec: f64,
    /// `avgrq-sz` - Average request size in sectors
    avg_request_size: f64,
    /// `avgqu-sz` - Average queue size
    avg_queue_size: f64,
    /// `await` - Average wait time (ms)
    avg_wait: f64,
    /// `r_await` - Average read wait time (ms)
    avg_read_wait: f64,
    /// `w_await` - Average write wait time (ms)
    avg_write_wait: f64,
    /// `svctm` - Service time (ms)
    svctm: f64,
    /// %`util` - Device utilization percentage
    util_percent: f64,
}

impl DeviceStats {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        device_name: String,
        rrqm_per_sec: f64,
        wrqm_per_sec: f64,
        read_requests_per_sec: f64,
        write_requests_per_sec: f64,
        rkb_per_sec: f64,
        wkb_per_sec: f64,
        avg_request_size: f64,
        avg_queue_size: f64,
        avg_wait: f64,
        avg_read_wait: f64,
        avg_write_wait: f64,
        svctm: f64,
        util_percent: f64,
    ) -> Self {
        Self {
            device_name,
            rrqm_per_sec,
            wrqm_per_sec,
            read_requests_per_sec,
            write_requests_per_sec,
            rkb_per_sec,
            wkb_per_sec,
            avg_request_size,
            avg_queue_size,
            avg_wait,
            avg_read_wait,
            avg_write_wait,
            svctm,
            util_percent,
        }
    }
}
