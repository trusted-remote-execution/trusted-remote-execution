#![cfg(target_os = "linux")]
//! Kernel statistics and CPU time information.
//!
//! The [`RhaiCpuTime`] and [`RhaiKernelStats`] newtypes wrap the procfs types
//! and provide named fields that serve as both Rhai getters (via
//! `derive_getters`) and `to_map` keys (via `serde::Serialize`), so the two
//! can never diverge.

use derive_getters::Getters;
use procfs::{CpuTime, KernelStats};
use serde::Serialize;

/// Rhai-facing wrapper around [`procfs::CpuTime`].
///
/// # Getters — ticks
///
/// | Getter              | Description                                  |
/// |---------------------|----------------------------------------------|
/// | `user_ticks`        | CPU ticks in user mode                       |
/// | `nice_ticks`        | CPU ticks in low-priority user mode           |
/// | `system_ticks`      | CPU ticks in system mode                     |
/// | `idle_ticks`        | CPU ticks in idle state                      |
/// | `iowait_ticks`      | CPU ticks in I/O wait (unreliable — see note)|
/// | `irq_ticks`         | CPU ticks servicing interrupts               |
/// | `softirq_ticks`     | CPU ticks servicing softirqs                 |
/// | `stolen_ticks`      | CPU ticks of stolen time (virtualised)       |
/// | `guest_ticks`       | CPU ticks in a guest OS                      |
/// | `guest_nice_ticks`  | CPU ticks in a guest OS (low priority)       |
///
/// # Getters — milliseconds
///
/// | Getter              | Description                                  |
/// |---------------------|----------------------------------------------|
/// | `user_ms`           | CPU millis in user mode                      |
/// | `nice_ms`           | CPU millis in low-priority user mode          |
/// | `system_ms`         | CPU millis in system mode                    |
/// | `idle_ms`           | CPU millis in idle state                     |
/// | `iowait_ms`         | CPU millis in I/O wait                       |
/// | `irq_ms`            | CPU millis servicing interrupts              |
/// | `softirq_ms`        | CPU millis servicing softirqs                |
/// | `stolen_ms`         | CPU millis of stolen time                    |
/// | `guest_ms`          | CPU millis in a guest OS                     |
/// | `guest_nice_ms`     | CPU millis in a guest OS (low priority)      |
///
/// # Note on `iowait_ticks` / `iowait_ms`
///
/// This value is not reliable because:
/// 1. The CPU will not wait for I/O to complete; iowait is the time that a
///    task is waiting for I/O to complete.
/// 2. On a multi-core CPU, the task waiting for I/O is not running on any CPU,
///    so the iowait for each CPU is difficult to calculate.
/// 3. The value may *decrease* in certain conditions.
///
/// # Example
/// ```
/// # use rex_test_utils::rhai::sysinfo::create_temp_test_env;
/// # let (mut scope, engine) = create_temp_test_env();
/// # let result = engine.eval_with_scope::<i64>(
/// #     &mut scope,
/// #     r#"
/// let system_info = SystemInfo();
/// let kernel_stats = system_info.kernel_stats();
/// let cpu_time = kernel_stats.total_cpu_time;
///
/// cpu_time.user_ticks;
/// cpu_time.nice_ticks;
/// cpu_time.system_ticks;
/// cpu_time.idle_ticks;
/// cpu_time.iowait_ticks;
/// cpu_time.irq_ticks;
/// cpu_time.softirq_ticks;
/// cpu_time.stolen_ticks;
/// cpu_time.guest_ticks;
/// cpu_time.guest_nice_ticks;
///
/// cpu_time.user_ms;
/// cpu_time.nice_ms;
/// cpu_time.system_ms;
/// cpu_time.idle_ms;
/// cpu_time.iowait_ms;
/// cpu_time.irq_ms;
/// cpu_time.softirq_ms;
/// cpu_time.stolen_ms;
/// cpu_time.guest_ms;
/// cpu_time.guest_nice_ms;
/// #     "#);
/// #
/// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
/// ```
#[derive(Debug, Clone, Copy, Getters, Serialize)]
pub struct RhaiCpuTime {
    // ticks
    user_ticks: i64,
    nice_ticks: i64,
    system_ticks: i64,
    idle_ticks: i64,
    iowait_ticks: i64,
    irq_ticks: i64,
    softirq_ticks: i64,
    stolen_ticks: i64,
    guest_ticks: i64,
    guest_nice_ticks: i64,
    // milliseconds
    user_ms: i64,
    nice_ms: i64,
    system_ms: i64,
    idle_ms: i64,
    iowait_ms: i64,
    irq_ms: i64,
    softirq_ms: i64,
    stolen_ms: i64,
    guest_ms: i64,
    guest_nice_ms: i64,
}

#[allow(clippy::cast_possible_wrap)]
impl From<&CpuTime> for RhaiCpuTime {
    fn from(ct: &CpuTime) -> Self {
        Self {
            user_ticks: ct.user as i64,
            nice_ticks: ct.nice as i64,
            system_ticks: ct.system as i64,
            idle_ticks: ct.idle as i64,
            iowait_ticks: ct.iowait.unwrap_or_default() as i64,
            irq_ticks: ct.irq.unwrap_or_default() as i64,
            softirq_ticks: ct.softirq.unwrap_or_default() as i64,
            stolen_ticks: ct.steal.unwrap_or_default() as i64,
            guest_ticks: ct.guest.unwrap_or_default() as i64,
            guest_nice_ticks: ct.guest_nice.unwrap_or_default() as i64,
            user_ms: ct.user_ms() as i64,
            nice_ms: ct.nice_ms() as i64,
            system_ms: ct.system_ms() as i64,
            idle_ms: ct.idle_ms() as i64,
            iowait_ms: ct.iowait_ms().unwrap_or_default() as i64,
            irq_ms: ct.irq_ms().unwrap_or_default() as i64,
            softirq_ms: ct.softirq_ms().unwrap_or_default() as i64,
            stolen_ms: ct.steal_ms().unwrap_or_default() as i64,
            guest_ms: ct.guest_ms().unwrap_or_default() as i64,
            guest_nice_ms: ct.guest_nice_ms().unwrap_or_default() as i64,
        }
    }
}

/// Rhai-facing wrapper around [`procfs::KernelStats`].
///
/// # Getters
///
/// | Getter              | Description                                                      |
/// |---------------------|------------------------------------------------------------------|
/// | `total_cpu_time`    | Aggregate CPU time across all cores (see [`RhaiCpuTime`])        |
/// | `cpu_time`          | Per-CPU time array (see [`RhaiCpuTime`])                         |
/// | `boot_time`         | Boot time (epoch seconds)                                        |
/// | `context_switches`  | Context switches since boot                                      |
/// | `forks`             | Process creations since boot                                     |
/// | `procs_running`     | Processes currently running                                      |
/// | `procs_blocked`     | Processes currently blocked                                      |
///
/// # Example
/// ```
/// # use rex_test_utils::rhai::sysinfo::create_temp_test_env;
/// # let (mut scope, engine) = create_temp_test_env();
/// # let result = engine.eval_with_scope::<i64>(
/// #     &mut scope,
/// #     r#"
/// let system_info = SystemInfo();
/// let kernel_stats = system_info.kernel_stats();
/// let total_cpu_time = kernel_stats.total_cpu_time;
/// let cpu0_time = kernel_stats.cpu_time[0];
///
/// kernel_stats.boot_time;
/// kernel_stats.context_switches;
/// kernel_stats.forks;
/// kernel_stats.procs_running;
/// kernel_stats.procs_blocked;
/// #     "#);
/// #
/// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
/// ```
#[derive(Debug, Clone, Getters, Serialize)]
pub struct RhaiKernelStats {
    total_cpu_time: RhaiCpuTime,
    cpu_time: Vec<RhaiCpuTime>,
    procs_running: i64,
    procs_blocked: i64,
    context_switches: i64,
    boot_time: i64,
    forks: i64,
}

#[allow(clippy::cast_possible_wrap)]
impl From<KernelStats> for RhaiKernelStats {
    fn from(ks: KernelStats) -> Self {
        Self {
            total_cpu_time: RhaiCpuTime::from(&ks.total),
            cpu_time: ks.cpu_time.iter().map(RhaiCpuTime::from).collect(),
            procs_running: ks.procs_running.map(i64::from).unwrap_or_default(),
            procs_blocked: ks.procs_blocked.map(i64::from).unwrap_or_default(),
            context_switches: ks.ctxt as i64,
            boot_time: ks.btime as i64,
            forks: ks.processes as i64,
        }
    }
}
