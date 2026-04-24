//! Process monitoring module implementing Rhai callback-based monitoring
//!
//! This module provides CPU and memory monitoring during script execution:
//! - CPU: Measured over entire execution period (baseline to end) for accuracy
//! - Memory: Sampled during execution using Rhai's `on_progress` callback mechanism

use anyhow::{Result, anyhow};
use rex_logger::{debug, error};
use rex_runner_registrar_utils::execution_context::ExecutionContext;
use rhai::{Dynamic, Engine};
use rust_sdk_common_utils::signal_handling::SigtermHandler;
use std::cell::RefCell;
use std::ops::Div;
use std::time::Instant;
use std::{env, process, rc::Rc};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

const SIGTERM_SCRIPT_GRACEFUL_TIMEOUT_SECONDS: i64 = 10;

const SAMPLING_INTERVAL_MSEC: u64 = 1000;

pub type ProcessMonitorHandle = Rc<RefCell<ProcessMonitor>>;

#[derive(Debug)]
pub struct ProcessMonitor {
    pid: u32,
    time_interval_ms: u64,
    memory_data: Vec<u64>,
    virtual_memory_data: Vec<u64>,
    cpu_system: System,
    memory_system: System,
    last_sample_time: Instant,
    monitoring_enabled: bool,
}

fn check_sigterm_timeout() -> Option<Dynamic> {
    SigtermHandler::is_received()
        .then(SigtermHandler::get_elapsed_seconds)
        .flatten()
        .filter(|&elapsed| elapsed >= SIGTERM_SCRIPT_GRACEFUL_TIMEOUT_SECONDS)
        .map(|_| {
            error!("Script execution terminated: SIGTERM timeout ({SIGTERM_SCRIPT_GRACEFUL_TIMEOUT_SECONDS} seconds) exceeded");
            Dynamic::from("SIGTERM timeout exceeded")
        })
}

impl ProcessMonitor {
    /// Create a new process monitor
    ///
    /// # Arguments
    /// * `pid` - Process ID to monitor
    /// * `time_interval_ms` - Minimum time interval in milliseconds between samples (e.g., 100)
    /// * `monitoring_enabled` - Whether to initialize actual monitoring systems
    pub fn new(pid: u32, time_interval_ms: u64, monitoring_enabled: bool) -> Result<Self> {
        let (cpu_system, memory_system) = if monitoring_enabled {
            /*
                We need to sample memory and CPU at different times.
                Memory usage is sampled periodically to compute the average memory usage.
                CPU usage by comparing the initial CPU time for the process with the CPU time when the process is finished.
                I observed that using same system for both memory and CPU corrupts the CPU usage results at the end.
            */
            let mut cpu_system = System::new();
            let mut memory_system = System::new();
            let process_pid = Pid::from_u32(pid);

            cpu_system.refresh_processes_specifics(
                ProcessesToUpdate::Some(&[process_pid]),
                true,
                ProcessRefreshKind::nothing().with_cpu(),
            );

            memory_system.refresh_processes_specifics(
                ProcessesToUpdate::Some(&[process_pid]),
                true,
                ProcessRefreshKind::nothing().with_memory(),
            );

            (cpu_system, memory_system)
        } else {
            // Create uninitialized systems when monitoring is disabled
            (System::new(), System::new())
        };

        Ok(Self {
            pid,
            time_interval_ms,
            memory_data: Vec::new(),
            virtual_memory_data: Vec::new(),
            cpu_system,
            memory_system,
            last_sample_time: Instant::now(),
            monitoring_enabled,
        })
    }

    /// Create the progress callback for Rhai engine using interior mutability
    ///
    /// This callback samples on the first operation and then only when enough time has
    /// passed since the last sample (`time_interval_ms` constraint)
    /// Uses Rc<`RefCell`<>> to provide interior mutability for Rhai's Fn requirement
    pub fn create_progress_callback(
        monitor: Rc<RefCell<Self>>,
        execution_context: Option<Rc<ExecutionContext>>,
    ) -> impl Fn(u64) -> Option<Dynamic> + 'static {
        move |current_operations| {
            if let Some(termination) = check_sigterm_timeout() {
                return Some(termination);
            }

            if let Some(ref ctx) = execution_context
                && ctx.termination_flag().should_terminate()
            {
                let error_message = ctx
                    .termination_flag()
                    .error()
                    .unwrap_or_else(|| "Script terminated due to critical error".to_string());

                error!("Script execution terminated: {}", error_message);
                return Some(Dynamic::from(error_message));
            }

            if let Ok(mut monitor_ref) = monitor.try_borrow_mut() {
                let should_sample = if current_operations == 1 {
                    // Always sample on first operation
                    true
                } else {
                    // Check time constraint for subsequent operations
                    let elapsed_ms = monitor_ref.last_sample_time.elapsed().as_millis();
                    elapsed_ms >= u128::from(monitor_ref.time_interval_ms)
                };

                if should_sample && let Err(e) = monitor_ref.sample_memory_metrics() {
                    debug!("Failed to sample metrics: {}", e);
                }
            }
            None
        }
    }

    fn sample_memory_metrics(&mut self) -> Result<()> {
        if !self.monitoring_enabled {
            return Ok(());
        }

        let process_pid = Pid::from_u32(self.pid);

        self.memory_system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[process_pid]),
            true,
            ProcessRefreshKind::nothing().with_memory(),
        );

        let process = self
            .memory_system
            .process(process_pid)
            .ok_or_else(|| anyhow!("Process with PID {} no longer exists", self.pid))?;

        let memory_usage_bytes = process.memory();
        let memory_usage_kb = memory_usage_bytes / 1024;
        self.memory_data.push(memory_usage_kb);

        let virtual_memory_bytes = process.virtual_memory();
        let virtual_memory_kb = virtual_memory_bytes / 1024;
        self.virtual_memory_data.push(virtual_memory_kb);

        // Update timestamp after successful sampling
        self.last_sample_time = Instant::now();

        debug!(
            "Sampled RSS memory: {} KB, Virtual memory: {} KB",
            memory_usage_kb, virtual_memory_kb
        );

        Ok(())
    }

    pub fn get_cpu_usage(&mut self) -> Option<f32> {
        if !self.monitoring_enabled {
            return None;
        }

        let process_pid = Pid::from_u32(self.pid);

        self.cpu_system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[process_pid]),
            true,
            ProcessRefreshKind::nothing().with_memory().with_cpu(),
        );

        if let Some(process) = self.cpu_system.process(process_pid) {
            Some(process.cpu_usage())
        } else {
            debug!("Process {} not found for CPU measurement", self.pid);
            None
        }
    }

    #[allow(clippy::cast_precision_loss)]
    pub fn get_rss_memory_average_mb(&self) -> Option<f64> {
        if !self.monitoring_enabled || self.memory_data.is_empty() {
            return None;
        }
        let sum = self.memory_data.iter().sum::<u64>() as f64;
        let count = self.memory_data.len() as f64;
        Some(sum.div(count).div(1024.0))
    }

    #[allow(clippy::cast_precision_loss)]
    pub fn get_virtual_memory_average_mb(&self) -> Option<f64> {
        if !self.monitoring_enabled || self.virtual_memory_data.is_empty() {
            return None;
        }
        let sum = self.virtual_memory_data.iter().sum::<u64>() as f64;
        let count = self.virtual_memory_data.len() as f64;
        Some(sum.div(count).div(1024.0))
    }
}

pub fn register_process_monitor(engine: &mut Engine) -> Result<ProcessMonitorHandle> {
    // Check if monitoring is disabled via environment variable
    let monitoring_disabled = env::var("REX_RUNNER_DISABLE_MONITORING")
        .map(|val| val.to_lowercase() == "true" || val == "1")
        .unwrap_or(false);

    let process_monitor = Rc::new(RefCell::new(ProcessMonitor::new(
        process::id(),
        SAMPLING_INTERVAL_MSEC,
        !monitoring_disabled,
    )?));

    if !monitoring_disabled {
        let callback = ProcessMonitor::create_progress_callback(Rc::clone(&process_monitor), None);
        engine.on_progress(callback);
    }

    Ok(process_monitor)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Given: A ProcessMonitor with operation sampling enabled
    /// When: Multiple operations trigger sampling via the progress callback
    /// Then: CPU, RSS memory, and virtual memory averages should be calculated correctly and be non-negative
    #[test]
    fn test_metric_calculation() {
        let monitor =
            ProcessMonitor::new(process::id(), 0, true).expect("Failed to create monitor");
        let monitor_rc = Rc::new(RefCell::new(monitor));

        {
            let callback = ProcessMonitor::create_progress_callback(monitor_rc.clone(), None);
            for i in 1..=5 {
                callback(i);
            }
        }

        let mut monitor_ref = monitor_rc.borrow_mut();
        let cpu_avg = monitor_ref.get_cpu_usage();
        let memory_avg = monitor_ref.get_rss_memory_average_mb();
        let virtual_memory_avg = monitor_ref.get_virtual_memory_average_mb();

        assert!(
            cpu_avg.is_some(),
            "CPU usage should be available when monitoring is enabled"
        );
        assert!(
            cpu_avg.unwrap() >= 0.0,
            "CPU average should be non-negative"
        );
        assert!(
            memory_avg.is_some(),
            "RSS memory average should be available when monitoring is enabled"
        );
        assert!(
            memory_avg.unwrap() >= 0.0,
            "RSS memory average should be non-negative"
        );
        assert!(
            virtual_memory_avg.is_some(),
            "Virtual memory average should be available when monitoring is enabled"
        );
        assert!(
            virtual_memory_avg.unwrap() >= 0.0,
            "Virtual memory average should be non-negative"
        );
    }

    /// Given: A ProcessMonitor with no data collection (no callback invocations)
    /// When: Requesting CPU and memory averages from empty data sets
    /// Then: CPU should return actual usage since baseline, memory should return None (no samples)
    #[test]
    fn test_empty_data_points() {
        let mut monitor =
            ProcessMonitor::new(process::id(), 0, true).expect("Failed to create monitor");

        let cpu_usage = monitor.get_cpu_usage();
        assert!(
            cpu_usage.is_some(),
            "CPU usage should be available when monitoring is enabled"
        );
        assert!(
            cpu_usage.unwrap() >= 0.0,
            "CPU usage should be non-negative"
        );

        assert_eq!(
            monitor.get_rss_memory_average_mb(),
            None,
            "RSS memory should be None when no samples collected"
        );
        assert_eq!(
            monitor.get_virtual_memory_average_mb(),
            None,
            "Virtual memory should be None when no samples collected"
        );
    }

    /// Given: A ProcessMonitor with time constraint enabled (1000ms interval)
    /// When: Operations are invoked rapidly (faster than 1000ms apart)
    /// Then: Only the first operation should trigger sampling due to time constraint
    #[test]
    fn test_time_constraint_enforcement() {
        let monitor =
            ProcessMonitor::new(process::id(), 1000, true).expect("Failed to create monitor");
        let monitor_rc = Rc::new(RefCell::new(monitor));

        {
            let callback = ProcessMonitor::create_progress_callback(monitor_rc.clone(), None);
            for i in 1..=5 {
                callback(i);
            }
        }
        let monitor_ref = monitor_rc.borrow();
        // Should only have 1 sample (from the first operation)
        assert_eq!(
            monitor_ref.memory_data.len(),
            1,
            "Should only have 1 sample due to time constraint"
        );
    }

    /// Given: A ProcessMonitor with no time constraint (0ms interval)
    /// When: Operations trigger sampling based on time only
    /// Then: All operations should trigger sampling due to no time constraint
    #[test]
    fn test_no_time_constraint() {
        let monitor =
            ProcessMonitor::new(process::id(), 0, true).expect("Failed to create monitor");
        let monitor_rc = Rc::new(RefCell::new(monitor));
        {
            let callback = ProcessMonitor::create_progress_callback(monitor_rc.clone(), None);
            // All operations should trigger sampling (no time constraint)
            for i in 1..=5 {
                callback(i);
            }
        }
        let monitor_ref = monitor_rc.borrow();
        // Should have 5 samples: all operations since no time constraint
        assert_eq!(
            monitor_ref.memory_data.len(),
            5,
            "Should have 5 samples without time constraint"
        );
    }

    /// Given: The REX_RUNNER_DISABLE_MONITORING environment variable is set to "true"
    /// When: register_process_monitor is called
    /// Then: A ProcessMonitor is returned but no progress callback is registered
    #[test]
    fn test_monitoring_disabled_via_environment_variable() {
        // Set the environment variable to disable monitoring
        unsafe { env::set_var("REX_RUNNER_DISABLE_MONITORING", "true") };

        let mut engine = rhai::Engine::new();
        let result = register_process_monitor(&mut engine);

        // Clean up the environment variable
        unsafe { env::remove_var("REX_RUNNER_DISABLE_MONITORING") };

        // Should still return a ProcessMonitor handle successfully
        assert!(
            result.is_ok(),
            "Should return a ProcessMonitor handle even when monitoring is disabled"
        );

        // The monitor should be created but with monitoring disabled
        let monitor_handle = result.unwrap();
        let monitor_ref = monitor_handle.borrow();

        // Verify the monitor exists and returns None when monitoring is disabled
        assert_eq!(
            monitor_ref.get_rss_memory_average_mb(),
            None,
            "Should return None for memory when monitoring is disabled"
        );
        assert_eq!(
            monitor_ref.get_virtual_memory_average_mb(),
            None,
            "Should return None for virtual memory when monitoring is disabled"
        );
    }

    /// Given: A ProcessMonitor created with monitoring disabled
    /// When: Creating a progress callback and calling it
    /// Then: No sampling should occur
    #[test]
    fn test_disabled_monitor_no_sampling() {
        let mut monitor = ProcessMonitor::new(process::id(), 0, false)
            .expect("Failed to create disabled monitor");
        assert_eq!(
            monitor.get_cpu_usage(),
            None,
            "Should have no virtual memory samples when monitoring is disabled"
        );
        let monitor_rc = Rc::new(RefCell::new(monitor));

        {
            let callback = ProcessMonitor::create_progress_callback(monitor_rc.clone(), None);
            // Call callback multiple times
            for i in 1..=5 {
                callback(i);
            }
        }

        let monitor_ref = monitor_rc.borrow();
        // Should have no samples since monitoring is disabled
        assert_eq!(
            monitor_ref.memory_data.len(),
            0,
            "Should have no samples when monitoring is disabled"
        );
        assert_eq!(
            monitor_ref.virtual_memory_data.len(),
            0,
            "Should have no virtual memory samples when monitoring is disabled"
        );
    }
}
