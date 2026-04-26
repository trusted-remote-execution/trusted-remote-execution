#![deny(missing_docs)]
#![allow(
    unused_variables,
    unreachable_code,
    clippy::unreachable,
    unused_mut,
    clippy::needless_pass_by_value,
    dead_code,
    clippy::unused_self,
    clippy::trivially_copy_pass_by_ref
)]
#[cfg(target_os = "linux")]
use procfs::KernelStats;
#[cfg(target_os = "linux")]
use rhai::Array;
use rhai::EvalAltResult;
#[cfg(target_os = "linux")]
use rust_safe_system_info::SlabInfo;
use rust_safe_system_info::options::ResolveConfig;
#[cfg(target_os = "linux")]
use rust_safe_system_info::{DmesgOptions, UnameInfo};
use rust_safe_system_info::{Meminfo, Swapinfo};

/// Query system information: memory, CPU, kernel, and DNS.
#[derive(Clone, Debug, Copy)]
pub struct SystemInfo;

impl SystemInfo {
    /// Creates a new [`rust_safe_system_info::SystemInfo`] instance
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::sysinfo::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// #     &mut scope,
    /// #     r#"
    /// let system_info = SystemInfo();
    /// #     "#);
    /// #
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    pub fn new() -> Result<Self, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Gets memory information
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"read"` | [`file_system::File`](cedar_auth::fs::entities::FileEntity) |
    ///
    /// NB: Resource is `/proc/meminfo`.
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::sysinfo::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// #     &mut scope,
    /// #     r#"
    /// let system_info = SystemInfo();
    /// let meminfo = system_info.memory_info();
    /// print("Total memory: " + meminfo.total);
    /// print("Free memory: " + meminfo.free);
    /// print("Available memory: " + meminfo.available);
    /// print("Used memory: " + meminfo.used);
    /// #     "#);
    /// #
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[doc(alias = "free")]
    pub fn memory_info(&self) -> Result<Meminfo, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Gets swap information
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"read"` | [`file_system::File`](cedar_auth::fs::entities::FileEntity) |
    ///
    /// NB: Resource is `/proc/meminfo`.
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::sysinfo::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// #     &mut scope,
    /// #     r#"
    /// let system_info = SystemInfo();
    /// let swapinfo = system_info.swap_info();
    /// print("Total swap: " + swapinfo.total);
    /// print("Free swap: " + swapinfo.free);
    /// print("Used swap: " + swapinfo.used);
    /// #     "#);
    /// #
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[doc(alias = "free")]
    pub fn swap_info(&self) -> Result<Swapinfo, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Get kernel stats information
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"read"` | [`file_system::File`](cedar_auth::fs::entities::FileEntity) |
    ///
    /// NB: Resource is `/proc/stat`.
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::sysinfo::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// #     &mut scope,
    /// #     r#"
    /// let system_info = SystemInfo();
    /// let kernel_stats = system_info.kernel_stats();
    /// print("Boot time: " + kernel_stats.boot_time);
    /// print("Context switches: " + kernel_stats.context_switches);
    /// print("Processes forked: " + kernel_stats.forks);
    /// #     "#);
    /// #
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[doc(alias = "vmstat")]
    #[cfg(target_os = "linux")]
    pub fn kernel_stats(&self) -> Result<KernelStats, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Gets slab cache information
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"open"` | [`file_system::Dir`](cedar_auth::fs::entities::DirEntity) |
    /// | `file_system::Action::"open"` | [`file_system::File`](cedar_auth::fs::entities::FileEntity) |
    /// | `file_system::Action::"read"` | [`file_system::File`](cedar_auth::fs::entities::FileEntity) |
    ///
    /// NB: Dir is `/proc`, File is `/proc/slabinfo`.
    ///
    /// # Linux Capabilities
    ///
    /// | Capability | Condition |
    /// |------------|-----------|
    /// | `CAP_DAC_READ_SEARCH` | Always required |
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::sysinfo::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// #     &mut scope,
    /// #     r#"
    /// let system_info = SystemInfo();
    /// let slabinfo = system_info.slab_info();
    ///
    /// let summary = slabinfo.summary;
    /// print(summary.to_string());
    ///
    /// print(`Objects: ${summary.active_objects}/${summary.total_objects} (${summary.objects_usage_percent}% used)`);
    /// print(`Slabs: ${summary.active_slabs}/${summary.total_slabs} (${summary.slabs_usage_percent}% used)`);
    /// print(`Caches: ${summary.active_caches}/${summary.total_caches} (${summary.caches_usage_percent}% used)`);
    ///
    /// let slabs = slabinfo.slabs;
    /// for slab in slabs {
    ///     print(`${slab.name}: OBJS=${slab.objs} ACTIVE=${slab.active} USE%=${slab.use_percent} OBJ_SIZE=${slab.obj_size_kb}K SLABS=${slab.slabs} OBJ/SLAB=${slab.obj_per_slab} CACHE_SIZE=${slab.cache_size_kb}K`);
    /// }
    /// #     "#);
    /// #
    /// # assert!(result.is_err(), "Expected error due to missing CAP_DAC_READ_SEARCH capability");
    /// ```
    #[doc(alias = "slabtop")]
    #[cfg(target_os = "linux")]
    pub fn slab_info(&self) -> Result<SlabInfo, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Gets kernel ring buffer messages (dmesg)
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"read"` | [`file_system::File`](cedar_auth::fs::entities::FileEntity) |
    ///
    /// NB: Resource is `/dev/kmsg`.
    ///
    /// # Linux Capabilities
    ///
    /// | Capability | Condition |
    /// |------------|-----------|
    /// | `CAP_SYSLOG` | When `kernel.dmesg_restrict=1` |
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use rex_test_utils::rhai::sysinfo::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// #     &mut scope,
    /// #     r#"
    /// let system_info = SystemInfo();
    /// let dmesg_options = DmesgOptions()
    ///     .human_readable_time(true)
    ///     .build();
    /// let entries = system_info.dmesg_info(dmesg_options);
    /// for entry in entries {
    ///     print(`[${entry.timestamp_from_system_start}] ${entry.message}`);
    /// }
    /// #     "#);
    /// #
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[doc(alias = "dmesg")]
    #[cfg(target_os = "linux")]
    pub fn dmesg_info(&self, options: DmesgOptions) -> Result<Array, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Returns the uinfo of the instance.
    ///
    /// This is equivalent to `uname` on Unix.
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `sysinfo::Action::"list"` | [`sysinfo::Sysinfo`](cedar_auth::sysinfo::entities::SysinfoEntity) |
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::sysinfo::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<String>(
    /// #     &mut scope,
    /// #     r#"
    /// let system_info = SystemInfo();
    /// let uname = system_info.uname_info();
    /// uname.to_string();
    /// #     "#);
    /// #
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[doc(alias = "uname")]
    #[cfg(target_os = "linux")]
    pub fn uname_info(&self) -> Result<UnameInfo, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Resolves a hostname to its IP addresses
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `sysinfo::Action::"resolve_hostname"` | [`sysinfo::Hostname`](cedar_auth::sysinfo::entities::HostnameEntity) |
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::sysinfo::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// #     &mut scope,
    /// #     r#"
    /// let system_info = SystemInfo();
    /// let resolve_opts = ResolveOptions().hostname("localhost").build();
    /// // or use a custom resolver
    /// let resolve_opts = ResolveOptions().hostname("localhost")
    ///                                    .resolver("8.8.8.8").build();
    /// // or choose a custom protocol for resolution
    /// let resolve_opts = ResolveOptions().hostname("localhost")
    ///                                    .resolver("8.8.8.8")
    ///                                    .protocol(TransportProtocol::TCP).build();
    /// // or choose a custom timeout duration in seconds to override the default of
    /// // of 5 seconds
    /// let resolve_opts = ResolveOptions().hostname("localhost")
    ///                                    .resolver("8.8.8.8")
    ///                                    .timeout(from_secs(10))
    ///                                    .protocol(TransportProtocol::TCP).build();
    /// let addresses = system_info.resolve_hostname(resolve_opts);
    ///
    /// if addresses.is_empty() {
    ///     throw "failed to resolve localhost"
    /// }
    /// #     "#);
    /// #
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[doc(alias = "dig")]
    #[doc(alias = "nslookup")]
    pub fn resolve_hostname(&self, opts: ResolveConfig) -> Result<Vec<String>, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Gets the system hostname
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `sysinfo::Action::"list"` | [`sysinfo::Sysinfo`](cedar_auth::sysinfo::entities::SysinfoEntity) |
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::sysinfo::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<String>(
    /// #     &mut scope,
    /// #     r#"
    /// let system_info = SystemInfo();
    /// system_info.hostname();
    /// #     "#);
    /// #
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// # let hostname = result.unwrap();
    /// # assert!(!hostname.is_empty(), "Hostname should not be empty");
    /// ```
    pub fn hostname(&self) -> Result<String, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Returns the number of logical CPUs available on the system
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `sysinfo::Action::"list"` | [`sysinfo::Sysinfo`](cedar_auth::sysinfo::entities::SysinfoEntity) |
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::sysinfo::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<i64>(
    /// #     &mut scope,
    /// #     r#"
    /// let system_info = SystemInfo();
    /// let cpu_count = system_info.cpu_count();
    /// print("System has " + cpu_count + " logical CPUs");
    /// cpu_count
    /// #     "#);
    /// #
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// # let count = result.unwrap();
    /// # assert!(count > 0, "CPU count should be at least 1");
    /// ```
    #[doc(alias = "nproc")]
    pub fn cpu_count(&self) -> Result<i64, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }
}
