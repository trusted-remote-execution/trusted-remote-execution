#[cfg(target_os = "linux")]
use crate::kernel_stats::{RhaiCpuTime, RhaiKernelStats};
use rex_cedar_auth::cedar_auth::CedarAuth;

use std::rc::Rc;

use rust_safe_system_info::{
    DmesgEntry, DmesgOptions, DmesgOptionsBuilder, Meminfo, ResolveConfig, ResolveConfigBuilder,
    Swapinfo, SystemInfo, TransportProtocol, UnameInfo,
};
#[cfg(target_os = "linux")]
use rust_safe_system_info::{SlabEntry, SlabInfo, SlabSummary, SysctlEntry, SysctlManager};

use crate::errors::{ERROR_MODULE_NAME, RhaiSysteminfoErrorKind};
use crate::transport_protocol::transport_protocol_type_mod;
use rex_logger::push_rhai_context_with_guard;
#[cfg(target_os = "linux")]
use rex_runner_registrar_utils::register_getter_with_guard;
use rex_runner_registrar_utils::{
    execution_context::ExecutionContext, register_derive_builder_options, register_direct_safe_fn,
    register_getters_with_guard, register_map_serializers, register_safe_fn, register_with_guard,
};

use rhai::plugin::{
    Engine, FnNamespace, FuncRegistration, Module, NativeCallContext, PluginFunc, RhaiResult,
    TypeId, export_module, exported_module, mem,
};
use rhai::serde::to_dynamic;
use rhai::{Array, Dynamic, EvalAltResult};

#[allow(non_upper_case_globals)]
#[allow(unreachable_pub)]
#[allow(clippy::unwrap_used)]
#[export_module]
mod error_kind_module {
    use super::Module;

    pub const AuthorizationError: RhaiSysteminfoErrorKind =
        RhaiSysteminfoErrorKind::AuthorizationError;
    pub const PermissionDenied: RhaiSysteminfoErrorKind = RhaiSysteminfoErrorKind::PermissionDenied;
    pub const IoError: RhaiSysteminfoErrorKind = RhaiSysteminfoErrorKind::IoError;
    #[cfg(target_os = "linux")]
    pub const CapsError: RhaiSysteminfoErrorKind = RhaiSysteminfoErrorKind::CapsError;
    pub const InvalidParameter: RhaiSysteminfoErrorKind = RhaiSysteminfoErrorKind::InvalidParameter;
    pub const InvalidValue: RhaiSysteminfoErrorKind = RhaiSysteminfoErrorKind::InvalidValue;
    pub const PrivilegeError: RhaiSysteminfoErrorKind = RhaiSysteminfoErrorKind::PrivilegeError;
    #[cfg(target_os = "linux")]
    pub const ProcFsError: RhaiSysteminfoErrorKind = RhaiSysteminfoErrorKind::ProcFsError;
    pub const Other: RhaiSysteminfoErrorKind = RhaiSysteminfoErrorKind::Other;

    #[rhai_fn(global, name = "==", pure)]
    pub fn eq(error_kind: &mut RhaiSysteminfoErrorKind, other: RhaiSysteminfoErrorKind) -> bool {
        error_kind == &other
    }

    #[rhai_fn(global, name = "!=", pure)]
    pub fn neq(error_kind: &mut RhaiSysteminfoErrorKind, other: RhaiSysteminfoErrorKind) -> bool {
        error_kind != &other
    }

    #[rhai_fn(global, name = "to_string")]
    pub fn to_string(kind: &mut RhaiSysteminfoErrorKind) -> String {
        kind.to_string()
    }
}

pub(crate) fn get_rhai_context_guard(context: &NativeCallContext) -> impl Drop {
    let line_number = context
        .call_position()
        .line()
        .map_or(0, |l| u32::try_from(l).unwrap_or(0));

    push_rhai_context_with_guard(Some(context.fn_name()), line_number)
}

#[allow(clippy::too_many_lines)]
/// Registers functions and types with the Rhai engine for use in scripts.
///
/// The `execution_context` parameter enables critical error handling by providing a shared
/// termination flag. When critical errors occur (e.g., `PrivilegeError` during privilege
/// elevation/drop), the error handler signals termination through this context, causing
/// the script execution to halt immediately rather than continuing with potentially
/// unsafe operations.
pub(super) fn register(
    engine: &mut Engine,
    cedar_auth: &Rc<CedarAuth>,
    execution_context: Option<&ExecutionContext>,
) {
    engine
        .register_type_with_name::<RhaiSysteminfoErrorKind>("RhaiSysteminfoErrorKind")
        .register_static_module(
            ERROR_MODULE_NAME,
            exported_module!(error_kind_module).into(),
        );

    engine
        .register_type_with_name::<TransportProtocol>("TransportProtocol")
        .register_static_module(
            "TransportProtocol",
            exported_module!(transport_protocol_type_mod).into(),
        );

    register_with_guard!(
        engine,
        "SystemInfo",
        SystemInfo,
        SystemInfo::new,
        crate::errors::convert_to_rhai_error
    );
    #[cfg(target_os = "linux")]
    {
        register_direct_safe_fn!(
            engine,
            "uname_info",
            SystemInfo,
            uname_info,
            cedar_auth,
            -> UnameInfo,
            crate::errors::convert_to_rhai_error;
            tests: { positive: "test_get_uname_info_success", negative: "test_get_uname_info_unauthorized" }
        );
    }
    register_direct_safe_fn!(
        engine,
        "resolve_hostname",
        SystemInfo,
        resolve,
        cedar_auth,
        -> Array,
        transform: |entries: Vec<String>| -> Result<Array, Box<EvalAltResult>> {
            Ok(entries.into_iter().map(Dynamic::from).collect())
        },
        crate::errors::convert_to_rhai_error,
        config: ResolveConfig;
        tests: { positive: "test_resolve_hostname_success", negative: "test_resolve_hostname_unauthorized" }
    );

    register_derive_builder_options!(
        engine,
        ResolveConfigBuilder,
        "ResolveOptions",
        ResolveConfig,
        setters: [
            (hostname, String),
            (protocol, TransportProtocol),
            (resolver, String),
            (timeout, i64 => u64)
        ]
    );

    register_direct_safe_fn!(
        engine,
        "hostname",
        SystemInfo,
        hostname,
        cedar_auth,
        -> String,
        crate::errors::convert_to_rhai_error;
        tests: { positive: "test_hostname_success", negative: "test_hostname_unauthorized" }
    );

    register_direct_safe_fn!(
        engine,
        "memory_info",
        SystemInfo,
        memory_info,
        cedar_auth,
        -> Meminfo,
        crate::errors::convert_to_rhai_error;
        tests: { positive: "test_get_memory_info", negative: "test_get_memory_info_unauthorized" }
    );
    register_direct_safe_fn!(
        engine,
        "swap_info",
        SystemInfo,
        swap_info,
        cedar_auth,
        -> Swapinfo,
        crate::errors::convert_to_rhai_error;
        tests: { positive: "test_get_swap_info", negative: "test_get_swap_info_unauthorized" }
    );
    #[cfg(target_os = "linux")]
    {
        register_direct_safe_fn!(
            engine,
            "dmesg_info",
            SystemInfo,
            dmesg_info,
            cedar_auth,
            -> Array,
            transform: |entries: Vec<DmesgEntry>| -> Result<Array, Box<EvalAltResult>> {
                Ok(entries.into_iter().map(Dynamic::from).collect())
            },
            crate::errors::convert_to_rhai_error,
            options: DmesgOptions;
            tests: { positive: "test_get_dmesg_info_unauthorized", negative: "test_get_dmesg_info_unauthorized" }
        );
    }

    engine.register_type::<Meminfo>();
    register_safe_fn!(engine, "to_string", Meminfo::to_string, self);
    register_getters_with_guard!(engine, Meminfo, [total, free, available, used]);

    engine.register_type::<Swapinfo>();
    register_safe_fn!(engine, "to_string", Swapinfo::to_string, self);
    register_getters_with_guard!(engine, Swapinfo, [total, free, used]);

    register_direct_safe_fn!(
        engine,
        "cpu_count",
        SystemInfo,
        cpu_count,
        cedar_auth,
        -> i64,
        transform: |count: usize| -> Result<i64, Box<EvalAltResult>> {
            i64::try_from(count).map_err(|e| format!("Failed to convert CPU count to i64: {e}").into())
        },
        crate::errors::convert_to_rhai_error;
        tests: { positive: "test_cpu_count_success", negative: "test_cpu_count_unauthorized" }
    );

    register_safe_fn!(engine, "to_string", DmesgEntry::to_string, self);
    register_getters_with_guard!(engine, DmesgEntry, [timestamp_from_system_start, message]);

    register_derive_builder_options!(
        engine,
        DmesgOptionsBuilder,
        "DmesgOptions",
        DmesgOptions,
        setters: [
            (human_readable_time, bool)
        ]
    );

    engine.register_type::<UnameInfo>();
    register_safe_fn!(engine, "to_string", UnameInfo::to_string, self);
    register_getters_with_guard!(
        engine,
        UnameInfo,
        [
            kernel_name,
            nodename,
            kernel_release,
            kernel_version,
            machine,
            processor,
            hardware_platform,
            operating_system
        ]
    );

    register_map_serializers!(engine, [UnameInfo, Swapinfo, DmesgEntry]);

    register_platform_specific_functions(engine, cedar_auth, execution_context);
}

#[allow(clippy::too_many_lines)]
fn register_platform_specific_functions(
    // engine, cedar_auth, execution_context not used in MacOS
    #[allow(unused_variables)] engine: &mut Engine,
    #[allow(unused_variables)] cedar_auth: &Rc<CedarAuth>,
    #[allow(unused_variables)] execution_context: Option<&ExecutionContext>,
) {
    #[cfg(target_os = "linux")]
    {
        // Meminfo linux-specific functions
        register_getters_with_guard!(engine, Meminfo, [buffers, cached]);
        register_getter_with_guard!(engine, "shared_mem", Meminfo, shared);

        register_direct_safe_fn!(
            engine,
            "kernel_stats",
            SystemInfo,
            kernel_stats,
            cedar_auth,
            -> RhaiKernelStats,
            transform: |ks: procfs::KernelStats| -> Result<RhaiKernelStats, Box<EvalAltResult>> {
                Ok(RhaiKernelStats::from(ks))
            },
            crate::errors::convert_to_rhai_error;
            tests: { positive: "test_kernel_stats_basic_getters", negative: "test_get_kernel_stats_unauthorized" }
        );
        register_direct_safe_fn!(
            engine,
            "slab_info",
            SystemInfo,
            slab_info,
            cedar_auth,
            -> SlabInfo,
            crate::errors::convert_to_rhai_error;
            tests: { positive: "test_get_slab_info_authorized_but_no_capability", negative: "test_get_slab_info_unauthorized" }
        );

        // Register SlabInfo types (Linux only)
        engine.register_type::<SlabInfo>();
        register_getter_with_guard!(engine, SlabInfo, slabs,
            transform: |entries: Vec<SlabEntry>| -> Result<Array, Box<EvalAltResult>> {
                Ok(entries.into_iter().map(Dynamic::from).collect())
            }
        );
        register_getter_with_guard!(engine, SlabInfo, summary);

        engine.register_type::<SlabEntry>();

        // This is a temporary fix to allow sorting based on objs field as sort needs an i64 in rhai
        // Once we create a macro for registering u64 types as i64 in rhai, this should be backported.
        register_getter_with_guard!(engine, "objs", SlabEntry, objs,
            transform: |objs: u64| -> Result<i64, Box<EvalAltResult>> {
                i64::try_from(objs).map_err(|e| format!("Failed to convert objs u64 to i64: {e}").into())
            }
        );

        register_getters_with_guard!(
            engine,
            SlabEntry,
            [
                active,
                slabs,
                obj_per_slab,
                pages_per_slab,
                obj_size_bytes,
                name,
                use_percent,
                obj_size_kb,
                cache_size_kb,
                active_size_kb
            ]
        );

        engine.register_type::<SlabSummary>();

        register_getters_with_guard!(
            engine,
            SlabSummary,
            [
                active_objects,
                total_objects,
                active_slabs,
                total_slabs,
                active_caches,
                total_caches,
                objects_usage_percent,
                slabs_usage_percent,
                caches_usage_percent,
                size_usage_percent,
                active_size_kb,
                total_size_kb,
                min_obj_size_kb,
                avg_obj_size_kb,
                max_obj_size_kb
            ]
        );

        register_safe_fn!(engine, "to_string", SlabSummary::to_string, self);

        // Register SysctlManager (Linux only)
        engine.register_type::<SysctlManager>();
        register_with_guard!(
            engine,
            "SysctlManager",
            SysctlManager,
            SysctlManager::new,
            crate::errors::convert_to_rhai_error_with_execution_context,
            execution_context: execution_context.cloned()
        );

        register_direct_safe_fn!(
            engine,
            "read",
            SysctlManager,
            read,
            cedar_auth,
            -> String,
            crate::errors::convert_to_rhai_error_with_execution_context,
            execution_context: execution_context.cloned(),
            key: &str;
            tests: { positive: "test_sysctl_read_success", negative: "test_sysctl_read_unauthorized" }
        );

        register_direct_safe_fn!(
            engine,
            "write",
            SysctlManager,
            write,
            cedar_auth,
            -> (),
            crate::errors::convert_to_rhai_error_with_execution_context,
            execution_context: execution_context.cloned(),
            key: &str,
            value: &str;
            tests: { positive: "test_sysctl_write_unauthorized", negative: "test_sysctl_write_unauthorized" }
        );

        register_direct_safe_fn!(
            engine,
            "load_system",
            SysctlManager,
            load_system,
            cedar_auth,
            -> (),
            crate::errors::convert_to_rhai_error_with_execution_context,
            execution_context: execution_context.cloned();
            tests: { positive: "test_sysctl_load_system_unauthorized", negative: "test_sysctl_load_system_unauthorized" }
        );

        register_direct_safe_fn!(
            engine,
            "find",
            SysctlManager,
            find,
            cedar_auth,
            -> Array,
            transform: |entries: Vec<SysctlEntry>| -> Result<Array, Box<EvalAltResult>> {
                Ok(entries.into_iter().map(Dynamic::from).collect())
            },
            crate::errors::convert_to_rhai_error_with_execution_context,
            execution_context: execution_context.cloned(),
            pattern: &str;
            tests: { positive: "test_sysctl_find_success", negative: "test_sysctl_find_unauthorized" }
        );

        // Register SysctlEntry type
        engine.register_type::<SysctlEntry>();
        register_getters_with_guard!(engine, SysctlEntry, [key, value]);

        register_map_serializers!(
            engine,
            [Meminfo, SlabInfo, SlabEntry, SlabSummary, SysctlEntry]
        );

        // Register CpuStats + KernelStats
        register_getters_with_guard!(
            engine,
            RhaiCpuTime,
            [
                user_ticks,
                nice_ticks,
                system_ticks,
                idle_ticks,
                iowait_ticks,
                irq_ticks,
                softirq_ticks,
                stolen_ticks,
                guest_ticks,
                guest_nice_ticks,
                user_ms,
                nice_ms,
                system_ms,
                idle_ms,
                iowait_ms,
                irq_ms,
                softirq_ms,
                stolen_ms,
                guest_ms,
                guest_nice_ms,
            ]
        );
        register_map_serializers!(engine, [RhaiCpuTime]);

        register_getters_with_guard!(engine, RhaiKernelStats, [
            total_cpu_time,
            (cpu_time, Vec<RhaiCpuTime> => Array),
            procs_running, procs_blocked,
            context_switches, boot_time, forks,
        ]);
        register_map_serializers!(engine, [RhaiKernelStats]);
    }
}

#[cfg(test)]
mod tests {
    use rex_test_utils::rhai::common::create_test_engine_and_register;

    /// Given: Two identical RhaiSysteminfoErrorKind values
    /// When: Comparing them for equality in the Rhai engine
    /// Then: They should be equal
    #[test]
    fn test_error_kind_equality_same_type() {
        let engine = create_test_engine_and_register();
        let result = engine
            .eval::<bool>(
                r#"
	                 let a = SysteminfoErrorKind::IoError;
	                 let b = SysteminfoErrorKind::IoError;
	                 a == b
	             "#,
            )
            .unwrap();
        assert!(result);
    }

    /// Given: Two identical RhaiSysteminfoErrorKind values
    /// When: Comparing them for inequality in the Rhai engine
    /// Then: They should not be unequal
    #[test]
    fn test_error_kind_inequality_same_type() {
        let engine = create_test_engine_and_register();
        let result = engine
            .eval::<bool>(
                r#"
	                 let a = SysteminfoErrorKind::IoError;
	                 let b = SysteminfoErrorKind::IoError;
	                 a != b
	             "#,
            )
            .unwrap();
        assert!(!result);
    }

    /// Given: Two different RhaiSysteminfoErrorKind values
    /// When: Comparing them for inequality in the Rhai engine
    /// Then: They should be unequal
    #[test]
    fn test_error_kind_inequality_different_types() {
        let engine = create_test_engine_and_register();
        let result = engine
            .eval::<bool>(
                r#"
	                 let a = SysteminfoErrorKind::IoError;
	                 let b = SysteminfoErrorKind::PermissionDenied;
	                 a != b
	             "#,
            )
            .unwrap();
        assert!(result);
    }

    /// Given: Two different RhaiSysteminfoErrorKind values
    /// When: Comparing them for equality in the Rhai engine
    /// Then: They should not be equal
    #[test]
    fn test_error_kind_equality_different_types() {
        let engine = create_test_engine_and_register();
        let result = engine
            .eval::<bool>(
                r#"
	                 let a = SysteminfoErrorKind::IoError;
	                 let b = SysteminfoErrorKind::PermissionDenied;
	                 a == b
	             "#,
            )
            .unwrap();
        assert!(!result);
    }

    /// Given: A RhaiSysteminfoErrorKind value
    /// When: Converting it to a string in the Rhai engine
    /// Then: It should return the correct string representation
    #[test]
    fn test_error_kind_to_string() {
        let engine = create_test_engine_and_register();

        let result = engine
            .eval::<String>(
                r#"
	                 let kind = SysteminfoErrorKind::IoError;
	                 kind.to_string()
	                 "#,
            )
            .unwrap();

        assert_eq!(result, "IoError");
    }
}
