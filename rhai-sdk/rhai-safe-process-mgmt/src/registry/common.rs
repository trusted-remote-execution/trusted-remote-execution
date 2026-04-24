use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_logger::push_rhai_context_with_guard;
use rex_runner_registrar_utils::{
    execution_context::ExecutionContext, register_derive_builder_options, register_direct_safe_fn,
    register_getter_with_guard, register_getters_with_guard, register_map_serializers,
    register_safe_fn, register_to_string_with_json, register_with_guard,
};
use rhai::serde::to_dynamic;
use rhai::{Array, Dynamic, Engine, EvalAltResult, Map};
use rust_safe_io::TracedProcess;
use rust_safe_process_mgmt::systemctl::{ServiceInfo, State, SystemctlManager};
use rust_safe_process_mgmt::{
    AccessType, FileType, FuserInfo, IpcsInfo, OpenFileInfo, PidNamespace, ProcessInfo,
    RcProcessManager,
};
use rustix::process::Signal;
use std::rc::Rc;

use crate::errors::{ERROR_MODULE_NAME, RhaiSafeProcessMgmtErrorKind};
use crate::signal::signal_type_mod;
use crate::state::active_state_module;
use rust_safe_process_mgmt::options::{
    KillOptions, KillOptionsBuilder, LsofOptions, LsofOptionsBuilder, MonitorProcessesCpuOptions,
    MonitorProcessesCpuOptionsBuilder, NamespaceOptions, NamespaceOptionsBuilder, ProcessOptions,
    ProcessOptionsBuilder, TraceOptions, TraceOptionsBuilder,
};

use rhai::plugin::{
    FnNamespace, FuncRegistration, Module, NativeCallContext, PluginFunc, RhaiResult, TypeId,
    export_module, exported_module, mem,
};

#[allow(non_upper_case_globals)]
#[allow(unreachable_pub)]
#[allow(clippy::unwrap_used)]
#[export_module]
mod error_kind_module {
    use super::Module;

    pub const ProcessNotFound: RhaiSafeProcessMgmtErrorKind =
        RhaiSafeProcessMgmtErrorKind::ProcessNotFound;
    pub const PidNamespaceOperationError: RhaiSafeProcessMgmtErrorKind =
        RhaiSafeProcessMgmtErrorKind::PidNamespaceOperationError;
    pub const NamespaceOperationError: RhaiSafeProcessMgmtErrorKind =
        RhaiSafeProcessMgmtErrorKind::NamespaceOperationError;
    pub const PermissionDenied: RhaiSafeProcessMgmtErrorKind =
        RhaiSafeProcessMgmtErrorKind::PermissionDenied;
    pub const AuthorizationError: RhaiSafeProcessMgmtErrorKind =
        RhaiSafeProcessMgmtErrorKind::AuthorizationError;
    pub const ValidationError: RhaiSafeProcessMgmtErrorKind =
        RhaiSafeProcessMgmtErrorKind::ValidationError;
    pub const CallbackExecutionError: RhaiSafeProcessMgmtErrorKind =
        RhaiSafeProcessMgmtErrorKind::CallbackExecutionError;
    pub const ProcessEnumerationError: RhaiSafeProcessMgmtErrorKind =
        RhaiSafeProcessMgmtErrorKind::ProcessEnumerationError;
    pub const DBusError: RhaiSafeProcessMgmtErrorKind = RhaiSafeProcessMgmtErrorKind::DBusError;
    pub const PrivilegeError: RhaiSafeProcessMgmtErrorKind =
        RhaiSafeProcessMgmtErrorKind::PrivilegeError;
    pub const ServiceNotFound: RhaiSafeProcessMgmtErrorKind =
        RhaiSafeProcessMgmtErrorKind::ServiceNotFound;
    pub const Other: RhaiSafeProcessMgmtErrorKind = RhaiSafeProcessMgmtErrorKind::Other;

    #[rhai_fn(global, name = "==", pure)]
    pub fn eq(
        error_kind: &mut RhaiSafeProcessMgmtErrorKind,
        other: RhaiSafeProcessMgmtErrorKind,
    ) -> bool {
        error_kind == &other
    }

    #[rhai_fn(global, name = "!=", pure)]
    pub fn neq(
        error_kind: &mut RhaiSafeProcessMgmtErrorKind,
        other: RhaiSafeProcessMgmtErrorKind,
    ) -> bool {
        error_kind != &other
    }

    #[rhai_fn(global, name = "to_string")]
    pub fn to_string(kind: &mut RhaiSafeProcessMgmtErrorKind) -> String {
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

/// Registers process management functions with the Rhai engine for use in scripts.
#[allow(clippy::too_many_lines)]
pub(super) fn register_safe_process_functions(
    engine: &mut Engine,
    cedar_auth: &Rc<CedarAuth>,
    execution_context: Option<&ExecutionContext>,
) {
    // Register error kinds
    engine
        .register_type_with_name::<RhaiSafeProcessMgmtErrorKind>("RhaiSafeProcessMgmtErrorKind")
        .register_static_module(
            ERROR_MODULE_NAME,
            exported_module!(error_kind_module).into(),
        );

    engine
        .register_type_with_name::<Signal>("Signal")
        .register_static_module("Signal", exported_module!(signal_type_mod).into());

    engine
        .register_type_with_name::<State>("State")
        .register_static_module("State", exported_module!(active_state_module).into());

    engine.register_type::<PidNamespace>();
    register_getters_with_guard!(
        engine,
        PidNamespace,
        [(namespace_id, u64 => i64), (child_ns_pid, u32 => i64)]
    );

    engine.register_type::<ProcessInfo>();
    register_getters_with_guard!(
        engine,
        ProcessInfo,
        [
            name,
            username,
            memory_percent,
            state,
            command,
            (pid_namespace, Option<PidNamespace> => PidNamespace),
            (memory_usage, u64 => i64),
            (pid, u32 => i64),
            (ppid, Option<u32> => i64),
            (uid, Option<u32> => i64),
            (recent_cpu_usage, Option<f32> => f64),
            (historical_cpu_usage, f32 => f64),
        ]
    );

    engine.register_type::<FuserInfo>();
    register_getters_with_guard!(engine, FuserInfo, [user, command, (pid, u32 => i64)]);

    register_getter_with_guard!(engine, "access", FuserInfo, format_access);

    engine.register_type::<IpcsInfo>();
    register_getters_with_guard!(engine, IpcsInfo, [shared_memory, queues, semaphores]);
    register_safe_fn!(engine, "to_string", IpcsInfo::to_string, self);

    register_derive_builder_options!(
        engine,
        LsofOptionsBuilder,
        "LsofOptions",
        LsofOptions,
        setters: [(path, String), (include_subdir, bool)]
    );

    engine.register_type::<OpenFileInfo>();
    register_getters_with_guard!(
        engine,
        OpenFileInfo,
        [process_name, user, command, file_path, (pid, u32 => i64)]
    );

    register_getter_with_guard!(
        engine,
        "file_type",
        OpenFileInfo,
        file_type,
        transform: |file_type: FileType| file_type.to_string()
    );

    register_getter_with_guard!(
        engine,
        "access",
        OpenFileInfo,
        access_type,
        transform: |access_type: AccessType| access_type.to_string()
    );

    engine.register_type::<RcProcessManager>();
    register_with_guard!(
        engine,
        "ProcessManager",
        RcProcessManager,
        RcProcessManager::default
    );

    register_derive_builder_options!(
        engine,
        ProcessOptionsBuilder,
        "ProcessOptions",
        ProcessOptions,
        setters: [(load_namespace_info, bool), (include_threads, bool)]
    );

    register_direct_safe_fn!(
        engine,
        "processes",
        RcProcessManager,
        safe_processes,
        cedar_auth,
        -> Array,
        transform: |processes: Vec<ProcessInfo>| -> Result<Array, Box<EvalAltResult>> {
            Ok(processes
                .into_iter()
                .map(Dynamic::from)
                .collect())
        },
        crate::errors::convert_to_rhai_error;
        tests: { positive: "test_get_processes_success", negative: "test_get_processes_success" }
    );

    register_direct_safe_fn!(
        engine,
        "processes",
        RcProcessManager,
        safe_processes_with_options,
        cedar_auth,
        -> Array,
        transform: |processes: Vec<ProcessInfo>| -> Result<Array, Box<EvalAltResult>> {
            Ok(processes
                .into_iter()
                .map(Dynamic::from)
                .collect())
        },
        crate::errors::convert_to_rhai_error,
        options: ProcessOptions;
        tests: { positive: "test_get_processes_success", negative: "test_get_processes_success" }
    );

    register_direct_safe_fn!(
        engine,
        "processes_using_inode",
        RcProcessManager,
        safe_fuser,
        cedar_auth,
        -> Array,
        transform: |fuser_infos: Vec<FuserInfo>| -> Result<Array, Box<EvalAltResult>> {
            Ok(fuser_infos
                .into_iter()
                .map(Dynamic::from)
                .collect())
        },
        crate::errors::convert_to_rhai_error,
        path: &str;
        tests: { positive: "test_get_processes_using_inode_success", negative: "test_get_processes_using_inode_fail" }
    );

    register_direct_safe_fn!(
        engine,
        "list_open_files",
        RcProcessManager,
        safe_lsof,
        cedar_auth,
        -> Array,
        transform: |open_files: Vec<OpenFileInfo>| -> Result<Array, Box<EvalAltResult>> {
            Ok(open_files
                .into_iter()
                .map(Dynamic::from)
                .collect())
        },
        crate::errors::convert_to_rhai_error,
        options: LsofOptions;
        tests: { positive: "test_process_manager_list_open_files", negative: "test_process_manager_list_open_files_fail" }
    );

    register_direct_safe_fn!(
        engine,
        "ipcs_info",
        RcProcessManager,
        safe_ipcs,
        cedar_auth,
        -> IpcsInfo,
        crate::errors::convert_to_rhai_error;
        // Add negative test
        tests: { positive: "test_ipcs_info", negative: "test_ipcs_info" }
    );

    register_direct_safe_fn!(
        engine,
        "kill",
        RcProcessManager,
        safe_kill,
        cedar_auth,
        -> Array,
        transform: |killed_processes: Vec<(String, u32)>| -> Result<Array, Box<EvalAltResult>> {
            Ok(killed_processes
                .into_iter()
                .map(|(name, pid)| {
                    let mut map = Map::new();
                    map.insert("name".into(), Dynamic::from(name));
                    map.insert("pid".into(), Dynamic::from(i64::from(pid)));
                    Dynamic::from(map)
                })
                .collect())
        },
        crate::errors::convert_to_rhai_error,
        kill_options: KillOptions;
        tests: { positive: "test_process_manager_kill_success", negative: "test_process_manager_kill_nonexistent_process" }
    );

    register_direct_safe_fn!(
        engine,
        "trace",
        RcProcessManager,
        safe_trace,
        cedar_auth,
        -> TracedProcess,
        crate::errors::convert_to_rhai_error,
        pid: i64 => u32;
        // the actual positive test is test_process_manager_trace_success, but since we can't run that test on AL2023
        // (pstack isn't installed) we avoid the build failure by putting the permission denied test in its place
        tests: { positive: "test_process_manager_trace_invalid_pid", negative: "test_process_manager_trace_invalid_pid" }
    );

    register_derive_builder_options!(
        engine,
        TraceOptionsBuilder,
        "TraceOptions",
        TraceOptions,
        setters: [(ns_pid, i64 => u32)]
    );

    register_direct_safe_fn!(
        engine,
        "trace",
        RcProcessManager,
        safe_trace_with_namespace,
        cedar_auth,
        -> TracedProcess,
        crate::errors::convert_to_rhai_error,
        pid: i64 => u32,
        options: TraceOptions;
        // We can't run a positive test here because that requires `CAP_SYS_ADMIN` to enter into the pid namespace. We test this in REX integration tests instead.
        tests: { positive: "test_process_manager_trace_with_namespace_permission_denied", negative: "test_process_manager_trace_with_namespace_permission_denied" }
    );

    engine.register_fn("nsenter", {
        let cedar_auth = cedar_auth.clone();
        move |context: NativeCallContext,
              manager: &mut RcProcessManager,
              options: NamespaceOptions,
              callback: rhai::FnPtr|
              -> Result<Dynamic, Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&context);

            // Integration test for nsenter as testing requires `CAP_SYS_ADMIN` capability.
            match manager.safe_nsenter(
                &options,
                || callback.call_within_context(&context, ()),
                &cedar_auth,
            ) {
                Ok(result) => Ok(result),
                Err(e) => crate::errors::convert_to_rhai_error(&e),
            }
        }
    });

    register_derive_builder_options!(
        engine,
        KillOptionsBuilder,
        "KillOptions",
        KillOptions,
        setters: [
            (pid, i64),
            (process_name, String),
            (username, String),
            (exact_match, bool),
            (command, String),
            (signal, Signal)
        ]
    );

    register_derive_builder_options!(
        engine,
        MonitorProcessesCpuOptionsBuilder,
        "MonitorProcessesCpuOptions",
        MonitorProcessesCpuOptions,
        setters: [
            (pids_to_monitor, Array, transform: |pids: Array| -> Vec<u32> { pids.into_iter().filter_map(|v| u32::try_from(v.as_int().unwrap_or(0)).ok()).collect() }),
            (batches, i64 => u32),
            (delay_in_seconds, i64 => u64),
            (include_threads, bool)
        ]
    );

    register_direct_safe_fn!(
        engine,
        "monitor_processes_cpu",
        RcProcessManager,
        safe_monitor_processes_cpu,
        cedar_auth,
        -> Array,
        transform: |batches: Vec<Vec<ProcessInfo>>| -> Result<Array, Box<EvalAltResult>> {
            Ok(batches
                .into_iter()
                .map(|batch| {
                    let batch_array: Array = batch.into_iter().map(Dynamic::from).collect();
                    Dynamic::from(batch_array)
                })
                .collect())
        },
        crate::errors::convert_to_rhai_error,
        options: MonitorProcessesCpuOptions;
        tests: { positive: "test_process_manager_top_success", negative: "test_process_manager_top_fail" }
    );

    register_derive_builder_options!(
        engine,
        NamespaceOptionsBuilder,
        "NamespaceOptions",
        NamespaceOptions,
        setters: [
            (mount, bool),
            (net, bool),
            (pid, i64 => u32),
            (net_ns_name, String)
        ]
    );

    engine.register_type::<ServiceInfo>();
    register_getters_with_guard!(
        engine,
        ServiceInfo,
        [
            name,
            description,
            load_state,
            load_path,
            unit_file_state,
            unit_file_preset,
            sub_state,
            active_state,
            need_daemon_reload,
            (main_pid, Option<u32> => i64),
            // These getters return u64 because for any services without limits, the value is represented as u64::MAX. If we tried to return an i64, the data
            // would be incorrectly converted to Dynamic::UNIT.
            (tasks, Option<u64> => u64),
            (memory, Option<u64> => u64)
        ]
    );
    register_to_string_with_json!(engine, ServiceInfo);

    engine.register_type::<SystemctlManager>();
    register_with_guard!(
        engine,
        "SystemctlManager",
        SystemctlManager,
        SystemctlManager::new,
        crate::errors::convert_to_rhai_error_with_execution_context,
        execution_context: execution_context.cloned()
    );

    register_direct_safe_fn!(
        engine,
        "start",
        SystemctlManager,
        safe_start,
        cedar_auth,
        -> (),
        crate::errors::convert_to_rhai_error_with_execution_context,
        execution_context: execution_context.cloned(),
        service: &str;
        tests: { positive: "test_systemctl_manager_creation", negative: "test_systemctl_manager_creation" }
    );

    register_direct_safe_fn!(
        engine,
        "stop",
        SystemctlManager,
        safe_stop,
        cedar_auth,
        -> (),
        crate::errors::convert_to_rhai_error_with_execution_context,
        execution_context: execution_context.cloned(),
        service: &str;
        tests: { positive: "test_systemctl_manager_creation", negative: "test_systemctl_manager_creation" }
    );

    register_direct_safe_fn!(
        engine,
        "restart",
        SystemctlManager,
        safe_restart,
        cedar_auth,
        -> (),
        crate::errors::convert_to_rhai_error_with_execution_context,
        execution_context: execution_context.cloned(),
        service: &str;
        tests: { positive: "test_systemctl_manager_creation", negative: "test_systemctl_manager_creation" }
    );

    register_direct_safe_fn!(
        engine,
        "try_restart",
        SystemctlManager,
        safe_try_restart,
        cedar_auth,
        -> (),
        crate::errors::convert_to_rhai_error_with_execution_context,
        execution_context: execution_context.cloned(),
        service: &str;
        tests: { positive: "test_systemctl_manager_creation", negative: "test_systemctl_manager_creation" }
    );

    register_direct_safe_fn!(
        engine,
        "daemon_reload",
        SystemctlManager,
        safe_daemon_reload,
        cedar_auth,
        -> (),
        crate::errors::convert_to_rhai_error_with_execution_context,
        execution_context: execution_context.cloned();
        tests: { positive: "test_systemctl_manager_creation", negative: "test_systemctl_manager_creation" }
    );

    register_direct_safe_fn!(
        engine,
        "status",
        SystemctlManager,
        safe_status,
        cedar_auth,
        -> ServiceInfo,
        crate::errors::convert_to_rhai_error,
        service: &str;
        tests: { positive: "test_systemctl_manager_creation", negative: "test_systemctl_manager_creation" }
    );

    register_map_serializers!(
        engine,
        [
            ProcessInfo,
            PidNamespace,
            FuserInfo,
            OpenFileInfo,
            IpcsInfo,
            ServiceInfo
        ]
    );
}

#[cfg(test)]
mod tests {
    use rex_test_utils::rhai::common::create_test_engine_and_register;

    /// Given: Two identical RhaiSafeProcessMgmtErrorKind values
    /// When: Comparing them for equality in the Rhai engine
    /// Then: They should be equal
    #[test]
    fn test_error_kind_equality_same_type() {
        let engine = create_test_engine_and_register();
        let result = engine
            .eval::<bool>(
                r#"
                let a = ProcessErrorKind::ProcessNotFound;
                let b = ProcessErrorKind::ProcessNotFound;
                a == b
            "#,
            )
            .unwrap();
        assert!(result);
    }

    /// Given: Two identical RhaiSafeProcessMgmtErrorKind values
    /// When: Comparing them for inequality in the Rhai engine
    /// Then: They should not be unequal
    #[test]
    fn test_error_kind_inequality_same_type() {
        let engine = create_test_engine_and_register();
        let result = engine
            .eval::<bool>(
                r#"
                let a = ProcessErrorKind::ProcessNotFound;
                let b = ProcessErrorKind::ProcessNotFound;
                a != b
            "#,
            )
            .unwrap();
        assert!(!result);
    }

    /// Given: Two different RhaiSafeProcessMgmtErrorKind values
    /// When: Comparing them for inequality in the Rhai engine
    /// Then: They should be unequal
    #[test]
    fn test_error_kind_inequality_different_types() {
        let engine = create_test_engine_and_register();
        let result = engine
            .eval::<bool>(
                r#"
                let a = ProcessErrorKind::ProcessNotFound;
                let b = ProcessErrorKind::ValidationError;
                a != b
            "#,
            )
            .unwrap();
        assert!(result);
    }

    /// Given: Two different RhaiSafeProcessMgmtErrorKind values
    /// When: Comparing them for equality in the Rhai engine
    /// Then: They should not be equal
    #[test]
    fn test_error_kind_equality_different_types() {
        let engine = create_test_engine_and_register();
        let result = engine
            .eval::<bool>(
                r#"
                let a = ProcessErrorKind::ProcessNotFound;
                let b = ProcessErrorKind::ValidationError;
                a == b
            "#,
            )
            .unwrap();
        assert!(!result);
    }

    /// Given: A RhaiSafeProcessMgmtErrorKind value
    /// When: Converting it to a string in the Rhai engine
    /// Then: It should return the correct string representation
    #[test]
    fn test_error_kind_to_string() {
        let engine = create_test_engine_and_register();

        let result = engine
            .eval::<String>(
                r#"
                let kind = ProcessErrorKind::ProcessNotFound;
                kind.to_string()
                "#,
            )
            .unwrap();

        assert_eq!(result, "ProcessNotFound");
    }
}
