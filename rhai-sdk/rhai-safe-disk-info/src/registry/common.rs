use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_logger::push_rhai_context_with_guard;
#[cfg(target_os = "linux")]
use rex_runner_registrar_utils::register_fn_with_auth;
use rex_runner_registrar_utils::{
    register_derive_builder_options, register_direct_safe_fn, register_getter_with_guard,
    register_getters_with_guard, register_map_serializers, register_safe_fn, register_with_guard,
};
use rhai::serde::to_dynamic;
use rhai::{Array, EvalAltResult};

use rust_safe_disk_info::{CpuStats, DeviceStats, Filesystem, IoStatSnapshot, Unit};
use std::rc::Rc;

use crate::errors::{ERROR_MODULE_NAME, RhaiDiskinfoErrorKind};
use rhai::Dynamic;
use rhai::plugin::{
    Engine, FnNamespace, FuncRegistration, Module, NativeCallContext, PluginFunc, RhaiResult,
    TypeId, export_module, exported_module, mem,
};

#[allow(non_upper_case_globals)]
#[allow(unreachable_pub)]
#[allow(clippy::unwrap_used)]
#[export_module]
mod error_kind_module {
    use super::Module;

    pub const AuthorizationError: RhaiDiskinfoErrorKind = RhaiDiskinfoErrorKind::AuthorizationError;
    pub const InvalidPath: RhaiDiskinfoErrorKind = RhaiDiskinfoErrorKind::InvalidPath;
    pub const SystemError: RhaiDiskinfoErrorKind = RhaiDiskinfoErrorKind::SystemError;
    pub const PermissionDenied: RhaiDiskinfoErrorKind = RhaiDiskinfoErrorKind::PermissionDenied;
    pub const TryFromIntError: RhaiDiskinfoErrorKind = RhaiDiskinfoErrorKind::TryFromIntError;
    pub const IoError: RhaiDiskinfoErrorKind = RhaiDiskinfoErrorKind::IoError;
    pub const Other: RhaiDiskinfoErrorKind = RhaiDiskinfoErrorKind::Other;
    pub const NixError: RhaiDiskinfoErrorKind = RhaiDiskinfoErrorKind::NixError;

    #[rhai_fn(global, name = "==", pure)]
    pub fn eq(error_kind: &mut RhaiDiskinfoErrorKind, other: RhaiDiskinfoErrorKind) -> bool {
        error_kind == &other
    }

    #[rhai_fn(global, name = "!=", pure)]
    pub fn neq(error_kind: &mut RhaiDiskinfoErrorKind, other: RhaiDiskinfoErrorKind) -> bool {
        error_kind != &other
    }

    #[rhai_fn(global, name = "to_string")]
    pub fn to_string(kind: &mut RhaiDiskinfoErrorKind) -> String {
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

/// Registers platform-specific functions with the Rhai engine.
/// These functions are only available on specific platforms.
#[allow(clippy::cast_possible_wrap)]
#[allow(clippy::cast_sign_loss)]
#[allow(clippy::too_many_lines)]
fn register_platform_specific_functions(engine: &mut Engine, cedar_auth: &Rc<CedarAuth>) {
    use rust_safe_disk_info::{FilesystemOptions, FilesystemOptionsBuilder, Filesystems};
    #[cfg(target_os = "linux")]
    use rust_safe_disk_info::{UnmountOptions, UnmountOptionsBuilder, unmount};

    register_derive_builder_options!(
        engine,
        FilesystemOptionsBuilder,
        "FilesystemOptions",
        FilesystemOptions,
        setters: [(targets, Array, transform: |targets: Array| -> Vec<String> {
            targets.into_iter()
                    .map(|v| v.clone().into_string().unwrap_or_else(|_| v.to_string()))
                    .collect()
        }), (local, bool)]
    );

    register_with_guard!(
        engine,
        "Filesystems",
        Filesystems,
        Filesystems::new,
        fs_opts: FilesystemOptions);
    register_with_guard!(engine, "format_bytes", u64, Filesystem::format_bytes, size: u64, unit: Unit);

    register_direct_safe_fn!(
        engine,
        "filesystems",
        Filesystems,
        filesystems,
        cedar_auth,
        -> Array,
        transform: |strings: Vec<Filesystem>| -> Result<Array, Box<EvalAltResult>> {
            Ok(strings.into_iter().map(Dynamic::from).collect())
        },
        crate::errors::convert_to_rhai_error;
        tests: { positive: "test_get_filesystems_success", negative: "test_filesystems_permission_denied_proc_mounts" }
    );

    engine.register_type::<Unit>();
    engine.register_static_module("Unit", {
        let mut module = Module::new();
        module.set_var("BYTES", Unit::Bytes);
        module.set_var("KILOBYTES", Unit::Kilobytes);
        module.set_var("MEGABYTES", Unit::Megabytes);
        module.into()
    });

    engine
        .register_type_with_name::<RhaiDiskinfoErrorKind>("RhaiDiskinfoErrorKind")
        .register_static_module(
            ERROR_MODULE_NAME,
            exported_module!(error_kind_module).into(),
        );

    engine.register_type::<Filesystem>();
    register_getter_with_guard!(engine, "size", Filesystem, raw_size);
    register_getters_with_guard!(
        engine,
        Filesystem,
        [
            block_used,
            block_available,
            inodes,
            kb_blocks,
            mb_blocks,
            iused,
            ifree,
            block_use_percent,
            iuse_percent,
            fs_device,
            fs_kind,
            mounted_on
        ]
    );
    register_getter_with_guard!(
        engine,
        Filesystem,
        mount_options,
        transform: |options: Vec<String>| -> Result<Array, Box<EvalAltResult>> {
            Ok(options.into_iter().map(Dynamic::from).collect())
        }
    );

    #[cfg(target_os = "linux")]
    register_derive_builder_options!(
        engine,
        UnmountOptionsBuilder,
        "UnmountOptions",
        UnmountOptions,
        setters: [(path, String)]
    );

    #[cfg(target_os = "linux")]
    register_fn_with_auth!(
        engine,
        "unmount",
        unmount,
        cedar_auth,
        options: UnmountOptions,
        -> (),
        crate::errors::convert_to_rhai_error;
        // No success test for unmount as they requires CAP_SYS_ADMIN and unit test env does not have that cap
        tests: { positive: "test_unauthorized_unmount", negative: "test_unauthorized_unmount" }
    );

    register_direct_safe_fn!(
        engine,
        "iostat",
        Filesystems,
        iostat,
        cedar_auth,
        -> IoStatSnapshot,
        crate::errors::convert_to_rhai_error;
        tests: { positive: "test_get_iostat_success", negative: "test_iostat_permission_denied" }
    );

    engine.register_type::<IoStatSnapshot>();
    register_getter_with_guard!(engine, "cpu_stats", IoStatSnapshot, cpu_stats);
    register_getter_with_guard!(engine, IoStatSnapshot, device_stats,
        transform: |entries: Vec<DeviceStats>| -> Result<Array, Box<EvalAltResult>> {
            Ok(entries.into_iter().map(Dynamic::from).collect())
        }
    );
    register_safe_fn!(engine, "to_string", IoStatSnapshot::to_string, self);

    engine.register_type::<CpuStats>();
    register_getters_with_guard!(
        engine,
        CpuStats,
        [
            user_percent,
            nice_percent,
            system_percent,
            iowait_percent,
            steal_percent,
            idle_percent
        ]
    );

    engine.register_type::<DeviceStats>();
    register_getters_with_guard!(
        engine,
        DeviceStats,
        [
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
            util_percent
        ]
    );

    register_serializer_fns(engine);
}

fn register_serializer_fns(engine: &mut Engine) {
    register_map_serializers!(engine, [IoStatSnapshot, DeviceStats, CpuStats, Filesystem,]);
}

/// Registers sysinfo functions with the Rhai engine for use in scripts.
pub(super) fn register(engine: &mut Engine, cedar_auth: &Rc<CedarAuth>) {
    register_platform_specific_functions(engine, cedar_auth);
}

#[cfg(test)]
mod tests {
    use rex_test_utils::rhai::common::create_test_engine_and_register;

    /// Given: Two identical RhaiDiskinfoErrorKind values
    /// When: Comparing them for equality in the Rhai engine
    /// Then: They should be equal
    #[test]
    fn test_error_kind_equality_same_type() {
        let engine = create_test_engine_and_register();
        let result = engine
            .eval::<bool>(
                r#"
	                 let a = DiskinfoErrorKind::InvalidPath;
	                 let b = DiskinfoErrorKind::InvalidPath;
	                 a == b
	             "#,
            )
            .unwrap();
        assert!(result);
    }

    /// Given: Two identical RhaiDiskinfoErrorKind values
    /// When: Comparing them for inequality in the Rhai engine
    /// Then: They should not be unequal
    #[test]
    fn test_error_kind_inequality_same_type() {
        let engine = create_test_engine_and_register();
        let result = engine
            .eval::<bool>(
                r#"
	                 let a = DiskinfoErrorKind::InvalidPath;
	                 let b = DiskinfoErrorKind::InvalidPath;
	                 a != b
	             "#,
            )
            .unwrap();
        assert!(!result);
    }

    /// Given: Two different RhaiDiskinfoErrorKind values
    /// When: Comparing them for inequality in the Rhai engine
    /// Then: They should be unequal
    #[test]
    fn test_error_kind_inequality_different_types() {
        let engine = create_test_engine_and_register();
        let result = engine
            .eval::<bool>(
                r#"
	                 let a = DiskinfoErrorKind::InvalidPath;
	                 let b = DiskinfoErrorKind::SystemError;
	                 a != b
	             "#,
            )
            .unwrap();
        assert!(result);
    }

    /// Given: Two different RhaiDiskinfoErrorKind values
    /// When: Comparing them for equality in the Rhai engine
    /// Then: They should not be equal
    #[test]
    fn test_error_kind_equality_different_types() {
        let engine = create_test_engine_and_register();
        let result = engine
            .eval::<bool>(
                r#"
	                 let a = DiskinfoErrorKind::InvalidPath;
	                 let b = DiskinfoErrorKind::SystemError;
	                 a == b
	             "#,
            )
            .unwrap();
        assert!(!result);
    }

    /// Given: A RhaiDiskinfoErrorKind value
    /// When: Converting it to a string in the Rhai engine
    /// Then: It should return the correct string representation
    #[test]
    fn test_error_kind_to_string() {
        let engine = create_test_engine_and_register();

        let result = engine
            .eval::<String>(
                r#"
	                 let kind = DiskinfoErrorKind::InvalidPath;
	                 kind.to_string()
	                 "#,
            )
            .unwrap();

        assert_eq!(result, "InvalidPath");
    }
}
