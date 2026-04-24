//! Linux-specific registry implementations

use super::common::get_rhai_context_guard;
use crate::utils::{parse_execute_args, parse_execute_capabilities, parse_execute_env};
use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_runner_registrar_utils::{
    execution_context::ExecutionContext, register_derive_builder_options,
    register_derive_builder_setter, register_direct_safe_fn, register_getter_with_guard,
    register_getters_with_guard, register_map_serializers,
};
use rhai::serde::to_dynamic;
use rhai::{Array, Dynamic, EvalAltResult, Map, NativeCallContext};
use rust_safe_io::{
    DiskAllocationOptions, DiskAllocationOptionsBuilder, ElfInfo, RcDirHandle, RcFileHandle,
    RcSymlinkHandle, SetXAttrOptions, SetXAttrOptionsBuilder,
    execute::{
        ChildNamespaceOptions, ChildNamespaceOptionsBuilder, ExecuteOptions, ExecuteOptionsBuilder,
        ExecuteResult,
    },
    options::{ExtractArchiveOptions, MoveOptions, SetOwnershipOptions, SizeUnit},
    truncate::{TruncateOptions, TruncateOptionsBuilder},
};

use rhai::plugin::Engine;
use std::rc::Rc;

pub(super) fn register_linux_builders(engine: &mut Engine) {
    register_derive_builder_options!(
        engine,
        TruncateOptionsBuilder,
        "TruncateOptions",
        TruncateOptions,
        setters: [
            (size, i64),
            (format, SizeUnit)
        ]
    );

    register_derive_builder_options!(
        engine,
        DiskAllocationOptionsBuilder,
        "FallocateOptions",
        DiskAllocationOptions,
        setters: [
            (length, i64),
            (format, SizeUnit)
        ]
    );

    register_derive_builder_options!(
        engine,
        ChildNamespaceOptionsBuilder,
        "ChildNamespaceOptions",
        ChildNamespaceOptions,
        setters: [
            (target_process, i64 => u32)
        ]
    );

    register_derive_builder_options!(
        engine,
        ExecuteOptionsBuilder,
        "ExecuteOptions",
        ExecuteOptions,
        setters: [
            (user, String),
            (group, String),
            (namespace, ChildNamespaceOptions)
        ]
    );

    register_derive_builder_setter!(
        engine,
        args,
        ExecuteOptionsBuilder,
        Array,
        transform: parse_execute_args
    );

    register_derive_builder_setter!(
        engine,
        env,
        ExecuteOptionsBuilder,
        Map,
        transform: parse_execute_env
    );

    register_derive_builder_setter!(
        engine,
        capabilities,
        ExecuteOptionsBuilder,
        Array,
        transform: parse_execute_capabilities
    );

    register_derive_builder_options!(
        engine,
        SetXAttrOptionsBuilder,
        "SetXAttrOptions",
        SetXAttrOptions,
        setters: [
            (name, String),
            (selinux_type, String),
            (selinux_user, String),
            (selinux_role, String),
            (selinux_level, String)
        ]
    );
}

#[allow(clippy::too_many_lines)]
pub(super) fn register_linux_functions(
    engine: &mut Engine,
    cedar_auth: &Rc<CedarAuth>,
    execution_context: Option<&ExecutionContext>,
) {
    use crate::register_core_dump_analysis_functions;

    register_linux_getters(engine);

    register_direct_safe_fn!(
        engine,
        "truncate",
        RcFileHandle,
        safe_truncate,
        cedar_auth,
        -> (),
        crate::errors::convert_to_rhai_error,
        options: TruncateOptions;
        tests: { positive: "test_truncate_succeeds", negative: "test_truncate_fails" }
    );
    register_direct_safe_fn!(
        engine,
        "fallocate",
        RcFileHandle,
        safe_initialize_bytes_on_disk,
        cedar_auth,
        -> (),
        crate::errors::convert_to_rhai_error,
        options: DiskAllocationOptions;
        tests: { positive: "test_fallocate_success", negative: "test_fallocate_fail" }
    );
    register_direct_safe_fn!(
        engine,
        "move",
        RcDirHandle,
        safe_move,
        cedar_auth,
        -> RcDirHandle,
        crate::errors::convert_to_rhai_error,
        src_dir: RcDirHandle,
        dest_parent_dir: RcDirHandle,
        dest_dirname: &str,
        move_options: MoveOptions;
        tests: { positive: "test_rhai_move_dir_success", negative: "test_rhai_move_dir_unauthorized" }
    );

    register_direct_safe_fn!(
        engine,
        "execute",
        RcFileHandle,
        safe_execute,
        cedar_auth,
        -> ExecuteResult,
        crate::errors::convert_to_rhai_error_with_execution_context,
        execution_context: execution_context.cloned(),
        options: ExecuteOptions;
        tests: { positive: "test_rhai_execute_success", negative: "test_rhai_execute_error" }
    );

    register_direct_safe_fn!(
        engine,
        "elf_info",
        RcFileHandle,
        elf_info,
        cedar_auth,
        -> ElfInfo,
        crate::errors::convert_to_rhai_error;
        tests: { positive: "test_elf_info_succeeds", negative: "test_elf_info_fails" }
    );
    register_core_dump_analysis_functions(engine, cedar_auth);

    register_direct_safe_fn!(
        engine,
        "set_ownership",
        RcDirHandle,
        set_ownership,
        cedar_auth,
        -> (),
        crate::errors::convert_to_rhai_error,
        set_ownership_options: SetOwnershipOptions;
        tests: { positive: "test_set_dir_ownership_success", negative: "test_set_dir_ownership_error" }
    );
    register_direct_safe_fn!(
        engine,
        "set_ownership",
        RcFileHandle,
        set_ownership,
        cedar_auth,
        -> (),
        crate::errors::convert_to_rhai_error,
        set_ownership_options: SetOwnershipOptions;
        tests: { positive: "test_set_file_ownership_success", negative: "test_set_file_ownership_error" }
    );
    register_direct_safe_fn!(
        engine,
        "extract_archive",
        RcFileHandle,
        safe_extract_archive,
        cedar_auth,
        -> (),
        crate::errors::convert_to_rhai_error,
        dest_dir: RcDirHandle,
        extract_options: ExtractArchiveOptions;
        tests: { positive: "test_extract_archive_preserve_timestamps", negative: "test_extract_archive_unauthorized_directory_operations" }
    );
    register_direct_safe_fn!(
        engine,
        "open_symlink",
        RcDirHandle,
        safe_open_symlink,
        cedar_auth,
        -> RcSymlinkHandle,
        crate::errors::convert_to_rhai_error,
        symlink_name: &str;
        tests: { positive: "test_open_symlink_success", negative: "test_unauthorized_open_symlink" }
    );
    register_direct_safe_fn!(
        engine,
        "set_ownership",
        RcSymlinkHandle,
        set_ownership,
        cedar_auth,
        -> (),
        crate::errors::convert_to_rhai_error,
        set_ownership_options: SetOwnershipOptions;
        tests: { positive: "test_set_symlink_ownership_success", negative: "test_set_symlink_ownership_error" }
    );

    register_direct_safe_fn!(
        engine,
        "set_extended_attr",
        RcFileHandle,
        safe_set_xattr,
        cedar_auth,
        -> (),
        crate::errors::convert_to_rhai_error,
        options: SetXAttrOptions;
        tests: { positive: "test_set_extended_attr_success", negative: "test_set_extended_attr_error" }
    );

    register_direct_safe_fn!(
        engine,
        "metadata",
        RcSymlinkHandle,
        metadata,
        cedar_auth,
        -> rust_safe_io::Metadata,
        crate::errors::convert_to_rhai_error;
        tests: { positive: "test_symlink_metadata_success", negative: "test_symlink_metadata_unauthorized" }
    );
}

pub(super) fn register_linux_types(engine: &mut Engine) {
    engine.register_type::<ExecuteResult>();
    engine.register_type::<ElfInfo>();
    engine.register_type::<RcSymlinkHandle>();
}

fn register_linux_serializer_fns(engine: &mut Engine) {
    register_map_serializers!(engine, [ExecuteResult, ElfInfo]);
}

pub(super) fn register_linux_getters(engine: &mut Engine) {
    register_linux_serializer_fns(engine);
    register_getters_with_guard!(engine, ExecuteResult, [stdout, stderr]);
    register_getter_with_guard!(
        engine,
        "exit_code",
        ExecuteResult,
        exit_code,
        transform: |code: i32| -> i64 { i64::from(code) }
    );
    register_getters_with_guard!(engine, ElfInfo, [(execfn, Option<String> => String), (platform, Option<String> => String), (interpreter, Option<String> => String), is_64bit]);
}
