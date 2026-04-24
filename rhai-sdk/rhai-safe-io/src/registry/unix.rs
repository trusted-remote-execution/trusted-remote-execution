//! Unix-specific registry implementations

use super::common::get_rhai_context_guard;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_runner_registrar_utils::{
    register_derive_builder_options, register_direct_safe_fn, register_getter_with_guard,
    register_getters_with_guard, register_map_serializers, register_option_as_dynamic,
    register_safe_fn, register_with_no_ctx,
};
use rhai::serde::to_dynamic;
use rhai::{Array, Dynamic, EvalAltResult, NativeCallContext};
use rust_safe_io::{
    DirEntry, DiskUsageEntry, DiskUsageResult, Metadata, Ownership, RcDirHandle, RcFileHandle,
    WordCount,
    options::{
        ChmodDirOptions, ChmodDirOptionsBuilder, CreateSymlinkOptions, CreateSymlinkOptionsBuilder,
        DiskUsageOptions, DiskUsageOptionsBuilder, ExtractArchiveOptions,
        ExtractArchiveOptionsBuilder, SetOwnershipOptions, SetOwnershipOptionsBuilder,
    },
};

use rhai::plugin::Engine;
use std::rc::Rc;

pub(super) fn register_unix_builders(engine: &mut Engine) {
    register_derive_builder_options!(
        engine,
        ChmodDirOptionsBuilder,
        "ChmodDirOptions",
        ChmodDirOptions,
        setters: [
            (permissions, i64),
            (recursive, bool)
        ]
    );

    register_derive_builder_options!(
        engine,
        SetOwnershipOptionsBuilder,
        "SetOwnershipOptions",
        SetOwnershipOptions,
        setters: [
            (user, String),
            (group, String),
            (recursive, bool)
        ]
    );
    register_derive_builder_options!(
        engine,
        ExtractArchiveOptionsBuilder,
        "ExtractArchiveOptions",
        ExtractArchiveOptions,
        setters: [
            (preserve_permissions, bool),
            (preserve_ownership, bool),
            (preserve_timestamps, bool)
        ]
    );
    register_derive_builder_options!(
        engine,
        DiskUsageOptionsBuilder,
        "DiskUsageOptions",
        DiskUsageOptions,
        setters: [
            (summarize, bool),
            (all_files, bool),
            (one_file_system, bool),
            (count_hard_links, bool),
            (apparent_size, bool),
            (max_depth, i64),
            (track_largest_subdir, bool)
        ]
    );

    register_derive_builder_options!(
        engine,
        CreateSymlinkOptionsBuilder,
        "CreateSymlinkOptions",
        CreateSymlinkOptions,
        setters: [
            (force, bool)
        ]
    );
}

#[allow(clippy::too_many_lines)]
pub(super) fn register_unix_functions(engine: &mut Engine, cedar_auth: &Rc<CedarAuth>) {
    register_unix_getters(engine);

    register_direct_safe_fn!(
        engine,
        "get_ownership",
        RcDirHandle,
        safe_get_ownership,
        cedar_auth,
        -> Ownership,
        crate::errors::convert_to_rhai_error;
        tests: { positive: "test_get_ownership_success", negative: "test_get_ownership_error" }
    );
    register_direct_safe_fn!(
        engine,
        "get_ownership",
        RcFileHandle,
        safe_get_ownership,
        cedar_auth,
        -> Ownership,
        crate::errors::convert_to_rhai_error;
        tests: { positive: "test_get_file_ownership_success", negative: "test_get_file_ownership_error" }
    );
    register_direct_safe_fn!(
        engine,
        "write_in_place",
        RcFileHandle,
        safe_write_in_place,
        cedar_auth,
        -> (),
        crate::errors::convert_to_rhai_error,
        content: &str;
        tests: { positive: "test_safe_write_file_happy_case", negative: "test_safe_write_file_force_err" }
    );
    register_direct_safe_fn!(
        engine,
        "chmod",
        RcFileHandle,
        safe_chmod,
        cedar_auth,
        -> (),
        crate::errors::convert_to_rhai_error,
        permissions: i64;
        tests: { positive: "test_safe_chmod_file_permissions", negative: "test_safe_chmod_file_error" }
    );
    register_direct_safe_fn!(
        engine,
        "chmod",
        RcDirHandle,
        safe_chmod,
        cedar_auth,
        -> (),
        crate::errors::convert_to_rhai_error,
        chmod_dir_options: ChmodDirOptions;
        tests: { positive: "test_safe_chmod_dir_permissions", negative: "test_safe_chmod_dir_error" }
    );
    register_direct_safe_fn!(
        engine,
        "get_last_modified_time",
        RcFileHandle,
        safe_get_last_modified_time,
        cedar_auth,
        -> i64,
        crate::errors::convert_to_rhai_error;
        tests: { positive: "test_last_modified_time", negative: "test_safe_chmod_dir_error" }
    );
    register_direct_safe_fn!(
        engine,
        "create_symlink",
        RcDirHandle,
        safe_create_symlink,
        cedar_auth,
        -> (),
        crate::errors::convert_to_rhai_error,
        target_path: &str,
        link_name: &str,
        create_symlink_options: CreateSymlinkOptions;
        tests: { positive: "test_rhai_create_symlink_force_behavior", negative: "test_rhai_unauthorized_create_symlink_delete_permission" }
    );
    register_direct_safe_fn!(
        engine,
        "counts",
        RcFileHandle,
        counts,
        cedar_auth,
        -> WordCount,
        crate::errors::convert_to_rhai_error;
        tests: { positive: "test_counts_success", negative: "test_counts_no_read_permission" }
    );

    register_with_no_ctx!(
        engine,
        "file_size",
        i64,
        Metadata,
        Metadata::file_size,
        result,
        crate::errors::convert_to_rhai_error
    );

    register_safe_fn!(engine, "last_modified_time", Metadata::mtime, self);
    register_safe_fn!(
        engine,
        "last_modified_time_nanos_component",
        Metadata::mtime_nsec,
        self
    );
    register_with_no_ctx!(
        engine,
        "num_hardlinks",
        i64,
        Metadata,
        Metadata::num_hardlinks,
        result,
        crate::errors::convert_to_rhai_error
    );
    register_with_no_ctx!(
        engine,
        "blocks",
        i64,
        Metadata,
        Metadata::blocks,
        result,
        crate::errors::convert_to_rhai_error
    );
    register_with_no_ctx!(
        engine,
        "allocated_size",
        i64,
        Metadata,
        Metadata::allocated_size,
        result,
        crate::errors::convert_to_rhai_error
    );
    register_safe_fn!(engine, "permissions", Metadata::permissions, self);
    register_option_as_dynamic!(engine, "symlink_target", Metadata, symlink_target);

    register_direct_safe_fn!(
        engine,
        "disk_usage",
        RcDirHandle,
        safe_disk_usage,
        cedar_auth,
        -> DiskUsageResult,
        crate::errors::convert_to_rhai_error,
        options: DiskUsageOptions;
        tests: { positive: "test_disk_usage_success", negative: "test_disk_usage_unauthorized" }
    );
    register_direct_safe_fn!(
        engine,
        "disk_usage",
        RcFileHandle,
        safe_disk_usage,
        cedar_auth,
        -> DiskUsageEntry,
        crate::errors::convert_to_rhai_error,
        options: DiskUsageOptions;
        tests: { positive: "test_file_disk_usage_success", negative: "test_file_disk_usage_unauthorized" }
    );
}

pub(super) fn register_unix_types(engine: &mut Engine) {
    engine.register_type::<Ownership>();
    engine.register_type::<DiskUsageEntry>();
    engine.register_type::<DiskUsageResult>();
}

fn register_unix_serializer_fns(engine: &mut Engine) {
    register_map_serializers!(engine, [DiskUsageEntry]);
}

pub(super) fn register_unix_getters(engine: &mut Engine) {
    register_unix_serializer_fns(engine);
    register_getters_with_guard!(engine, Ownership, [user, group]);

    // Safe: i64::MAX (~9.2 EB) vastly exceeds any real disk size.
    // Safe: i64::MAX (~9.2e18) vastly exceeds max Linux inode count (~4 billion on ext4).
    register_getters_with_guard!(engine, DiskUsageEntry, [
        path,
        (size_bytes, u64 => i64),
        (inode_count, u64 => i64),
    ]);
    register_getter_with_guard!(engine, DirEntry, inode);
    register_getter_with_guard!(engine, "owner", Metadata, ownership);
    register_getter_with_guard!(engine, DiskUsageResult, largest_subdir_handle,
        transform: |handle: Option<RcDirHandle>| -> Result<Dynamic, Box<EvalAltResult>> {
            Ok(handle.map_or_else(|| Dynamic::from(()), Dynamic::from))
        }
    );
    register_getter_with_guard!(engine, DiskUsageResult, entries,
        transform: |entries: Vec<DiskUsageEntry>| -> Result<Array, Box<EvalAltResult>> {
            Ok(entries.into_iter().map(Dynamic::from).collect())
        }
    );
}
