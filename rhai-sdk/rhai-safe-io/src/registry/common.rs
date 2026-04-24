//! Platform-agnostic registry implementations

use crate::{dir_entry::dir_entry_type_mod, errors::error_kind_module};
use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_runner_registrar_utils::{
    register_derive_builder_options, register_direct_safe_fn, register_direct_safe_no_cedar_fn,
    register_getter_with_guard, register_getters_with_guard, register_map_serializers,
    register_safe_fn, register_with_guard,
};
use rhai::serde::to_dynamic;
use rhai::{AST, Array, Dynamic, EvalAltResult, FnPtr, Map};
use rust_safe_io::{
    DirConfig, DirConfigBuilder, DirEntry, Match, Metadata, RcDirHandle, RcFileHandle, WalkEntry,
    WordCount,
    dir_entry::EntryType,
    errors::RustSafeIoError,
    gzip::GzipInfo,
    options::{
        CompressGzipOptions, CompressGzipOptionsBuilder, CopyFileOptions, CopyFileOptionsBuilder,
        DeleteDirOptions, DeleteDirOptionsBuilder, DeleteFileOptions, DeleteFileOptionsBuilder,
        FindOptions, FindOptionsBuilder, MoveOptions, MoveOptionsBuilder, OpenDirOptions,
        OpenDirOptionsBuilder, OpenFileOptions, OpenFileOptionsBuilder, ReadLinesOptions,
        ReadLinesOptionsBuilder, ReadPageOptions, ReadPageOptionsBuilder, ReplacementOptions,
        ReplacementOptionsBuilder, SearchGzipOptions, SearchGzipOptionsBuilder, SizeRange,
        SizeUnit, WriteOptions, WriteOptionsBuilder,
    },
    replace_text,
};
use rust_sdk_common_utils::types::datetime::DateTime;

use crate::errors::{ERROR_MODULE_NAME, RhaiSafeIoErrorKind};
use rex_logger::push_rhai_context_with_guard;

use rhai::plugin::{
    Engine, FuncRegistration, Module, NativeCallContext, PluginFunc, RhaiResult, TypeId,
    export_module, exported_module, mem,
};
use std::rc::Rc;

/// Converts a Rhai Array to `Vec<RcFileHandle>` for certificate chain verification
fn array_to_file_handles(arr: Array) -> Result<Vec<RcFileHandle>, Box<EvalAltResult>> {
    arr.into_iter()
        .map(Dynamic::try_cast::<RcFileHandle>)
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| {
            Box::new(EvalAltResult::ErrorMismatchDataType(
                "Array<RcFileHandle>".to_string(),
                "Array with non-file-handle elements".to_string(),
                rhai::Position::NONE,
            ))
        })
}

#[export_module]
pub mod size_range_mod {
    use rust_safe_io::options::{SizeRange, SizeUnit};

    #[rhai_fn(name = "min_only")]
    pub(crate) const fn min_only(min: i64, unit: SizeUnit) -> SizeRange {
        SizeRange::min_only(min, unit)
    }

    #[rhai_fn(name = "max_only")]
    pub(crate) const fn max_only(max: i64, unit: SizeUnit) -> SizeRange {
        SizeRange::max_only(max, unit)
    }

    #[rhai_fn(name = "between")]
    pub(crate) const fn between(min: i64, max: i64, unit: SizeUnit) -> SizeRange {
        SizeRange::between(min, max, unit)
    }
}

pub(super) fn get_rhai_context_guard(context: &NativeCallContext) -> impl Drop {
    let line_number = context
        .call_position()
        .line()
        .map_or(0, |l| u32::try_from(l).unwrap_or(0));

    push_rhai_context_with_guard(Some(context.fn_name()), line_number)
}

#[allow(clippy::too_many_lines)]
pub(super) fn register_platform_agnostic_functions(
    engine: &mut Engine,
    cedar_auth: &Rc<CedarAuth>,
) {
    register_direct_safe_fn!(
        engine,
        "move",
        RcFileHandle,
        safe_move,
        cedar_auth,
        -> RcFileHandle,
        crate::errors::convert_to_rhai_error,
        dest_dir: RcDirHandle,
        dest_filename: &str,
        move_options: MoveOptions;
        tests: { positive: "test_rhai_move_file_success", negative: "test_rhai_move_file_unauthorized" }
    );

    register_direct_safe_fn!(
        engine,
        "open_file",
        RcDirHandle,
        safe_open_file,
        cedar_auth,
        -> RcFileHandle,
        crate::errors::convert_to_rhai_error,
        file_name: &str,
        open_file_options: OpenFileOptions;
        tests: { positive: "test_safe_write_file_happy_case", negative: "test_reading_file_that_dne" }
    );

    register_direct_safe_fn!(
        engine,
        "open",
        DirConfig,
        safe_open,
        cedar_auth,
        -> RcDirHandle,
        crate::errors::convert_to_rhai_error,
        open_dir_options: OpenDirOptions;
        tests: { positive: "test_reading_normal_file", negative: "test_reading_non_utf8" }
    );
    register_direct_safe_fn!(
        engine,
        "delete",
        RcDirHandle,
        safe_delete,
        cedar_auth,
        -> (),
        crate::errors::convert_to_rhai_error,
        delete_dir_options: DeleteDirOptions;
        tests: { positive: "test_delete_dir_with_files", negative: "test_delete_dir_permission_denied" }
    );
    register_direct_safe_fn!(
        engine,
        "read",
        RcFileHandle,
        safe_read,
        cedar_auth,
        -> String,
        crate::errors::convert_to_rhai_error;
        tests: { positive: "test_reading_normal_file", negative: "test_reading_non_utf8" }
    );
    register_direct_safe_fn!(
        engine,
        "read_lines",
        RcFileHandle,
        safe_read_lines,
        cedar_auth,
        -> Array,
        transform: |strings: Vec<String>| -> Result<Array, Box<EvalAltResult>> {
            Ok(strings.into_iter().map(Dynamic::from).collect())
        },
        crate::errors::convert_to_rhai_error,
        options: ReadLinesOptions;
        tests: { positive: "test_rhai_read_lines_count_success", negative: "test_rhai_read_lines_no_read_permission" }
    );
    register_direct_safe_fn!(
        engine,
        "read_page",
        RcFileHandle,
        safe_read_page,
        cedar_auth,
        -> Array,
        transform: |strings: Vec<String>| -> Result<Array, Box<EvalAltResult>> {
            Ok(strings.into_iter().map(Dynamic::from).collect())
        },
        crate::errors::convert_to_rhai_error,
        options: ReadPageOptions;
        tests: { positive: "test_rhai_read_page_success", negative: "test_rhai_read_page_no_read_permission" }
    );
    register_direct_safe_fn!(
        engine,
        "write",
        RcFileHandle,
        safe_write,
        cedar_auth,
        -> RcFileHandle,
        crate::errors::convert_to_rhai_error,
        content: &str;
        tests: { positive: "test_safe_write_file_happy_case", negative: "test_safe_write_file_force_err" }
    );
    register_direct_safe_fn!(
        engine,
        "write",
        RcFileHandle,
        safe_write_with_options,
        cedar_auth,
        -> RcFileHandle,
        crate::errors::convert_to_rhai_error,
        content: &str,
        write_options: WriteOptions;
        tests: { positive: "test_safe_write_file_with_options_happy_case", negative: "test_safe_write_file_with_options_err" }
    );
    register_direct_safe_fn!(
        engine,
        "copy",
        RcFileHandle,
        safe_copy,
        cedar_auth,
        -> RcFileHandle,
        crate::errors::convert_to_rhai_error,
        destination: RcFileHandle,
        copy_file_options: CopyFileOptions;
        tests: { positive: "test_copy_file_success", negative: "test_copy_file_error_destination_not_empty" }
    );
    register_with_guard!(engine, "replace_text", String, replace_text, crate::errors::convert_to_rhai_error,
        text: &str,
        old_string: &str,
        new_string: &str,
        replacement_options: ReplacementOptions);
    register_direct_safe_fn!(
        engine,
        "delete",
        RcFileHandle,
        safe_delete,
        cedar_auth,
        -> (),
        crate::errors::convert_to_rhai_error,
        delete_file_options: DeleteFileOptions;
        tests: { positive: "test_safe_delete_file_for_nonexistent_dir", negative: "test_delete_dir_with_files" }
    );
    register_direct_safe_fn!(
        engine,
        "search",
        RcFileHandle,
        safe_search,
        cedar_auth,
        -> Array,
        transform: |strings: Vec<Match>| -> Result<Array, Box<EvalAltResult>> {
            Ok(strings.into_iter().map(Dynamic::from).collect())
        },
        crate::errors::convert_to_rhai_error,
        pattern: &str;
        tests: { positive: "test_search_array_len", negative: "test_search_invalid_regex_pattern" }
    );
    register_direct_safe_fn!(
        engine,
        "read_link_target",
        RcDirHandle,
        safe_read_link_target,
        cedar_auth,
        -> String,
        crate::errors::convert_to_rhai_error,
        symlink_name: &str;
        tests: { positive: "test_read_link_target", negative: "test_read_link_target_not_a_symlink" }
    );
    register_direct_safe_fn!(
        engine,
        "list_entries",
        RcDirHandle,
        safe_list_dir,
        cedar_auth,
        -> Map,
        transform: |entries: Vec<DirEntry>| -> Result<Map, Box<EvalAltResult>> {
            Ok(entries
                .into_iter()
                .map(|element| (element.name().into(), Dynamic::from(element)))
                .collect())
        },
        crate::errors::convert_to_rhai_error;
        tests: { positive: "test_list_entries_success", negative: "test_list_entries_unauthorized" }
    );
    register_direct_safe_fn!(
        engine,
        "open_as_file",
        DirEntry,
        open_as_file,
        cedar_auth,
        -> RcFileHandle,
        crate::errors::convert_to_rhai_error,
        open_file_options: OpenFileOptions;
        tests: { positive: "test_reading_normal_file", negative: "test_reading_non_utf8" }
    );
    register_direct_safe_fn!(
        engine,
        "open_as_dir",
        DirEntry,
        open_as_dir,
        cedar_auth,
        -> RcDirHandle,
        crate::errors::convert_to_rhai_error,
        open_dir_options: OpenDirOptions;
        tests: { positive: "test_rhai_dir_entry_open_as_dir_authorized", negative: "test_rhai_dir_entry_open_as_dir_unauthorized" }
    );
    register_direct_safe_fn!(
        engine,
        "metadata",
        RcDirHandle,
        metadata,
        cedar_auth,
        -> Metadata,
        crate::errors::convert_to_rhai_error;
        tests: { positive: "test_dir_metadata_success", negative: "test_dir_metadata_unauthorized" }
    );
    register_direct_safe_fn!(
        engine,
        "metadata",
        RcFileHandle,
        metadata,
        cedar_auth,
        -> Metadata,
        crate::errors::convert_to_rhai_error;
        tests: { positive: "test_file_metadata_success", negative: "test_file_metadata_unauthorized" }
    );
    register_direct_safe_fn!(
        engine,
        "metadata",
        DirEntry,
        metadata,
        cedar_auth,
        -> Metadata,
        crate::errors::convert_to_rhai_error;
        tests: { positive: "test_rhai_dir_entry_metadata_blocks", negative: "test_rhai_dir_entry_metadata_unauthorized" }
    );

    engine.register_fn("find", {
        let cedar_auth = cedar_auth.clone();
        move |ctx: NativeCallContext,
              dir_handle: &mut RcDirHandle,
              options: FindOptions,
              callback: FnPtr|
              -> Result<(), Box<EvalAltResult>> {
            let _guard = get_rhai_context_guard(&ctx);

            match dir_handle.safe_find(
                &cedar_auth,
                options,
                |entry: &WalkEntry| -> Result<(), RustSafeIoError> {
                    // WalkEntry::Entry is where fd memoization occurs and will match every file AND directory within the directory
                    // tree during traversal. This chunk converts the Rust DirEntry to a DirEntry from which the user can
                    // access the memoized fd in the callback, enabling TOCTOU-safe file operations (open_as_file, etc.)
                    let rhai_entry = match entry {
                        WalkEntry::Entry(dir_entry) => dir_entry.clone(),
                        _ => {
                            return Ok(());
                        }
                    };

                    // Call the Rhai callback with the converted entry
                    match callback.call::<Dynamic>(ctx.engine(), &AST::empty(), (rhai_entry,)) {
                        Ok(_) => Ok(()),
                        Err(eval_err) => Err(RustSafeIoError::CallbackError {
                            reason: format!("Rhai callback execution failed: {eval_err}"),
                            source: Box::new(std::io::Error::other(eval_err.to_string())),
                        }),
                    }
                },
            ) {
                Ok(()) => Ok(()),
                Err(e) => crate::errors::convert_to_rhai_error(&e),
            }
        }
    });

    register_direct_safe_fn!(
        engine,
        "extract_strings",
        RcFileHandle,
        extract_strings,
        cedar_auth,
        -> Array,
        transform: |strings: Vec<String>| -> Result<Array, Box<EvalAltResult>> {
            Ok(strings.into_iter().map(Dynamic::from).collect())
        },
        crate::errors::convert_to_rhai_error;
        tests: { positive: "test_extract_strings_success", negative: "test_unauthorized_extract_strings" }
    );
    register_safe_fn!(engine, "to_string", EntryType::to_string, self);
    register_safe_fn!(engine, "type", DirEntry::entry_type, self);
    register_safe_fn!(engine, "type", Metadata::entry_type, self);

    register_direct_safe_fn!(
        engine,
        "compress_gzip",
        RcFileHandle,
        safe_compress_gzip,
        cedar_auth,
        -> (),
        crate::errors::convert_to_rhai_error,
        dest_file: RcFileHandle,
        options: CompressGzipOptions;
        tests: { positive: "test_safe_compress_gzip_success", negative: "test_unauthorized_safe_compress_gzip_read" }
    );
    register_direct_safe_fn!(
        engine,
        "read_gzip_lines",
        RcFileHandle,
        safe_read_gzip_lines,
        cedar_auth,
        -> Array,
        transform: |strings: Vec<String>| -> Result<Array, Box<EvalAltResult>> {
            Ok(strings.into_iter().map(Dynamic::from).collect())
        },
        crate::errors::convert_to_rhai_error,
        options: ReadLinesOptions;
        tests: { positive: "test_rhai_read_gzip_lines_success", negative: "test_rhai_read_gzip_lines_no_read_permission" }
    );
    register_direct_safe_fn!(
        engine,
        "gzip_info",
        RcFileHandle,
        safe_gzip_info,
        cedar_auth,
        -> GzipInfo,
        crate::errors::convert_to_rhai_error;
        tests: { positive: "test_rhai_gzip_info_success", negative: "test_rhai_gzip_info_no_read_permission" }
    );
    register_direct_safe_fn!(
        engine,
        "search_gzip",
        RcFileHandle,
        safe_search_gzip,
        cedar_auth,
        -> Array,
        transform: |matches: Vec<Match>| -> Result<Array, Box<EvalAltResult>> {
            Ok(matches.into_iter().map(Dynamic::from).collect())
        },
        crate::errors::convert_to_rhai_error,
        pattern: &str,
        options: SearchGzipOptions;
        tests: { positive: "test_rhai_search_gzip_success", negative: "test_rhai_search_gzip_invalid_pattern" }
    );
    register_direct_safe_fn!(
        engine,
        "search_gzip_exists",
        RcFileHandle,
        safe_search_gzip_exists,
        cedar_auth,
        -> bool,
        crate::errors::convert_to_rhai_error,
        pattern: &str,
        options: SearchGzipOptions;
        tests: { positive: "test_rhai_search_gzip_exists_found", negative: "test_rhai_search_gzip_exists_not_found" }
    );

    register_direct_safe_no_cedar_fn!(
        engine,
        "verify_cert",
        RcFileHandle,
        verify_cert,
        -> (),
        crate::errors::convert_to_rhai_error,
        root_ca_fh: RcFileHandle;
        tests: { positive: "test_rhai_verify_cert_valid", negative: "test_rhai_verify_cert_invalid" }
    );
    register_direct_safe_no_cedar_fn!(
        engine,
        "verify_cert_chain",
        RcFileHandle,
        verify_cert_chain,
        -> (),
        crate::errors::convert_to_rhai_error,
        root_ca_fh: RcFileHandle,
        intermediate_ca_fhs: Array |>? array_to_file_handles;
        tests: { positive: "test_rhai_verify_cert_chain_valid", negative: "test_rhai_verify_cert_chain_invalid" }
    );
}

#[allow(clippy::too_many_lines)]
pub(super) fn register_common_builders(engine: &mut Engine) {
    register_derive_builder_options!(
        engine,
        DeleteDirOptionsBuilder,
        "DeleteDirOptions",
        DeleteDirOptions,
        setters: [
            (force, bool),
            (recursive, bool)
        ]
    );

    register_derive_builder_options!(
        engine,
        DeleteFileOptionsBuilder,
        "DeleteFileOptions",
        DeleteFileOptions,
        setters: [
            (force, bool)
        ]
    );

    register_derive_builder_options!(
        engine,
        ReadLinesOptionsBuilder,
        "ReadLinesOptions",
        ReadLinesOptions,
        setters: [
            (count, i64 => isize),
            (start, i64 => usize)
        ]
    );

    register_derive_builder_options!(
        engine,
        ReadPageOptionsBuilder,
        "ReadPageOptions",
        ReadPageOptions,
        setters: [
            (num_lines, i64 => usize)
        ]
    );

    register_derive_builder_options!(
        engine,
        CopyFileOptionsBuilder,
        "CopyFileOptions",
        CopyFileOptions,
        setters: [
            (force, bool),
            (preserve, bool)
        ]
    );

    register_derive_builder_options!(
        engine,
        WriteOptionsBuilder,
        "WriteOptions",
        WriteOptions,
        setters: [
            (preserve_ownership, bool)
        ]
    );

    register_derive_builder_options!(
        engine,
        ReplacementOptionsBuilder,
        "ReplacementOptions",
        ReplacementOptions,
        setters: [
            (is_regex, bool),
            (replace_all, bool)
        ]
    );

    register_derive_builder_options!(
        engine,
        OpenDirOptionsBuilder,
        "OpenDirOptions",
        OpenDirOptions,
        setters: [
            (create, bool),
            (recursive, bool),
            (follow_symlinks, bool)
        ]
    );

    register_derive_builder_options!(
        engine,
        MoveOptionsBuilder,
        "MoveOptions",
        MoveOptions,
        setters: [
            (backup, bool),
            (verbose, bool)
        ]
    );

    register_derive_builder_options!(
        engine,
        OpenFileOptionsBuilder,
        "OpenFileOptions",
        OpenFileOptions,
        setters: [
            (read, bool),
            (write, bool),
            (create, bool),
            (permissions, i64),
            (follow_symlinks, bool)
        ]
    );

    register_derive_builder_options!(
        engine,
        DirConfigBuilder,
        "DirConfig",
        DirConfig,
        setters: [
            (path, String)
        ]
    );

    register_derive_builder_options!(
        engine,
        FindOptionsBuilder,
        "FindOptions",
        FindOptions,
        setters: [
            (name, String),
            (iname, String),
            (regex, String),
            (negate_name, bool),
            (size_range, SizeRange),
            (min_depth, i64),
            (max_depth, i64),
            (max_creation_time, DateTime),
            (min_creation_time, DateTime),
            (max_modification_time, DateTime),
            (min_modification_time, DateTime),
            (follow_symlinks, bool)
        ]
    );

    register_derive_builder_options!(
        engine,
        SearchGzipOptionsBuilder,
        "SearchGzipOptions",
        SearchGzipOptions,
        setters: [
            (exclude_pattern, String),
            (case_insensitive, bool),
            (max_results, i64 => isize)
        ]
    );
    register_derive_builder_options!(
        engine,
        CompressGzipOptionsBuilder,
        "CompressGzipOptions",
        CompressGzipOptions,
        setters: [
            (level, i64 => u32)
        ]
    );
}

pub(super) fn register_common_types_and_modules(engine: &mut Engine) {
    // Types
    engine.register_type::<SizeUnit>();
    engine.register_type::<RcDirHandle>();
    engine.register_type::<GzipInfo>();

    // Modules
    engine.register_static_module("SizeUnit", {
        let mut module = Module::new();
        module.set_var("BYTES", SizeUnit::Bytes);
        module.set_var("KILOBYTES", SizeUnit::Kilobytes);
        module.set_var("KIBIBYTES", SizeUnit::Kibibytes);
        module.set_var("MEGABYTES", SizeUnit::Megabytes);
        module.set_var("MEBIBYTES", SizeUnit::Mebibytes);
        module.set_var("GIGABYTES", SizeUnit::Gigabytes);
        module.set_var("GIBIBYTES", SizeUnit::Gibibytes);
        module.into()
    });
    engine.register_static_module("SizeRange", exported_module!(size_range_mod).into());
    engine
        .register_type_with_name::<RhaiSafeIoErrorKind>("RhaiSafeIoErrorKind")
        .register_static_module(
            ERROR_MODULE_NAME,
            exported_module!(error_kind_module).into(),
        );
    engine
        .register_type_with_name::<EntryType>("EntryType")
        .register_static_module("EntryType", exported_module!(dir_entry_type_mod).into());
}

fn register_common_serializer_fns(engine: &mut Engine) {
    register_map_serializers!(engine, [DirEntry, Metadata, WordCount, GzipInfo]);
}

pub(super) fn register_common_getters(engine: &mut Engine) {
    register_common_serializer_fns(engine);
    register_getters_with_guard!(engine, Match, [line_content, (line_number, usize => i64)]);
    register_getters_with_guard!(engine, WordCount, [
        (line_count, usize => i64),
        (word_count, usize => i64),
        (byte_count, usize => i64)
    ]);
    register_getters_with_guard!(engine, GzipInfo, [
        (compressed_size_bytes, u64 => i64),
        (uncompressed_size_bytes, u64 => i64),
        compression_ratio
    ]);
    register_getter_with_guard!(engine, DirEntry, name);
}

#[cfg(test)]
mod tests {
    use rex_test_utils::rhai::common::create_test_engine_and_register;

    /// Given: Two identical RhaiSafeIoErrorKind values
    /// When: Comparing them for equality in the Rhai engine
    /// Then: They should be equal
    #[test]
    fn test_error_kind_equality_same_type() {
        let engine = create_test_engine_and_register();
        let result = engine
            .eval::<bool>(
                r#"
                let a = IoErrorKind::InvalidPath;
                let b = IoErrorKind::InvalidPath;
                a == b
            "#,
            )
            .unwrap();
        assert!(result);
    }

    /// Given: Two identical RhaiSafeIoErrorKind values
    /// When: Comparing them for inequality in the Rhai engine
    /// Then: They should not be unequal
    #[test]
    fn test_error_kind_inequality_same_type() {
        let engine = create_test_engine_and_register();
        let result = engine
            .eval::<bool>(
                r#"
                let a = IoErrorKind::InvalidPath;
                let b = IoErrorKind::InvalidPath;
                a != b
            "#,
            )
            .unwrap();
        assert!(!result);
    }

    /// Given: Two different RhaiSafeIoErrorKind values
    /// When: Comparing them for inequality in the Rhai engine
    /// Then: They should be unequal
    #[test]
    fn test_error_kind_inequality_different_types() {
        let engine = create_test_engine_and_register();
        let result = engine
            .eval::<bool>(
                r#"
                let a = IoErrorKind::InvalidPath;
                let b = IoErrorKind::DirectoryOpenError;
                a != b
            "#,
            )
            .unwrap();
        assert!(result);
    }

    /// Given: Two different RhaiSafeIoErrorKind values
    /// When: Comparing them for equality in the Rhai engine
    /// Then: They should not be equal
    #[test]
    fn test_error_kind_equality_different_types() {
        let engine = create_test_engine_and_register();
        let result = engine
            .eval::<bool>(
                r#"
                let a = IoErrorKind::InvalidPath;
                let b = IoErrorKind::DirectoryOpenError;
                a == b
            "#,
            )
            .unwrap();
        assert!(!result);
    }

    /// Given: A RhaiSafeIoErrorKind value
    /// When: Converting it to a string in the Rhai engine
    /// Then: It should return the correct string representation
    #[test]
    fn test_error_kind_to_string() {
        let engine = create_test_engine_and_register();

        let result = engine
            .eval::<String>(
                r#"
                let kind = IoErrorKind::InvalidPath;
                kind.to_string()
                "#,
            )
            .unwrap();

        assert_eq!(result, "InvalidPath");
    }
}
