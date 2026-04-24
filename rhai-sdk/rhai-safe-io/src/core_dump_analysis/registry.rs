use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_logger::push_rhai_context_with_guard;
use rex_runner_registrar_utils::{
    register_direct_safe_fn, register_getters_with_guard, register_map_serializers,
    register_with_guard,
};
use rhai::serde::to_dynamic;
use rhai::{Array, Dynamic, Engine, EvalAltResult, Map, NativeCallContext};
use rust_safe_io::{CoreDump, Frame, TracedProcess, TracedThread};
use std::collections::HashMap;
use std::rc::Rc;

/// Register core dump analysis functions with Rhai engine
pub fn register_core_dump_analysis_functions(engine: &mut Engine, cedar_auth: &Rc<CedarAuth>) {
    engine.register_type::<CoreDump>();
    register_with_guard!(
        engine,
        "CoreDump",
        CoreDump,
        CoreDump::new,
        exe_file: String,
        core_dump_path: String
    );

    engine.register_type::<TracedProcess>();
    register_getters_with_guard!(
        engine,
        TracedProcess,
        [
            (pid, Option<u32> => i64),
            (threads, Vec<TracedThread> => Array)
        ]
    );

    engine.register_type::<TracedThread>();
    register_getters_with_guard!(
        engine,
        TracedThread,
        [
            (id, u32 => i64),
            (tid, Option<u32> => i64),
            (frames, Vec<Frame> => Array)
        ]
    );

    engine.register_type::<Frame>();
    register_getters_with_guard!(
        engine,
        Frame,
        [
            (frame_number, u32 => i64),
            function_name,
            (instruction_ptr, Option<String> => String),
            (source, Option<String> => String),
            (line_number, Option<u32> => i64)
        ]
    );

    register_core_dump_serializer_fns(engine);
    register_direct_safe_fn!(
        engine,
        "backtrace",
        CoreDump,
        backtrace,
        cedar_auth,
        -> TracedProcess,
        crate::errors::convert_to_rhai_error;
        tests: { positive: "test_rhai_core_dump_backtrace", negative: "test_rhai_core_dump_backtrace_parsing_error" }
    );

    register_direct_safe_fn!(
        engine,
        "get_variables",
        CoreDump,
        get_variables,
        cedar_auth,
        -> Map,
        transform: |result: HashMap<String, String>| Ok(convert_hashmap_to_rhai_map(result)),
        crate::errors::convert_to_rhai_error,
        frame_number: i64 => u32,
        variable_names: Array |> rhai_array_to_vec_string;
        tests: { positive: "test_rhai_core_dump_variables", negative: "test_rhai_core_dump_variables_invalid_variable" }
    );

    register_direct_safe_fn!(
        engine,
        "get_variables",
        CoreDump,
        get_variables_with_thread,
        cedar_auth,
        -> Map,
        transform: |result: HashMap<String, String>| Ok(convert_hashmap_to_rhai_map(result)),
        crate::errors::convert_to_rhai_error,
        thread_id: i64 => u32,
        frame_number: i64 => u32,
        variable_names: Array |> rhai_array_to_vec_string;
        tests: { positive: "test_rhai_core_dump_variables_with_thread_id", negative: "test_rhai_core_dump_variables_with_nonexistent_thread_id" }
    );
}

fn register_core_dump_serializer_fns(engine: &mut Engine) {
    register_map_serializers!(engine, [CoreDump, TracedProcess, TracedThread, Frame]);
}

fn rhai_array_to_vec_string(array: Array) -> Vec<String> {
    array.into_iter().map(|value| value.to_string()).collect()
}

/// Convert `HashMap`<String, String> to Rhai Map
fn convert_hashmap_to_rhai_map(hashmap: HashMap<String, String>) -> Map {
    let mut map = Map::new();
    for (key, value) in hashmap {
        map.insert(key.into(), Dynamic::from(value));
    }
    map
}

// move this to registrar utils
fn get_rhai_context_guard(context: &NativeCallContext) -> impl Drop {
    let line_number = context
        .call_position()
        .line()
        .map_or(0, |l| u32::try_from(l).unwrap_or(0));

    push_rhai_context_with_guard(Some(context.fn_name()), line_number)
}
