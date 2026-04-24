#![deny(missing_docs)]
//! Documentation-only wrappers for `CoreDump` analysis functions.
#![allow(
    unused_variables,
    unused_imports,
    unreachable_code,
    clippy::unreachable,
    unused_mut,
    clippy::needless_pass_by_value
)]

use rhai::{Array, EvalAltResult};
use rust_safe_io::{RcFileHandle, TracedProcess};

/// Analyze core dump files to extract backtraces and inspect variable values.
#[derive(Debug, Clone, Copy)]
pub struct CoreDump;

impl CoreDump {
    /// Extracts backtrace information from a core dump file.
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"open"` | [`file_system::Dir::"<absolute_path>"`](cedar_auth::fs::entities::DirEntity) |
    /// | `file_system::Action::"open"` | [`file_system::File::"<absolute_path>"`](cedar_auth::fs::entities::FileEntity) |
    /// | `file_system::Action::"read"` | [`file_system::File::"<absolute_path>"`](cedar_auth::fs::entities::FileEntity) |
    ///
    /// NB: `open` is checked on the directories and files for gdb (`/usr/bin/gdb`),
    /// the executable, and the core dump. `read` is checked on the executable and core dump files.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let exe_path = "/appbin/aurora-17.4.17.4.4.25949.0/bin/postgres";
    /// let core_dump = CoreDump(exe_path, core_dump_path);
    /// let backtrace = core_dump.backtrace();
    ///
    /// let threads = backtrace.threads;
    /// let thread_count = threads.len();
    /// let main_thread = threads[0];
    /// let thread_id = main_thread.id;
    /// et thread_tid = main_thread.tid;
    ///
    /// let frames = main_thread.frames;
    /// let frame_count = frames.len();
    /// let main_frame = frames[0];
    /// let function_name = main_frame.function_name;
    /// let source = main_frame.source;
    /// let line_number = main_frame.line_number;
    /// let instruction_pointer = main_frame.instruction_ptr;
    /// let frame_number = main_frame.frame_number;
    /// # "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    pub fn backtrace(
        &mut self,
        gdb_binary: RcFileHandle,
    ) -> Result<TracedProcess, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Extracts variable values from a specific frame in the core dump as a map from variable name to value (string).
    ///
    /// If a variable isn't present in the frame, the output value will be the unit type for that variable.
    ///
    /// # Cedar Permissions
    ///
    /// Same as [`CoreDump::backtrace`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let exe_path = "/appbin/aurora-17.4.17.4.4.25949.0/bin/postgres";
    /// let core_dump = CoreDump(exe_path, core_dump_path);
    /// let variables = ["x"];
    /// let frame_num = 0;
    /// let result = core_dump.get_variables(frame_num, variables);
    /// result.get("x"); // 42
    /// result.get("non_existent_variable"); // () (unit)
    ///
    /// // additionally, a thread id can be specified. The default value is 1
    /// let thread_id = 1;
    /// let result = core_dump.get_variables(gdb_binary, thread_id, frame_num, variables);
    /// # "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    pub fn get_variables(
        &mut self,
        gdb_binary: RcFileHandle,
        frame_number: i64,
        variable_names: Array,
    ) -> Result<rhai::Map, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }
}
