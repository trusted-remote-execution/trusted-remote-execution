use derive_getters::Getters;
use serde::Serialize;

mod core_dump;
mod parser;

pub use core_dump::CoreDump;
pub use parser::parse_backtrace_output;

/// Represents a core dump analysis result containing process and thread information
#[derive(Debug, Clone, Getters, PartialEq, Eq, Serialize)]
pub struct TracedProcess {
    /// Process ID from the core dump. There are some cases where the core dump just doesn't provide the process id, hence the Optional.
    pid: Option<u32>,
    /// List of threads in the process
    threads: Vec<TracedThread>,
}

impl TracedProcess {
    pub fn new(pid: Option<u32>, threads: Vec<TracedThread>) -> Self {
        Self { pid, threads }
    }

    /// Provide a setter for the pid for cases where traced output doesn't provide a pid, but we know what it should be (e.g. pstack with 1 thread)
    pub fn set_pid(&mut self, pid: u32) {
        self.pid = Some(pid);
    }
}

/// Represents a thread in a traced process
#[derive(Debug, Clone, Getters, PartialEq, Eq, Serialize)]
pub struct TracedThread {
    /// Thread ID assigned by GDB
    id: u32,
    /// Lightweight Process ID from kernel
    tid: Option<u32>,
    /// Stack frames for this thread
    frames: Vec<Frame>,
}

impl TracedThread {
    pub fn new(id: u32, tid: Option<u32>, frames: Vec<Frame>) -> Self {
        Self { id, tid, frames }
    }
}

/// Represents a stack frame in a thread's backtrace
#[derive(Debug, Clone, Getters, PartialEq, Eq, Serialize)]
#[allow(clippy::struct_field_names)] // clippy doesn't like "Frame.frame_number" because it's redundant. Calling a field "number" is worse though
pub struct Frame {
    /// Frame number assigned by GDB
    frame_number: u32,
    /// Function name (can be "??" if no debug symbols)
    function_name: String,
    /// Instruction pointer in hex format
    instruction_ptr: Option<String>,
    /// Source file or library path
    source: Option<String>,
    /// Line number if available (not for libraries)
    line_number: Option<u32>,
}

impl Frame {
    pub fn new(
        frame_number: u32,
        function_name: String,
        instruction_ptr: Option<String>,
        source: Option<String>,
        line_number: Option<u32>,
    ) -> Self {
        Self {
            frame_number,
            function_name,
            instruction_ptr,
            source,
            line_number,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Given: a TracedProcess
    /// When: set_pid is called
    /// Then: the pid is set to the new pid
    #[rstest]
    #[case(None, 456, Some(456))]
    #[case(Some(123), 789, Some(789))]
    fn test_set_pid(
        #[case] initial_pid: Option<u32>,
        #[case] new_pid: u32,
        #[case] expected_pid: Option<u32>,
    ) {
        let threads = vec![TracedThread::new(1, Some(123), vec![])];
        let mut process = TracedProcess::new(initial_pid, threads);

        // Set the pid
        process.set_pid(new_pid);

        // Verify pid is set to expected value
        assert_eq!(process.pid, expected_pid);
    }
}
