use crate::core_dump_analysis::{Frame, TracedProcess, TracedThread};
use crate::errors::RustSafeIoError;
use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;
use std::sync::LazyLock;

// Regex patterns for parsing GDB output. See unit tests for example lines that should be matched by these patterns.
// We skip over "New LWP XXXX" lines because although they provide a thread tid, they don't consistently map to anything else.
#[allow(clippy::unwrap_used)] // As long as tests pass it is impossible for this regex to fail at runtime
static THREAD_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"Thread (?P<thread_num>\d+) (?:\(Thread 0x[0-9a-f]+ )?\(LWP (?P<thread_tid>\d+)\)\)?:",
    )
    .unwrap()
});

#[allow(clippy::unwrap_used)]
static ALTERNATE_THREAD_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"Current thread is (?P<thread_num>\d+) \(LWP (?P<thread_tid>\d+)\)").unwrap()
});

#[allow(clippy::unwrap_used)]
static FRAME_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^#(?P<frame_number>\d+)\s+(?:0x(?P<instruction_pointer>[0-9a-f]+)\s+in)?\s+(?P<to_post_process>.*)?",
    ).unwrap()
});

/// Parse GDB/pstack backtrace output into structured data
pub fn parse_backtrace_output(output: &str) -> Result<Option<TracedProcess>, RustSafeIoError> {
    let mut threads: HashMap<u32, TracedThread> = HashMap::new(); // using a hashmap here and for Frames ensures we don't keep duplicates
    let mut current_thread_num: u32 = 1;
    let mut current_tid: Option<u32> = None;
    let mut current_frames: HashMap<u32, Frame> = HashMap::new();
    let mut pid: Option<u32> = None;

    // Algorithm: once we find a Thread match, store all subsequent Frame matches in an array. Once we find the next thread match or EOF,
    // flush the current thread to the threads map and reset frames for the new thread.
    // If the thread with id 1 happens to have a tid, that typically also corresponds to the main process id.
    for line in output.lines() {
        let line = line.trim();

        // Process Thread line
        if let Some(captures) = THREAD_REGEX
            .captures(line)
            .or(ALTERNATE_THREAD_REGEX.captures(line))
        {
            // Save previous thread if exists
            if !current_frames.is_empty() {
                let mut frames = current_frames.values().cloned().collect::<Vec<Frame>>();
                frames.sort_by(|a, b| a.frame_number.cmp(&b.frame_number));
                threads.insert(
                    current_thread_num,
                    TracedThread::new(current_thread_num, current_tid, frames),
                );
                if current_thread_num == 1 {
                    pid = current_tid;
                }
                current_frames.clear();
            }

            current_thread_num = captures
                .name("thread_num")
                .map(|m| m.as_str().parse())
                .transpose()?
                .unwrap_or(1);
            current_tid = captures
                .name("thread_tid")
                .map(|m| m.as_str().parse())
                .transpose()?;
        }

        // Process Frame line
        if let Some(captures) = FRAME_REGEX.captures(line) {
            let frame_number = captures
                .name("frame_number")
                .map(|m| m.as_str().parse())
                .transpose()?
                .unwrap_or(0);
            let instruction_ptr = captures
                .name("instruction_pointer")
                .map(|m| format!("0x{}", m.as_str()));
            let (function_name, source, line_number) = captures
                .name("to_post_process")
                .map(|m| m.as_str())
                .map(process_frame_info)
                .transpose()?
                .unwrap_or(("unknown".to_string(), None, None));

            current_frames.insert(
                frame_number,
                Frame::new(
                    frame_number,
                    function_name,
                    instruction_ptr,
                    source,
                    line_number,
                ),
            );
        }
    }

    // Add the last thread
    if !current_frames.is_empty() {
        let mut frames = current_frames.values().cloned().collect::<Vec<Frame>>();
        frames.sort_by(|a, b| a.frame_number.cmp(&b.frame_number));
        threads.insert(
            current_thread_num,
            TracedThread::new(current_thread_num, current_tid, frames),
        );
        if current_thread_num == 1 {
            pid = current_tid;
        }
    }

    if threads.is_empty() {
        // We didn't parse anything of note from the output
        return Ok(None);
    }

    let mut threads: Vec<TracedThread> = threads.values().cloned().collect();
    threads.sort_by(|a, b| a.id.cmp(&b.id));

    Ok(Some(TracedProcess::new(pid, threads)))
}

// frame_info contains: the function name, the function args, and optionally information about the source
// if source is present, then it will be demarcated by either "at" (for source files) or "from" (for libs)
#[allow(clippy::indexing_slicing)]
fn process_frame_info(s: &str) -> Result<(String, Option<String>, Option<u32>)> {
    let function_info;
    let mut source = None;
    let mut line_num = None;

    if s.contains(" at ") {
        // collect the source file name and the line number
        let parts: Vec<&str> = s.split(" at ").collect();
        function_info = parts[0].trim().to_string();
        let source_info = parts[1].trim().to_string();
        let source_parts: Vec<&str> = source_info.split(':').collect();
        source = Some(source_parts[0].to_string());
        line_num = Some(source_parts[1].parse()).transpose()?;
    } else if s.contains(" from ") {
        // collect the source library name
        let parts: Vec<&str> = s.split(" from ").collect();
        function_info = parts[0].trim().to_string();
        source = Some(parts[1].trim().to_string());
    } else {
        // no source info
        function_info = s.trim().to_string();
    }

    // discard the function args and keep the rest as the function name
    let function_args_start = function_info.rfind('(').unwrap_or(function_info.len());
    let function_name = function_info[0..function_args_start].trim();

    Ok((function_name.to_string(), source, line_num))
}

/// Parse GDB variable output into `HashMap` with optional values
#[allow(clippy::ptr_arg)] // generally we prefer to use Vec's with Rhai rather than array slices, avoids unnecessary type conversion
pub(super) fn parse_variable_output(
    output: &str,
    variable_names: &Vec<String>,
) -> Result<HashMap<String, String>, RustSafeIoError> {
    let mut variables = HashMap::new();
    let mut current_var_index = 0;

    // Look for GDB variable output patterns like "$1 = value"
    let value_regex = Regex::new(r"^\$\d+\s*=\s*(.*)$")?;

    // Check for user errors (invalid symbols)
    let error_patterns = ["No symbol", "There is no member named", "not defined"];

    for line in output.lines() {
        let line = line.trim();

        // Check for user errors - if the variable doesn't exist, skip to the next one
        for pattern in &error_patterns {
            if line.contains(pattern) && variable_names.get(current_var_index).is_some() {
                current_var_index += 1;
                break;
            }
        }

        // Parse variable values
        if let Some(captures) = value_regex.captures(line)
            && let Some(var_name) = variable_names.get(current_var_index)
        {
            let value = captures[1].trim().to_string();
            variables.insert(var_name.clone(), value);
            current_var_index += 1;
        }
    }

    Ok(variables)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Given: A simple GDB backtrace output
    /// When: Parsing the backtrace output
    /// Then: Returns a TracedProcess with correct thread and frame details
    #[test]
    fn test_parse_backtrace_output_basic() -> Result<()> {
        let output = r#"
[New LWP 1234]
Thread 1 (Thread 0x7f8b8c0a1000 (LWP 1234)):
#0  0x00007f8b8c0a1234 in main () at main.c:10
#1  0x00007f8b8c0a5678 in start_thread
"#;

        let expected = TracedProcess {
            pid: Some(1234),
            threads: vec![TracedThread {
                id: 1,
                tid: Some(1234),
                frames: vec![
                    Frame {
                        frame_number: 0,
                        function_name: "main".to_string(),
                        instruction_ptr: Some("0x00007f8b8c0a1234".to_string()),
                        source: Some("main.c".to_string()),
                        line_number: Some(10),
                    },
                    Frame {
                        frame_number: 1,
                        function_name: "start_thread".to_string(),
                        instruction_ptr: Some("0x00007f8b8c0a5678".to_string()),
                        source: None,
                        line_number: None,
                    },
                ],
            }],
        };

        assert_eq!(expected, parse_backtrace_output(output)?.unwrap());
        Ok(())
    }

    /// Given: A more complex GDB backtrace output with multiple frames
    /// When: Parsing the backtrace output
    /// Then: Returns a TracedProcess with correct thread and frame details
    #[test]
    fn test_parse_backtrace_output_2() -> Result<()> {
        // This is a real trace I got from running `less`. It has a few features that test some edge cases:
        // - the first frame num is duplicated. No idea why, but this did come from real gdb output
        // - all lines either contain references to the libc library or no source at all
        // - no actual thread line match
        let output = r#"
[New LWP 18451]
Core was generated by `less'.
#0  0x00007f07349d34f1 in read () from /lib64/libc.so.6
#0  0x00007f07349d34f1 in read () from /lib64/libc.so.6
#1  0x0000000000411422 in iread ()
#2  0x0000000000415045 in getchr ()
#3  0x00000000004084ee in commands ()
#4  0x0000000000401e62 in main ()
"#;

        let expected = TracedProcess {
            pid: None,
            threads: vec![TracedThread {
                id: 1,
                tid: None,
                frames: vec![
                    Frame {
                        frame_number: 0,
                        function_name: "read".to_string(),
                        instruction_ptr: Some("0x00007f07349d34f1".to_string()),
                        source: Some("/lib64/libc.so.6".to_string()),
                        line_number: None,
                    },
                    Frame {
                        frame_number: 1,
                        function_name: "iread".to_string(),
                        instruction_ptr: Some("0x0000000000411422".to_string()),
                        source: None,
                        line_number: None,
                    },
                    Frame {
                        frame_number: 2,
                        function_name: "getchr".to_string(),
                        instruction_ptr: Some("0x0000000000415045".to_string()),
                        source: None,
                        line_number: None,
                    },
                    Frame {
                        frame_number: 3,
                        function_name: "commands".to_string(),
                        instruction_ptr: Some("0x00000000004084ee".to_string()),
                        source: None,
                        line_number: None,
                    },
                    Frame {
                        frame_number: 4,
                        function_name: "main".to_string(),
                        instruction_ptr: Some("0x0000000000401e62".to_string()),
                        source: None,
                        line_number: None,
                    },
                ],
            }],
        };

        assert_eq!(expected, parse_backtrace_output(output)?.unwrap());
        Ok(())
    }

    /// Given: A more complex pstack output with multiple threads and complex function names
    /// When: Parsing the backtrace output
    /// Then: Returns a TracedProcess with correct thread and frame details
    #[test]
    fn test_parse_backtrace_output_3() -> Result<()> {
        // this is real output from pstack and has the total number of threads cut down (most of them had the same stack trace)
        let output = r#"
Thread 4 (Thread 0xffff7b7fd590 (LWP 50620)):
#0  0x0000ffff844f4df0 in pthread_cond_wait@@GLIBC_2.17 () from /lib64/libpthread.so.0
#1  0x000000000153f610 in std::condition_variable::wait(std::unique_lock<std::mutex>&) ()
#2  0x00000000008453a8 in myapp::server::ThreadPoolExecutor<myapp::server::LinuxMetrics>::Execute() ()
#3  0x000000000154459c in execute_native_thread_routine ()
#4  0x0000ffff844ee22c in start_thread () from /lib64/libpthread.so.0
#5  0x0000ffff844356dc in thread_start () from /lib64/libc.so.6
Thread 3 (Thread 0xffff838d0590 (LWP 50612)):
#0  0x0000ffff844358a4 in epoll_pwait () from /lib64/libc.so.6
#1  0x0000000000921544 in boost::asio::detail::epoll_reactor::run(bool, boost::asio::detail::op_queue<boost::asio::detail::task_io_service_operation>&) ()
#2  0x000000000091f8b0 in std::thread::_State_impl<std::thread::_Invoker<std::tuple<myapp::server::RPCServer::Start()::{lambda()#1}> > >::_M_run() ()
#3  0x000000000154459c in execute_native_thread_routine ()
#4  0x0000ffff844ee22c in start_thread () from /lib64/libpthread.so.0
#5  0x0000ffff844356dc in thread_start () from /lib64/libc.so.6
Thread 2 (Thread 0xffff840d1590 (LWP 50611)):
#0  0x0000ffff844f5180 in pthread_cond_timedwait@@GLIBC_2.17 () from /lib64/libpthread.so.0
#1  0x000000000090aca8 in myapp::server::HighResTimerStd::Start()::{lambda()#1}::operator()() const ()
#2  0x000000000154459c in execute_native_thread_routine ()
#3  0x0000ffff844ee22c in start_thread () from /lib64/libpthread.so.0
#4  0x0000ffff844356dc in thread_start () from /lib64/libc.so.6
Thread 1 (Thread 0xffff8468e010 (LWP 50609)):
#0  0x0000ffff844f979c in nanosleep () from /lib64/libpthread.so.0
#1  0x00000000007e80f8 in main ()
"#;

        let expected = TracedProcess {
            pid: Some(50609),
            threads: vec![
                TracedThread { id: 1, tid: Some(50609), frames: vec![
                    Frame { frame_number: 0, function_name: "nanosleep".to_string(), instruction_ptr: Some("0x0000ffff844f979c".to_string()), source: Some("/lib64/libpthread.so.0".to_string()), line_number: None },
                    Frame { frame_number: 1, function_name: "main".to_string(), instruction_ptr: Some("0x00000000007e80f8".to_string()), source: None, line_number: None },
                ]},
                TracedThread { id: 2, tid: Some(50611), frames: vec! [
                    Frame { frame_number: 0, function_name: "pthread_cond_timedwait@@GLIBC_2.17".to_string(), instruction_ptr: Some("0x0000ffff844f5180".to_string()), source: Some("/lib64/libpthread.so.0".to_string()), line_number: None },
                    Frame { frame_number: 1, function_name: "myapp::server::HighResTimerStd::Start()::{lambda()#1}::operator()() const".to_string(), instruction_ptr: Some("0x000000000090aca8".to_string()), source: None, line_number: None },
                    Frame { frame_number: 2, function_name: "execute_native_thread_routine".to_string(), instruction_ptr: Some("0x000000000154459c".to_string()), source: None, line_number: None },
                    Frame { frame_number: 3, function_name: "start_thread".to_string(), instruction_ptr: Some("0x0000ffff844ee22c".to_string()), source: Some("/lib64/libpthread.so.0".to_string()), line_number: None },
                    Frame { frame_number: 4, function_name: "thread_start".to_string(), instruction_ptr: Some("0x0000ffff844356dc".to_string()), source: Some("/lib64/libc.so.6".to_string()), line_number: None },
                ]},
                TracedThread { id: 3, tid: Some(50612), frames: vec! [
                    Frame { frame_number: 0, function_name: "epoll_pwait".to_string(), instruction_ptr: Some("0x0000ffff844358a4".to_string()), source: Some("/lib64/libc.so.6".to_string()), line_number: None },
                    Frame { frame_number: 1, function_name: "boost::asio::detail::epoll_reactor::run(bool, boost::asio::detail::op_queue<boost::asio::detail::task_io_service_operation>&)".to_string(), instruction_ptr: Some("0x0000000000921544".to_string()), source: None, line_number: None },
                    Frame { frame_number: 2, function_name: "std::thread::_State_impl<std::thread::_Invoker<std::tuple<myapp::server::RPCServer::Start()::{lambda()#1}> > >::_M_run()".to_string(), instruction_ptr: Some("0x000000000091f8b0".to_string()), source: None, line_number: None },
                    Frame { frame_number: 3, function_name: "execute_native_thread_routine".to_string(), instruction_ptr: Some("0x000000000154459c".to_string()), source: None, line_number: None },
                    Frame { frame_number: 4, function_name: "start_thread".to_string(), instruction_ptr: Some("0x0000ffff844ee22c".to_string()), source: Some("/lib64/libpthread.so.0".to_string()), line_number: None },
                    Frame { frame_number: 5, function_name: "thread_start".to_string(), instruction_ptr: Some("0x0000ffff844356dc".to_string()), source: Some("/lib64/libc.so.6".to_string()), line_number: None },
                ]},
                TracedThread { id: 4, tid: Some(50620), frames: vec! [
                    Frame { frame_number: 0, function_name: "pthread_cond_wait@@GLIBC_2.17".to_string(), instruction_ptr: Some("0x0000ffff844f4df0".to_string()), source: Some("/lib64/libpthread.so.0".to_string()), line_number: None },
                    Frame { frame_number: 1, function_name: "std::condition_variable::wait(std::unique_lock<std::mutex>&)".to_string(), instruction_ptr: Some("0x000000000153f610".to_string()), source: None, line_number: None },
                    Frame { frame_number: 2, function_name: "myapp::server::ThreadPoolExecutor<myapp::server::LinuxMetrics>::Execute()".to_string(), instruction_ptr: Some("0x00000000008453a8".to_string()), source: None, line_number: None },
                    Frame { frame_number: 3, function_name: "execute_native_thread_routine".to_string(), instruction_ptr: Some("0x000000000154459c".to_string()), source: None, line_number: None },
                    Frame { frame_number: 4, function_name: "start_thread".to_string(), instruction_ptr: Some("0x0000ffff844ee22c".to_string()), source: Some("/lib64/libpthread.so.0".to_string()), line_number: None },
                    Frame { frame_number: 5, function_name: "thread_start".to_string(), instruction_ptr: Some("0x0000ffff844356dc".to_string()), source: Some("/lib64/libc.so.6".to_string()), line_number: None },
                ]},
            ],
        };

        assert_eq!(expected, parse_backtrace_output(output)?.unwrap());
        Ok(())
    }

    /// Given: A GDB backtrace output with the alternate thread id pattern and non-null args
    /// When: Parsing the backtrace output
    /// Then: Returns a TracedProcess with correct thread and frame details
    #[test]
    fn test_parse_backtrace_output_4() -> Result<()> {
        let output = r#"
[New LWP 41479]
[New LWP 687]
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib64/libthread_db.so.1".
Core was generated by `/appbin/aurora-17.4.17.4.4.25949.0/bin/postgres'.
#0  0x0000400032866854 in epoll_pwait () from /lib64/libc.so.6
[Current thread is 1 (LWP 41479)]
#0  0x0000400032866854 in epoll_pwait () from /lib64/libc.so.6
#1  0x000000000077bf64 in WaitEventSetWaitBlock (nevents=<optimized out>, occurred_events=0xfffffa8cb890, cur_timeout=<optimized out>, set=0x40003a27a030) at latch.c:1587
#2  WaitEventSetWait (set=set@entry=0x40003a27a030, timeout=60000, occurred_events=occurred_events@entry=0xfffffa8cb890, nevents=nevents@entry=64, wait_event_info=wait_event_info@entry=0) at latch.c:1535
#3  0x0000000000768480 in ServerLoop () at postmaster.c:2109
#4  0x0000000000b8d488 in PostmasterMain (argc=<optimized out>, argv=<optimized out>) at postmaster.c:1887
#5  0x000000000065ec8c in main (argc=<optimized out>, argv=<optimized out>) at main.c:246
"#;
        let expected = TracedProcess {
            pid: Some(41479),
            threads: vec![TracedThread {
                id: 1,
                tid: Some(41479),
                frames: vec![
                    Frame {
                        frame_number: 0,
                        function_name: "epoll_pwait".to_string(),
                        instruction_ptr: Some("0x0000400032866854".to_string()),
                        source: Some("/lib64/libc.so.6".to_string()),
                        line_number: None,
                    },
                    Frame {
                        frame_number: 1,
                        function_name: "WaitEventSetWaitBlock".to_string(),
                        instruction_ptr: Some("0x000000000077bf64".to_string()),
                        source: Some("latch.c".to_string()),
                        line_number: Some(1587),
                    },
                    Frame {
                        frame_number: 2,
                        function_name: "WaitEventSetWait".to_string(),
                        instruction_ptr: None,
                        source: Some("latch.c".to_string()),
                        line_number: Some(1535),
                    },
                    Frame {
                        frame_number: 3,
                        function_name: "ServerLoop".to_string(),
                        instruction_ptr: Some("0x0000000000768480".to_string()),
                        source: Some("postmaster.c".to_string()),
                        line_number: Some(2109),
                    },
                    Frame {
                        frame_number: 4,
                        function_name: "PostmasterMain".to_string(),
                        instruction_ptr: Some("0x0000000000b8d488".to_string()),
                        source: Some("postmaster.c".to_string()),
                        line_number: Some(1887),
                    },
                    Frame {
                        frame_number: 5,
                        function_name: "main".to_string(),
                        instruction_ptr: Some("0x000000000065ec8c".to_string()),
                        source: Some("main.c".to_string()),
                        line_number: Some(246),
                    },
                ],
            }],
        };

        assert_eq!(expected, parse_backtrace_output(output)?.unwrap());

        Ok(())
    }

    /// Given: output from pstack command
    /// When: Parsing the pstack output
    /// Then: Returns a TracedProcess with correct thread and frame details
    #[test]
    fn test_parse_pstack_output() -> Result<()> {
        let output = r#"#0  0x00007f2c642f4c01 in nanosleep () from /lib64/libc.so.6
#1  0x0000000000403ab7 in rpl_nanosleep ()
#2  0x0000000000403949 in xnanosleep ()
#3  0x000000000040167c in main ()"#;

        let expected = TracedProcess {
            pid: None,
            threads: vec![TracedThread {
                id: 1,
                tid: None,
                frames: vec![
                    Frame {
                        frame_number: 0,
                        function_name: "nanosleep".to_string(),
                        instruction_ptr: Some("0x00007f2c642f4c01".to_string()),
                        source: Some("/lib64/libc.so.6".to_string()),
                        line_number: None,
                    },
                    Frame {
                        frame_number: 1,
                        function_name: "rpl_nanosleep".to_string(),
                        instruction_ptr: Some("0x0000000000403ab7".to_string()),
                        source: None,
                        line_number: None,
                    },
                    Frame {
                        frame_number: 2,
                        function_name: "xnanosleep".to_string(),
                        instruction_ptr: Some("0x0000000000403949".to_string()),
                        source: None,
                        line_number: None,
                    },
                    Frame {
                        frame_number: 3,
                        function_name: "main".to_string(),
                        instruction_ptr: Some("0x000000000040167c".to_string()),
                        source: None,
                        line_number: None,
                    },
                ],
            }],
        };

        assert_eq!(expected, parse_backtrace_output(output)?.unwrap());

        Ok(())
    }

    /// Given: output from pstack command with multiple threads
    /// When: Parsing the pstack output
    /// Then: Returns a TracedProcess with correct thread and frame details
    #[test]
    fn test_parse_pstack_output_multithread() -> Result<()> {
        let output = r#"Thread 2 (Thread 0x7fda2d62e700 (LWP 19939)):
#0  0x00007fda2d7192a9 in syscall () from /lib64/libc.so.6
#1  0x000055a05fd8f577 in std::thread::park ()
#2  0x000055a05e496453 in crossbeam_channel::select::run_select::{{closure}} ()
#3  0x000055a05e495ee6 in crossbeam_channel::select::run_select ()
#4  0x000055a05fc7d6d7 in rust_analyzer::main_loop::<impl rust_analyzer::global_state::GlobalState>::run ()
#5  0x000055a05fba9d59 in rust_analyzer::main_loop::main_loop ()
#6  0x000055a05fd0ddb1 in rust_analyzer::run_server ()
#7  0x000055a05fd24136 in std::sys::backtrace::__rust_begin_short_backtrace ()
#8  0x000055a05fd3aabb in core::ops::function::FnOnce::call_once{{vtable-shim}} ()
#9  0x000055a05fd859ef in std::sys::thread::unix::Thread::new::thread_start ()
#10 0x00007fda2df2744b in start_thread () from /lib64/libpthread.so.0
#11 0x00007fda2d71e52f in clone () from /lib64/libc.so.6
Thread 1 (Thread 0x7fda2e769a00 (LWP 19930)):
#0  0x00007fda2df2874a in pthread_join () from /lib64/libpthread.so.0
#1  0x000055a05fd3909b in std::thread::JoinInner<T>::join ()
#2  0x000055a05fd08205 in stdx::thread::JoinHandle<T>::join ()
#3  0x000055a05fd0eb0c in rust_analyzer::with_extra_thread ()
#4  0x000055a05fd0fe1e in rust_analyzer::main ()
#5  0x000055a05fd24146 in std::sys::backtrace::__rust_begin_short_backtrace ()
#6  0x000055a05fd10e72 in std::rt::lang_start::{{closure}} ()
#7  0x000055a05fd7f3b1 in std::rt::lang_start_internal ()
#8  0x000055a05fd15865 in main ()"#;

        let expected = TracedProcess {
            pid: Some(19930),
            threads: vec![
                TracedThread {
                    id: 1,
                    tid: Some(19930),
                    frames: vec![
                        Frame {
                            frame_number: 0,
                            function_name: "pthread_join".to_string(),
                            instruction_ptr: Some("0x00007fda2df2874a".to_string()),
                            source: Some("/lib64/libpthread.so.0".to_string()),
                            line_number: None,
                        },
                        Frame {
                            frame_number: 1,
                            function_name: "std::thread::JoinInner<T>::join".to_string(),
                            instruction_ptr: Some("0x000055a05fd3909b".to_string()),
                            source: None,
                            line_number: None,
                        },
                        Frame {
                            frame_number: 2,
                            function_name: "stdx::thread::JoinHandle<T>::join".to_string(),
                            instruction_ptr: Some("0x000055a05fd08205".to_string()),
                            source: None,
                            line_number: None,
                        },
                        Frame {
                            frame_number: 3,
                            function_name: "rust_analyzer::with_extra_thread".to_string(),
                            instruction_ptr: Some("0x000055a05fd0eb0c".to_string()),
                            source: None,
                            line_number: None,
                        },
                        Frame {
                            frame_number: 4,
                            function_name: "rust_analyzer::main".to_string(),
                            instruction_ptr: Some("0x000055a05fd0fe1e".to_string()),
                            source: None,
                            line_number: None,
                        },
                        Frame {
                            frame_number: 5,
                            function_name: "std::sys::backtrace::__rust_begin_short_backtrace".to_string(),
                            instruction_ptr: Some("0x000055a05fd24146".to_string()),
                            source: None,
                            line_number: None,
                        },
                        Frame {
                            frame_number: 6,
                            function_name: "std::rt::lang_start::{{closure}}".to_string(),
                            instruction_ptr: Some("0x000055a05fd10e72".to_string()),
                            source: None,
                            line_number: None,
                        },
                        Frame {
                            frame_number: 7,
                            function_name: "std::rt::lang_start_internal".to_string(),
                            instruction_ptr: Some("0x000055a05fd7f3b1".to_string()),
                            source: None,
                            line_number: None,
                        },
                        Frame {
                            frame_number: 8,
                            function_name: "main".to_string(),
                            instruction_ptr: Some("0x000055a05fd15865".to_string()),
                            source: None,
                            line_number: None,
                        },
                    ],
                },
                TracedThread {
                    id: 2,
                    tid: Some(19939),
                    frames: vec![
                        Frame {
                            frame_number: 0,
                            function_name: "syscall".to_string(),
                            instruction_ptr: Some("0x00007fda2d7192a9".to_string()),
                            source: Some("/lib64/libc.so.6".to_string()),
                            line_number: None,
                        },
                        Frame {
                            frame_number: 1,
                            function_name: "std::thread::park".to_string(),
                            instruction_ptr: Some("0x000055a05fd8f577".to_string()),
                            source: None,
                            line_number: None,
                        },
                        Frame {
                            frame_number: 2,
                            function_name: "crossbeam_channel::select::run_select::{{closure}}".to_string(),
                            instruction_ptr: Some("0x000055a05e496453".to_string()),
                            source: None,
                            line_number: None,
                        },
                        Frame {
                            frame_number: 3,
                            function_name: "crossbeam_channel::select::run_select".to_string(),
                            instruction_ptr: Some("0x000055a05e495ee6".to_string()),
                            source: None,
                            line_number: None,
                        },
                        Frame {
                            frame_number: 4,
                            function_name: "rust_analyzer::main_loop::<impl rust_analyzer::global_state::GlobalState>::run".to_string(),
                            instruction_ptr: Some("0x000055a05fc7d6d7".to_string()),
                            source: None,
                            line_number: None,
                        },
                        Frame {
                            frame_number: 5,
                            function_name: "rust_analyzer::main_loop::main_loop".to_string(),
                            instruction_ptr: Some("0x000055a05fba9d59".to_string()),
                            source: None,
                            line_number: None,
                        },
                        Frame {
                            frame_number: 6,
                            function_name: "rust_analyzer::run_server".to_string(),
                            instruction_ptr: Some("0x000055a05fd0ddb1".to_string()),
                            source: None,
                            line_number: None,
                        },
                        Frame {
                            frame_number: 7,
                            function_name: "std::sys::backtrace::__rust_begin_short_backtrace".to_string(),
                            instruction_ptr: Some("0x000055a05fd24136".to_string()),
                            source: None,
                            line_number: None,
                        },
                        Frame {
                            frame_number: 8,
                            function_name: "core::ops::function::FnOnce::call_once{{vtable-shim}}".to_string(),
                            instruction_ptr: Some("0x000055a05fd3aabb".to_string()),
                            source: None,
                            line_number: None,
                        },
                        Frame {
                            frame_number: 9,
                            function_name: "std::sys::thread::unix::Thread::new::thread_start".to_string(),
                            instruction_ptr: Some("0x000055a05fd859ef".to_string()),
                            source: None,
                            line_number: None,
                        },
                        Frame {
                            frame_number: 10,
                            function_name: "start_thread".to_string(),
                            instruction_ptr: Some("0x00007fda2df2744b".to_string()),
                            source: Some("/lib64/libpthread.so.0".to_string()),
                            line_number: None,
                        },
                        Frame {
                            frame_number: 11,
                            function_name: "clone".to_string(),
                            instruction_ptr: Some("0x00007fda2d71e52f".to_string()),
                            source: Some("/lib64/libc.so.6".to_string()),
                            line_number: None,
                        },
                    ],
                },
            ],
        };

        assert_eq!(expected, parse_backtrace_output(output)?.unwrap());

        Ok(())
    }

    /// Given: output from pstack command with multiple threads and unknown instruction pointers
    /// When: Parsing the pstack output
    /// Then: Returns a TracedProcess with correct thread and frame details
    #[test]
    fn test_parse_pstack_output_multithread_2() -> Result<()> {
        let output = r#"Thread 2 (LWP 32600):
#0  0x00007f0daeec6cae in __GI_epoll_pwait (epfd=10, events=0x7f0daedcecd0, maxevents=1024, timeout=-1, set=0x0) at ../sysdeps/unix/sysv/linux/epoll_pwait.c:42
#1  0x000000000214c627 in ?? ()
#2  0x0000003000000000 in ?? ()
Thread 1 (LWP 32599):
#0  0x00007f0daeec6cae in __GI_epoll_pwait (epfd=15, events=0x7ffe8a4e0d10, maxevents=1024, timeout=100, set=0x0) at ../sysdeps/unix/sysv/linux/epoll_pwait.c:42
#1  0x000000000214c627 in ?? ()
#2  0x00000030928ff4f0 in ?? ()"#;

        let expected = TracedProcess {
            pid: Some(32599),
            threads: vec![
                TracedThread {
                    id: 1,
                    tid: Some(32599),
                    frames: vec![
                        Frame {
                            frame_number: 0,
                            function_name: "__GI_epoll_pwait".to_string(),
                            instruction_ptr: Some("0x00007f0daeec6cae".to_string()),
                            source: Some("../sysdeps/unix/sysv/linux/epoll_pwait.c".to_string()),
                            line_number: Some(42),
                        },
                        Frame {
                            frame_number: 1,
                            function_name: "??".to_string(),
                            instruction_ptr: Some("0x000000000214c627".to_string()),
                            source: None,
                            line_number: None,
                        },
                        Frame {
                            frame_number: 2,
                            function_name: "??".to_string(),
                            instruction_ptr: Some("0x00000030928ff4f0".to_string()),
                            source: None,
                            line_number: None,
                        },
                    ],
                },
                TracedThread {
                    id: 2,
                    tid: Some(32600),
                    frames: vec![
                        Frame {
                            frame_number: 0,
                            function_name: "__GI_epoll_pwait".to_string(),
                            instruction_ptr: Some("0x00007f0daeec6cae".to_string()),
                            source: Some("../sysdeps/unix/sysv/linux/epoll_pwait.c".to_string()),
                            line_number: Some(42),
                        },
                        Frame {
                            frame_number: 1,
                            function_name: "??".to_string(),
                            instruction_ptr: Some("0x000000000214c627".to_string()),
                            source: None,
                            line_number: None,
                        },
                        Frame {
                            frame_number: 2,
                            function_name: "??".to_string(),
                            instruction_ptr: Some("0x0000003000000000".to_string()),
                            source: None,
                            line_number: None,
                        },
                    ],
                },
            ],
        };

        assert_eq!(expected, parse_backtrace_output(output)?.unwrap());

        Ok(())
    }

    /// Given: an invalid GDB backtrace output
    /// When: Parsing the backtrace output
    /// Then: Returns an error
    #[test]
    fn test_parse_backtrace_invalid() {
        let output = "not a valid backtrace";
        assert!(parse_backtrace_output(output).unwrap().is_none());
    }

    /// Given: GDB variable output with valid and invalid variables
    /// When: Parsing the variable output with variable names
    /// Then: Returns a HashMap with correct variable values and None for invalid ones
    #[test]
    fn test_parse_variable_output_basic() {
        let output = r#"
No symbol "invalid" in current context.
$1 = 42
$2 = "hello"
"#;
        let vars = vec!["invalid".to_string(), "x".to_string(), "str".to_string()];

        let result = parse_variable_output(output, &vars).unwrap();
        assert_eq!(result.get("invalid"), None);
        assert_eq!(result.get("x"), Some(&"42".to_string()));
        assert_eq!(result.get("str"), Some(&"\"hello\"".to_string()));
    }
}
