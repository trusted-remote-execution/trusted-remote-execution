//! Command registry implementations
//!
//! This module registers command functions and their flag enums with the Rhai engine.
//! Each command has its own submodule handling type registration and function binding.
//!
//! # Available Commands
//!
//! | Command | Description | Example |
//! |---------|-------------|---------|
//! | `cat(path)` | Read file contents | `cat("/path/to/file.txt")` |
//! | `cat(flags, path)` | Read with flags | `cat([cat::number], "/path/to/file.txt")` |
//! | `ls(path)` | List directory contents | `ls("/path/to/dir")` |
//! | `ls(flags, path)` | List with flags | `ls([ls::all, ls::long], "/path/to/dir")` |
//! | `grep(pattern, path)` | Search file contents | `grep("error", "/path/to/file.txt")` |
//! | `tail(path)` | Read last lines | `tail("/path/to/file.txt")` |
//! | `sed(pat, rep, path)` | Find/replace | `sed("old", "new", "/path/to/file.txt")` |
//! | `rm(path)` | Remove file/dir | `rm("/path/to/file.txt")` |
//! | `seq(start, end)` | Numeric sequence | `seq(1, 10)` |
//! | `find_files(pat, path)` | Glob search | `find_files("*.txt", "/path/to/dir")` |
//! | `awk_*(...)` | Field processing | `awk_field(2, " ", "/path/to/file.txt")` |
//! | `wc(path)` | Line/word/byte counts | `wc("/path/to/file.txt")` |
//! | `cp(src, dst)` | Copy file | `cp("/src.txt", "/dst.txt")` |
//! | `mv(src, dst)` | Move/rename file | `mv("/old.txt", "/new.txt")` |
//! | `mkdir(path)` | Create directories | `mkdir("/tmp/a/b/c")` |
//! | `du(path)` | Disk usage (Unix) | `du("/path/to/dir")` |
//! | `touch(path)` | Create empty file | `touch("/tmp/file.txt")` |
//! | `write(path, content)` | Write to file (append default) | `write("/tmp/file.txt", "content\n")` |
//! | `write(flags, path, content)` | Write with mode | `write([write::replace], "/tmp/file.txt", "new\n")` |
//!
//! # Flag Modules
//!
//! | Module | Flags | Short Forms |
//! |--------|-------|-------------|
//! | `cat` | `number` | `n` |
//! | `ls` | `all`, `long`, `recursive` | `a`, `l`, `R` |
//! | `grep` | `ignore_case`, `count`, `invert`, `line_number`, `max_count(n)` | `i`, `c`, `v`, `n`, `m(n)` |
//! | `tail` | `n(count)`, `from(line)`, `range(start, end)` | — |
//! | `sed` | `regex`, `all`, `in_place` | `g`, `i` |
//! | `rm` | `force`, `recursive` | `f`, `r` |
//! | `seq` | `step(n)` | — |
//! | `glob` | `recursive` | `r` |
//! | `cp` | `force`, `preserve` | `f`, `p` |
//! | `mv` | `backup`, `verbose` | `b`, `v` |
//! | `mkdir` | `parents` | `p` |
//! | `wc` | `lines`, `words`, `bytes` | `l`, `w`, `c` |
//! | `du` | `summarize`, `all_files`, `apparent_size`, `max_depth(n)` | `s`, `a`, `d(n)` |
//! | `write` | `append`, `replace` | `a`, `r` |

mod awk;
mod cat;
mod cp;
mod du;
mod glob;
mod grep;
mod ls;
mod mkdir;
mod mv;
mod rm;
mod sed;
mod seq;
mod tail;
mod touch;
mod wc;
mod write;

use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::plugin::Engine;
use std::rc::Rc;

/// Registers all command functions and flag types with the Rhai engine.
pub(in crate::registry) fn register_command_functions(
    engine: &mut Engine,
    cedar_auth: &Rc<CedarAuth>,
) {
    cat::register(engine, cedar_auth);
    ls::register(engine, cedar_auth);
    grep::register(engine, cedar_auth);
    tail::register(engine, cedar_auth);
    sed::register(engine, cedar_auth);
    rm::register(engine, cedar_auth);
    seq::register(engine);
    glob::register(engine, cedar_auth);
    awk::register(engine, cedar_auth);
    wc::register(engine, cedar_auth);
    cp::register(engine, cedar_auth);
    mv::register(engine, cedar_auth);
    mkdir::register(engine, cedar_auth);
    du::register(engine, cedar_auth);
    touch::register(engine, cedar_auth);
    write::register(engine, cedar_auth);
}
