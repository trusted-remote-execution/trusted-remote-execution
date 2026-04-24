//! Integration tests for command functions
//!
//! Each command has its own submodule with comprehensive tests covering
//! basic usage, flags (long and short forms), flag combinations,
//! error cases, and Cedar authorization denial.

#[path = "command/awk.rs"]
mod awk;
#[path = "command/cat.rs"]
mod cat;
#[path = "command/cp.rs"]
mod cp;
#[cfg(unix)]
#[path = "command/du.rs"]
mod du;
#[path = "command/glob.rs"]
mod glob;
#[path = "command/grep.rs"]
mod grep;
#[path = "command/ls.rs"]
mod ls;
#[path = "command/mkdir.rs"]
mod mkdir;
#[path = "command/mv.rs"]
mod mv;
#[path = "command/rm.rs"]
mod rm;
#[path = "command/sed.rs"]
mod sed;
#[path = "command/seq.rs"]
mod seq;
#[path = "command/tail.rs"]
mod tail;
#[path = "command/touch.rs"]
mod touch;
#[path = "command/wc.rs"]
mod wc;
#[path = "command/write.rs"]
mod write;
