use cfg_if::cfg_if;

mod common;
pub use common::{FileHandle, RcFileHandle};

mod copy;
mod counts;
mod crypto;
mod delete;
mod metadata;
mod mv; // move is a reserved keyword in rust
mod read;
mod search;
mod strings;
mod write;

pub mod gzip;

pub use counts::WordCount;
pub use search::Match;

cfg_if! {
    if #[cfg(unix)] {
        mod unix;
    }
}

cfg_if! {
    if #[cfg(target_os = "linux")] {
        pub use unix::linux::truncate;
        pub(crate) use unix::linux::elf_info;
    }
}
