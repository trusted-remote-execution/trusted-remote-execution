use cfg_if::cfg_if;

mod common;
mod metadata;
pub use common::{RcSymlinkHandle, SymlinkHandle};

cfg_if! {
    if #[cfg(unix)] {
        mod unix;
    }
}
