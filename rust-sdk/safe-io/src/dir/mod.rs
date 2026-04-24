use cfg_if::cfg_if;

mod common;
pub(crate) use common::validate_is_basename;
pub use common::{DirHandle, RcDirHandle};

mod open_dir;
pub use open_dir::{DirConfig, DirConfigBuilder};

mod create_subdirs;
mod delete;
mod find;
mod list;
mod metadata;
mod open_file;
mod read_link;

cfg_if! {
    if #[cfg(unix)] {
        mod unix;
        pub use unix::{DiskUsageEntry, DiskUsageResult};
    }
}
