use cfg_if::cfg_if;

mod create_subdirs;
mod delete;
mod find;
mod list;
mod metadata;
mod open_dir;
mod open_file;
mod read_link;

cfg_if! {
    if #[cfg(unix)] {
        mod unix;
    }
}
