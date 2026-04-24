use cfg_if::cfg_if;

mod copy;
mod counts;
mod crypto;
mod delete;
mod gzip;
mod metadata;
mod mv;
mod read;
mod search;
mod strings;
mod write;

cfg_if! {
    if #[cfg(unix)] {
        mod unix;
    }
}
