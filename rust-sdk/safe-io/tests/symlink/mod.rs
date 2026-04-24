use cfg_if::cfg_if;

mod metadata;

cfg_if! {
    if #[cfg(unix)] {
        mod unix;
    }
}
