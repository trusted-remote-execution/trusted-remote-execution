use cfg_if::cfg_if;

mod chmod;
mod create_link;
mod disk_usage;
mod get_ownership;

cfg_if! {
    if #[cfg(target_os = "linux")] {
        mod linux;
    }
}
