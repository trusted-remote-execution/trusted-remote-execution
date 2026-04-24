use cfg_if::cfg_if;

mod chmod;
mod get_ownership;
mod write_in_place;

cfg_if! {
    if #[cfg(target_os = "linux")] {
        mod disk_usage;
        mod linux;
    }
}
