use cfg_if::cfg_if;

mod chmod;
mod disk_usage;
mod get_ownership;
mod write_in_place;

cfg_if! {
    if #[cfg(target_os = "linux")] {
        pub(super) mod linux;
    }
}
