pub mod error_constants {
    pub const PROCESS_NOT_FOUND: &str = "Process with specified PID does not exist";
    pub const NAMESPACE_ENTER_FAILED: &str = "Failed to enter requested namespaces";
    pub const NAMESPACE_RESTORE_FAILED: &str = "Failed to restore original namespace";
    pub const CURRENT_NAMESPACE_ACCESS_FAILED: &str = "Failed to access current namespace";
    pub const INVALID_NAMESPACE_OPTIONS: &str = "At least one namespace must be enabled";
    pub const SYSTEMD_UNIT_NOT_FOUND: &str = "org.freedesktop.systemd1.NoSuchUnit";
}

pub mod systemd_constants {
    pub const SYSTEMD_SERVICE: &str = "org.freedesktop.systemd1";
    pub const SYSTEMD_PATH: &str = "/org/freedesktop/systemd1";

    /// Systemd D-Bus interfaces
    pub mod interface {
        pub const MANAGER: &str = "org.freedesktop.systemd1.Manager";
        pub const UNIT: &str = "org.freedesktop.systemd1.Unit";
        pub const SERVICE: &str = "org.freedesktop.systemd1.Service";
    }

    /// Systemd Manager D-Bus methods
    pub mod method {
        pub const START_UNIT: &str = "StartUnit";
        pub const STOP_UNIT: &str = "StopUnit";
        pub const RESTART_UNIT: &str = "RestartUnit";
        pub const TRY_RESTART_UNIT: &str = "TryRestartUnit";
        pub const RELOAD: &str = "Reload";
        pub const LOAD_UNIT: &str = "LoadUnit";
    }

    /// Unit operation modes
    pub mod mode {
        pub const REPLACE: &str = "replace";
    }
}
