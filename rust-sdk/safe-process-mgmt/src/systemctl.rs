//! # Systemd Service Management
//!
//! This module provides secure wrappers for systemd service management operations.
//! All APIs operate on systemd services via D-Bus and require Cedar authorization.
//!
use crate::auth::is_authorized;
use crate::constants::error_constants::SYSTEMD_UNIT_NOT_FOUND;
use crate::constants::systemd_constants::{SYSTEMD_PATH, SYSTEMD_SERVICE, interface, method, mode};
use crate::errors::RustSafeProcessMgmtError;
use caps::CapSet;
use derive_getters::Getters;
use nix::sys::prctl;
use nix::unistd::{Uid, geteuid, seteuid, setresuid};
use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::systemd::actions::SystemdAction;
use rex_cedar_auth::systemd::entities::{ServiceEntity, SystemdEntity};
use rex_logger::warn;
use rust_sdk_common_utils::execute_with_privilege_drop;
use serde::{Serialize, Serializer};
use strum_macros::Display;
use zbus::blocking::{Connection, Proxy};
use zvariant::OwnedObjectPath;

// Systemctl API requires CAP_SETUID to initialize the Systemctl manager which is not available in Unit test environment.

/// Systemd unit active state
///
/// Represents the active state of a systemd unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Display)]
#[strum(serialize_all = "lowercase")]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum State {
    /// Started, bound, plugged in, depending on the unit type
    Active,
    /// Stopped, unbound, unplugged, depending on the unit type
    Inactive,
    /// Similar to inactive, but the unit failed in some way
    Failed,
    /// Changing from inactive to active
    Activating,
    /// Changing from active to inactive
    Deactivating,
    /// Unit is inactive and a maintenance operation is in progress
    Maintenance,
    /// Unit is active and it is reloading its configuration
    Reloading,
    /// Unit is active and a new mount is being activated in its namespace
    Refreshing,
    // Unknown state
    Unknown,
}

impl State {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "active" => State::Active,
            "inactive" => State::Inactive,
            "failed" => State::Failed,
            "activating" => State::Activating,
            "deactivating" => State::Deactivating,
            "maintenance" => State::Maintenance,
            "reloading" => State::Reloading,
            "refreshing" => State::Refreshing,
            _ => State::Unknown,
        }
    }

    /// Check if the state represents an active unit
    pub const fn is_active(self) -> bool {
        matches!(self, State::Active | State::Reloading | State::Refreshing)
    }
}

/// Information about a systemd service
#[derive(Debug, Clone, PartialEq, Eq, Getters, Serialize)]
pub struct ServiceInfo {
    pub name: String,
    pub description: String,
    pub load_state: String,
    pub load_path: String,
    pub unit_file_state: String,
    pub unit_file_preset: String,
    pub active_state: State,
    pub sub_state: String,
    pub main_pid: Option<u32>,

    // These need to be serialized as string because serializing with rhai::serde::to_dynamic automatically casts integer values to i64. Since these particular values
    // often exceed i64::MAX, they would be represented incorrectly in Rhai output.
    #[serde(serialize_with = "crate::systemctl::serialize_option_u64_as_string")]
    pub tasks: Option<u64>,
    #[serde(serialize_with = "crate::systemctl::serialize_option_u64_as_string")]
    pub memory: Option<u64>,

    pub documentation: Vec<String>,
    pub need_daemon_reload: bool,
}

#[allow(clippy::ref_option)] // Taking `&Option<u64>` instead of `Option<&u64>` as the parameter is required by serde.
fn serialize_option_u64_as_string<S>(v: &Option<u64>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match v {
        Some(v) => s.serialize_str(&v.to_string()),
        None => s.serialize_none(),
    }
}

/// Manager for systemd service operations
///
/// `SystemctlManager` provides a secure interface for managing systemd services through D-Bus.
/// It implements privilege management to run with user privileges by default and temporarily
/// elevate to root only when needed for systemd operations.
///
/// # Required Capability
/// - `CAP_SETUID`
///
/// # Examples
///
/// ```no_run
/// # use rust_safe_process_mgmt::systemctl::SystemctlManager;
/// # use rex_cedar_auth::cedar_auth::CedarAuth;
/// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
/// #
/// # let cedar_auth = CedarAuth::new(
/// #     &get_default_test_rex_policy(),
/// #     get_default_test_rex_schema(),
/// #     "[]"
/// # ).unwrap().0;
///
/// let manager = SystemctlManager::new().unwrap();
///
/// ```
#[derive(Debug, Clone, Copy)]
pub struct SystemctlManager {
    uid: Uid,
}

impl SystemctlManager {
    pub fn new() -> Result<Self, RustSafeProcessMgmtError> {
        let uid = geteuid();

        prctl::set_keepcaps(true).map_err(|e| RustSafeProcessMgmtError::Other(e.into()))?;

        // Set the saved set-user-id to 0 (root) to enable temporary privilege escalation.
        // This configures the process UIDs as: real=uid, effective=uid, saved=0
        // The saved UID of 0 allows seteuid(0) to succeed later when root access is needed.
        // Systemd operations via D-Bus require root privileges to manage system services.
        // This setup allows the process to run as non-root by default but temporarily
        // elevate to root only when calling systemd D-Bus methods.
        setresuid(uid, uid, Uid::from_raw(0)).map_err(|e| {
            warn!("Failed to set saved uid as 0. CAP_SETUID capability is required");
            RustSafeProcessMgmtError::PrivilegeError {
                message: format!("Failed to initialize systemd manager. Error: {e}"),
            }
        })?;

        Ok(Self { uid })
    }

    /// Execute a function with root privileges
    fn execute_as_root<F, R>(self, f: F) -> Result<R, RustSafeProcessMgmtError>
    where
        F: FnOnce() -> Result<R, RustSafeProcessMgmtError>,
    {
        let initial_caps = caps::read(None, CapSet::Effective).map_err(|e| {
            RustSafeProcessMgmtError::PrivilegeError {
                message: format!("Failed to read effective capabilities: {e}"),
            }
        })?;

        set_euid(0)?;

        let result = execute_with_privilege_drop!(
            f,
            set_euid(self.uid.as_raw()).map_err(|_| ()).and_then(|_| {
                if geteuid() != self.uid {
                    Err(())
                } else {
                    Ok(())
                }
            }),
            format!(
                "FATAL: Failed to drop privileges: expected UID {}, but current UID is {}. Terminating process",
                self.uid.as_raw(),
                geteuid().as_raw()
            ),
            |msg| RustSafeProcessMgmtError::PrivilegeError {
                message: format!("Panic during privileged execution: {msg}"),
            },
            |msg| RustSafeProcessMgmtError::PrivilegeError { message: msg }
        );

        caps::set(None, CapSet::Effective, &initial_caps).map_err(|e| {
            RustSafeProcessMgmtError::PrivilegeError {
                message: format!("Failed to restore effective capabilities: {e}"),
            }
        })?;

        result
    }

    /// Starts a systemd service
    ///
    /// This method starts the specified systemd service using D-Bus.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rust_safe_process_mgmt::systemctl::SystemctlManager;
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    ///
    /// let manager = SystemctlManager::new().unwrap();
    /// manager.safe_start(&cedar_auth, "nginx.service").unwrap();
    /// ```
    pub fn safe_start(
        &self,
        cedar: &CedarAuth,
        service: &str,
    ) -> Result<(), RustSafeProcessMgmtError> {
        let entity = ServiceEntity::new(service.to_string());
        is_authorized(cedar, &SystemdAction::Start, &entity)?;

        self.execute_as_root(|| {
            let (_conn, mgr) = get_manager()?;
            let _job = call_dbus_method(&mgr, method::START_UNIT, service)?;
            Ok(())
        })
    }

    /// Stops a systemd service
    ///
    /// This method stops the specified systemd service using D-Bus.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rust_safe_process_mgmt::systemctl::SystemctlManager;
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    ///
    /// let manager = SystemctlManager::new().unwrap();
    /// manager.safe_stop(&cedar_auth, "nginx.service").unwrap();
    /// ```
    pub fn safe_stop(
        &self,
        cedar: &CedarAuth,
        service: &str,
    ) -> Result<(), RustSafeProcessMgmtError> {
        let entity = ServiceEntity::new(service.to_string());
        is_authorized(cedar, &SystemdAction::Stop, &entity)?;

        self.execute_as_root(|| {
            let (_conn, mgr) = get_manager()?;
            let _job = call_dbus_method(&mgr, method::STOP_UNIT, service)?;
            Ok(())
        })
    }

    /// Restarts a systemd service
    ///
    /// This method restarts the specified systemd service using D-Bus.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rust_safe_process_mgmt::systemctl::SystemctlManager;
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    ///
    /// let manager = SystemctlManager::new().unwrap();
    /// manager.safe_restart(&cedar_auth, "nginx.service").unwrap();
    /// ```
    pub fn safe_restart(
        &self,
        cedar: &CedarAuth,
        service: &str,
    ) -> Result<(), RustSafeProcessMgmtError> {
        let entity = ServiceEntity::new(service.to_string());
        is_authorized(cedar, &SystemdAction::Restart, &entity)?;

        self.execute_as_root(|| {
            let (_conn, mgr) = get_manager()?;
            let _job = call_dbus_method(&mgr, method::RESTART_UNIT, service)?;
            Ok(())
        })
    }

    /// Restarts a systemd service (only if already running)
    ///
    /// This method restarts the specified systemd service using D-Bus only if the service
    /// is currently running. If the service is stopped or inactive, this method does nothing.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rust_safe_process_mgmt::systemctl::SystemctlManager;
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    ///
    /// let manager = SystemctlManager::new().unwrap();
    /// // Only restarts nginx if it's currently running
    /// manager.safe_try_restart(&cedar_auth, "nginx.service").unwrap();
    /// ```
    pub fn safe_try_restart(
        &self,
        cedar: &CedarAuth,
        service: &str,
    ) -> Result<(), RustSafeProcessMgmtError> {
        let entity = ServiceEntity::new(service.to_string());
        is_authorized(cedar, &SystemdAction::Restart, &entity)?;

        self.execute_as_root(|| {
            let (_conn, mgr) = get_manager()?;
            let _job = call_dbus_method(&mgr, method::TRY_RESTART_UNIT, service)?;
            Ok(())
        })
    }

    /// Reloads systemd daemon configuration
    ///
    /// This method reloads the systemd daemon configuration, which is necessary after
    /// modifying unit files.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rust_safe_process_mgmt::systemctl::SystemctlManager;
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    ///
    /// let manager = SystemctlManager::new().unwrap();
    ///
    /// manager.safe_daemon_reload(&cedar_auth).unwrap();
    /// ```
    pub fn safe_daemon_reload(&self, cedar: &CedarAuth) -> Result<(), RustSafeProcessMgmtError> {
        let entity = SystemdEntity::new();
        is_authorized(cedar, &SystemdAction::DaemonReload, &entity)?;

        self.execute_as_root(|| {
            let (_conn, mgr) = get_manager()?;
            mgr.call::<&str, (), ()>(method::RELOAD, &())?;
            Ok(())
        })
    }

    /// Gets detailed status information for a systemd service
    ///
    /// This method retrieves information about a systemd service including
    /// its state, configuration, resource usage, and whether a daemon reload is needed.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rust_safe_process_mgmt::systemctl::SystemctlManager;
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    ///
    /// let manager = SystemctlManager::new().unwrap();
    /// let status = manager.safe_status(&cedar_auth, "nginx.service").unwrap();
    ///
    /// println!("Service: {}", status.name);
    /// println!("State: {} ({})", status.active_state, status.sub_state);
    /// println!("Needs reload: {}", status.need_daemon_reload);
    /// ```
    pub fn safe_status(
        &self,
        cedar: &CedarAuth,
        service: &str,
    ) -> Result<ServiceInfo, RustSafeProcessMgmtError> {
        let entity = ServiceEntity::new(service.to_string());
        is_authorized(cedar, &SystemdAction::Status, &entity)?;

        let (conn, mgr) = get_manager()?;

        let unit_path: OwnedObjectPath =
            mgr.call(method::LOAD_UNIT, &(service,)).map_err(|_| {
                RustSafeProcessMgmtError::ServiceNotFound {
                    service: service.to_string(),
                }
            })?;

        let unit_proxy: Proxy<'_> = get_proxy(&conn, unit_path.as_str(), interface::UNIT)?;
        let service_proxy = get_proxy(&conn, unit_path.as_str(), interface::SERVICE)?;

        let active_state_str: String = unit_proxy.get_property("ActiveState")?;
        let active_state = State::from_str(&active_state_str);

        let sub_state: String = unit_proxy.get_property("SubState")?;
        let load_state: String = unit_proxy.get_property("LoadState")?;
        let description: String = unit_proxy.get_property("Description")?;
        let load_path: String = unit_proxy.get_property("FragmentPath")?;
        let unit_file_state: String = unit_proxy.get_property("UnitFileState")?;
        let unit_file_preset: String = unit_proxy.get_property("UnitFilePreset")?;
        let documentation: Vec<String> = unit_proxy.get_property("Documentation")?;
        let need_daemon_reload: bool = unit_proxy.get_property("NeedDaemonReload")?;

        let mut info = ServiceInfo {
            name: service.to_string(),
            description,
            load_state,
            load_path,
            unit_file_state,
            unit_file_preset,
            active_state,
            sub_state,
            main_pid: None,
            tasks: None,
            memory: None,
            documentation,
            need_daemon_reload,
        };

        if active_state.is_active() {
            let main_pid: u32 = service_proxy.get_property("MainPID")?;
            let tasks: u64 = service_proxy.get_property("TasksCurrent")?;
            let memory: u64 = service_proxy.get_property("MemoryCurrent")?;

            info.main_pid = Some(main_pid);
            info.tasks = Some(tasks);
            info.memory = Some(memory);
        }

        Ok(info)
    }
}

fn get_manager<'a>() -> Result<(Connection, Proxy<'a>), RustSafeProcessMgmtError> {
    let conn = Connection::system().map_err(|e| RustSafeProcessMgmtError::DBusError {
        message: format!("Failed to connect to system bus: {e}"),
    })?;

    let mgr =
        Proxy::new(&conn, SYSTEMD_SERVICE, SYSTEMD_PATH, interface::MANAGER).map_err(|e| {
            RustSafeProcessMgmtError::DBusError {
                message: format!("Failed to create systemd manager proxy: {e}"),
            }
        })?;

    Ok((conn, mgr))
}

fn get_proxy<'a>(
    conn: &'a Connection,
    path: &'a str,
    interface: &'a str,
) -> Result<Proxy<'a>, RustSafeProcessMgmtError> {
    Proxy::new(conn, SYSTEMD_SERVICE, path, interface).map_err(|e| {
        RustSafeProcessMgmtError::DBusError {
            message: format!("Failed to create proxy for interface '{interface}': {e}"),
        }
    })
}

fn set_euid(uid: u32) -> Result<(), RustSafeProcessMgmtError> {
    seteuid(Uid::from_raw(uid)).map_err(|e| RustSafeProcessMgmtError::PrivilegeError {
        message: format!("Failed to switch privileges. Error: {e}"),
    })
}

fn call_dbus_method(
    mgr: &Proxy<'_>,
    method: &str,
    service: &str,
) -> Result<OwnedObjectPath, RustSafeProcessMgmtError> {
    mgr.call(method, &(service, mode::REPLACE)).map_err(|e| {
        if format!("{e}").contains(SYSTEMD_UNIT_NOT_FOUND) {
            RustSafeProcessMgmtError::ServiceNotFound {
                service: service.to_string(),
            }
        } else {
            e.into()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Given: Various systemd active state strings
    /// When: Parsing them with State::from_str
    /// Then: Should return correct State variants
    #[rstest]
    #[case("active", State::Active)]
    #[case("ACTIVE", State::Active)]
    #[case("Active", State::Active)]
    #[case("inactive", State::Inactive)]
    #[case("INACTIVE", State::Inactive)]
    #[case("failed", State::Failed)]
    #[case("activating", State::Activating)]
    #[case("deactivating", State::Deactivating)]
    #[case("maintenance", State::Maintenance)]
    #[case("reloading", State::Reloading)]
    #[case("refreshing", State::Refreshing)]
    #[case("unknown", State::Unknown)]
    #[case("invalid-state", State::Unknown)]
    #[case("", State::Unknown)]
    fn test_state_from_str(#[case] input: &str, #[case] expected: State) {
        let result = State::from_str(input);
        assert_eq!(
            result, expected,
            "State::from_str({:?}) should return {:?}",
            input, expected
        );
    }

    /// Given: All State variants
    /// When: Calling is_active on each
    /// Then: Should return true only for Active, Reloading, and Refreshing states
    #[rstest]
    #[case(State::Active, true)]
    #[case(State::Reloading, true)]
    #[case(State::Refreshing, true)]
    #[case(State::Inactive, false)]
    #[case(State::Failed, false)]
    #[case(State::Activating, false)]
    #[case(State::Deactivating, false)]
    #[case(State::Maintenance, false)]
    #[case(State::Unknown, false)]
    fn test_state_is_active(#[case] state: State, #[case] expected: bool) {
        let result = state.is_active();
        assert_eq!(
            result, expected,
            "{:?}.is_active() should return {}",
            state, expected
        );
    }

    /// Given: ServiceInfo instances with various active_state enums
    /// When: Checking the active_state field
    /// Then: Should return correct State enum and is_active status
    #[rstest]
    #[case(State::Active, true)]
    #[case(State::Inactive, false)]
    #[case(State::Failed, false)]
    #[case(State::Reloading, true)]
    #[case(State::Refreshing, true)]
    #[case(State::Activating, false)]
    #[case(State::Unknown, false)]
    fn test_service_info_active_state(
        #[case] active_state: State,
        #[case] expected_is_active: bool,
    ) {
        let service_info = ServiceInfo {
            name: "test.service".to_string(),
            description: "Test Service".to_string(),
            load_state: "loaded".to_string(),
            load_path: "/etc/systemd/system/test.service".to_string(),
            unit_file_state: "enabled".to_string(),
            unit_file_preset: "enabled".to_string(),
            active_state,
            sub_state: "running".to_string(),
            main_pid: Some(1234),
            tasks: Some(1),
            memory: Some(1024),
            documentation: vec![],
            need_daemon_reload: false,
        };

        assert_eq!(
            service_info.active_state, active_state,
            "ServiceInfo should have active_state {:?}",
            active_state
        );
        assert_eq!(
            service_info.active_state.is_active(),
            expected_is_active,
            "ServiceInfo with active_state {:?} should have is_active() = {}",
            active_state,
            expected_is_active
        );
    }

    /// Given: a systemctl State
    /// When: calling fmt::Display and Serialize on it
    /// Then: the three representation should be the same and should be equal to the lowercase name of the state
    #[rstest]
    #[case(State::Active, "active")]
    #[case(State::Reloading, "reloading")]
    #[case(State::Refreshing, "refreshing")]
    #[case(State::Inactive, "inactive")]
    #[case(State::Failed, "failed")]
    #[case(State::Activating, "activating")]
    #[case(State::Deactivating, "deactivating")]
    #[case(State::Maintenance, "maintenance")]
    #[case(State::Unknown, "unknown")]
    fn test_serialization(#[case] state: State, #[case] expected: &str) {
        // Test Display trait
        assert_eq!(format!("{}", state), expected);

        // Test Serialize trait
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, format!("\"{}\"", expected));
    }
}
