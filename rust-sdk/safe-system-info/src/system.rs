#[cfg(target_os = "linux")]
use crate::UnameInfo;
use crate::auth::{is_authorized, is_authorized_hostname_lookup, is_authorized_sysinfo};
use crate::dmesg::Dmesg;
#[cfg(target_os = "linux")]
use crate::dmesg::{DmesgEntry, DmesgProvider};
use crate::memory::{MeminfoProvider, Memory};
#[cfg(target_os = "linux")]
use crate::options::DmesgOptions;
#[cfg(target_os = "linux")]
use crate::slab::{Slab, SlabInfo, SlabInfoProvider};
use crate::sysctl::{Sysctl, SysctlEntry, SysctlProvider};
use crate::uname::Uname;
#[cfg(target_os = "linux")]
use crate::uname::UnameProvider;
use crate::{DNSInfo, Meminfo, ResolveConfig, RustSysteminfoError, Swapinfo};

use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::fs::entities::FileEntity;
use rust_safe_io::{
    DirConfigBuilder, RcFileHandle, options::OpenDirOptionsBuilder, options::OpenFileOptionsBuilder,
};
use sysinfo::{CpuRefreshKind, System};

#[cfg(target_os = "linux")]
use procfs::{CurrentSI, KernelStats};

const PROC_MEMINFO_PATH: &str = "/proc/meminfo";
const PROC_STAT_PATH: &str = "/proc/stat";
const DEV_KMSG_PATH: &str = "/dev/kmsg";

/// The `SystemInfo` struct acts as both a unified interface for getting various pieces of system information (memory, cpu, processes, io,
/// slabs, etc) as well as the layer that performs cedar auth checks.
#[derive(Debug, Clone)]
pub struct SystemInfo {
    memory: Memory,
    #[cfg(target_os = "linux")]
    slab: Slab,
    dmesg: Dmesg,
    uname: Uname,
}

impl SystemInfo {
    pub fn new() -> Result<SystemInfo, RustSysteminfoError> {
        Ok(SystemInfo {
            memory: Memory::new()?,
            #[cfg(target_os = "linux")]
            slab: Slab,
            dmesg: Dmesg,
            uname: Uname,
        })
    }

    /// Memory usage information about the system
    pub fn memory_info(&mut self, cedar_auth: &CedarAuth) -> Result<Meminfo, RustSysteminfoError> {
        is_authorized_to_read_file(cedar_auth, PROC_MEMINFO_PATH)?;
        self.memory.memory_info()
    }

    /// Swap usage of the system
    pub fn swap_info(&mut self, cedar_auth: &CedarAuth) -> Result<Swapinfo, RustSysteminfoError> {
        is_authorized_to_read_file(cedar_auth, PROC_MEMINFO_PATH)?;
        self.memory.swap_info()
    }

    /// Resolves a hostname to IP addresses using DNS resolution with configurable options.
    ///
    /// Supports custom DNS resolvers, protocol selection (TCP/UDP), and configurable timeouts.
    /// Returns all resolved IP addresses (both IPv4 and IPv6).
    #[allow(clippy::needless_pass_by_value)]
    pub fn resolve(
        &self,
        cedar_auth: &CedarAuth,
        config: ResolveConfig,
    ) -> Result<Vec<String>, RustSysteminfoError> {
        is_authorized_hostname_lookup(cedar_auth, &config.hostname)?;
        DNSInfo::resolve(&config)
    }

    /// Returns the hostname of the host
    pub fn hostname(&self, cedar_auth: &CedarAuth) -> Result<String, RustSysteminfoError> {
        // Sysinfo::host_name() calls libc's hostname which calls uname under the hood.
        is_authorized_sysinfo(cedar_auth)?;
        DNSInfo::hostname()
    }

    /// Returns the number of logical CPUs available on the system.
    ///
    /// This is equivalent to the `nproc --all` command on Linux, which returns the total
    /// number of logical processors (including hyper-threading/SMT cores) available on the
    /// system, regardless of CPU affinity or cgroup restrictions.
    pub fn cpu_count(&self, cedar_auth: &CedarAuth) -> Result<usize, RustSysteminfoError> {
        is_authorized_sysinfo(cedar_auth)?;
        let mut sys = System::new();
        sys.refresh_cpu_list(CpuRefreshKind::nothing());
        Ok(sys.cpus().len())
    }
}

#[cfg(target_os = "linux")]
impl SystemInfo {
    /// Provides system information matching the UNIX `uname` command
    pub fn uname_info(&self, cedar_auth: &CedarAuth) -> Result<UnameInfo, RustSysteminfoError> {
        is_authorized_sysinfo(cedar_auth)?;
        self.uname.uname_info()
    }

    /// Provides kernel information. See [`KernelStats`] docs for more details
    pub fn kernel_stats(&self, cedar_auth: &CedarAuth) -> Result<KernelStats, RustSysteminfoError> {
        is_authorized_to_read_file(cedar_auth, PROC_STAT_PATH)?;
        KernelStats::current().map_err(RustSysteminfoError::from)
    }

    /// Returns slabinfo for the system gathered from `/proc/slabinfo`
    pub fn slab_info(&mut self, cedar_auth: &CedarAuth) -> Result<SlabInfo, RustSysteminfoError> {
        self.slab.slab_info(cedar_auth)
    }

    /// Returns `dmesg` output in a structured format
    pub fn dmesg_info(
        &self,
        cedar_auth: &CedarAuth,
        options: DmesgOptions,
    ) -> Result<Vec<DmesgEntry>, RustSysteminfoError> {
        is_authorized_to_read_file(cedar_auth, DEV_KMSG_PATH)?;
        self.dmesg.dmesg_info(options)
    }
}

fn is_authorized_to_read_file(
    cedar_auth: &CedarAuth,
    file_path: &str,
) -> Result<(), RustSysteminfoError> {
    is_authorized(
        cedar_auth,
        &FilesystemAction::Read,
        &FileEntity::from_string_path(file_path)?,
    )
}

/// The `SysctlManager` struct provides a unified interface for managing kernel parameters.
#[derive(Debug, Clone, Copy)]
pub struct SysctlManager {
    sysctl: Sysctl,
}

impl SysctlManager {
    /// Creates a new `SysctlManager`
    ///
    /// # Required Capabilities
    ///
    /// - `CAP_SETUID` - Required to read root specific parameters
    pub fn new() -> Result<Self, RustSysteminfoError> {
        Ok(Self {
            sysctl: Sysctl::new()?,
        })
    }

    /// Reads a kernel parameter value
    pub fn read(&self, cedar_auth: &CedarAuth, key: &str) -> Result<String, RustSysteminfoError> {
        self.sysctl.read(cedar_auth, key)
    }

    /// Writes a kernel parameter value
    ///
    /// # Required Capabilities
    ///
    /// - `CAP_SETUID` - Required to execute the sysctl binary as root
    ///
    /// **Additional capabilities needed for specific parameters:**
    /// - `CAP_SYS_ADMIN` - For security-sensitive parameters (e.g. `kernel.kptr_restrict`)
    /// - `CAP_SYS_PTRACE` - For ptrace-related parameters (e.g. `kernel.yama.ptrace_scope`)
    pub fn write(
        &self,
        cedar_auth: &CedarAuth,
        key: &str,
        value: &str,
    ) -> Result<(), RustSysteminfoError> {
        self.sysctl.write(cedar_auth, key, value)
    }

    /// Loads sysctl settings from system configuration files
    ///
    /// This method executes `sysctl --system` to load settings from:
    /// - `/etc/sysctl.d/*.conf`
    /// - `/run/sysctl.d/*.conf`
    /// - `/usr/local/lib/sysctl.d/*.conf`
    /// - `/usr/lib/sysctl.d/*.conf`
    /// - `/lib/sysctl.d/*.conf`
    /// - `/etc/sysctl.conf`
    ///
    /// # Required Capabilities
    ///
    /// - `CAP_SETUID` - Required to execute the sysctl binary as root
    ///
    /// **Additional capabilities needed for specific parameters:**
    /// - `CAP_SYS_ADMIN` - For security-sensitive parameters (e.g. `kernel.kptr_restrict`)
    /// - `CAP_SYS_PTRACE` - For ptrace-related parameters (e.g. `kernel.yama.ptrace_scope`)
    ///
    /// **Note:** Some parameters may still fail to load even with all capabilities if restricted
    /// by Linux Security Modules (LSM) or kernel boot parameters. The operation will succeed
    /// (exit code 0) but may log warnings for parameters that couldn't be set.
    pub fn load_system(&self, cedar_auth: &CedarAuth) -> Result<(), RustSysteminfoError> {
        use rex_cedar_auth::sysctl::actions::SysctlAction;
        use rex_cedar_auth::sysctl::entities::SysctlEntity;

        let sysctl_entity = SysctlEntity::new();
        is_authorized(cedar_auth, &SysctlAction::Load, &sysctl_entity)?;

        self.sysctl.load_system(cedar_auth)
    }

    /// Finds sysctl parameters matching the given regex pattern
    ///
    /// The pattern is matched against filesystem paths (e.g., `/proc/sys/kernel/hostname`),
    /// not dot notation. Results are returned with keys in dot notation.
    ///
    /// # Pattern Examples
    /// - `".*"` - Find all parameters
    /// - `"kernel"` - Find all kernel parameters
    /// - `"net/ipv4"` - Find all net/IPv4 parameters
    pub fn find(
        &self,
        cedar_auth: &CedarAuth,
        pattern: &str,
    ) -> Result<Vec<SysctlEntry>, RustSysteminfoError> {
        self.sysctl.find(cedar_auth, pattern)
    }
}

pub fn open_proc_fd(
    cedar_auth: &CedarAuth,
    file_name: &str,
) -> Result<RcFileHandle, RustSysteminfoError> {
    let dir_path = "/proc";

    let dir_handle = DirConfigBuilder::default()
        .path(dir_path.to_string())
        .build()?
        .safe_open(cedar_auth, OpenDirOptionsBuilder::default().build()?)?;

    let file_handle = dir_handle.safe_open_file(
        cedar_auth,
        file_name,
        OpenFileOptionsBuilder::default().read(true).build()?,
    )?;

    Ok(file_handle)
}
