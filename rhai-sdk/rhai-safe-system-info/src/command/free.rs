//! `free` — Display memory and swap usage
//!
//! # Example (Rhai)
//! ```rhai
//! let mem = free();
//! print(`Memory: ${mem.memory.total} total, ${mem.memory.available} available`);
//! print(`Swap: ${mem.swap.total} total, ${mem.swap.free} free`);
//! ```

use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::Map;

/// Returns memory and swap info as a map with `memory` (Meminfo) and `swap` (Swapinfo) structs.
#[cfg(target_os = "linux")]
pub(crate) fn free(cedar_auth: &CedarAuth) -> Result<Map, String> {
    use rhai::Dynamic;
    use rust_safe_system_info::SystemInfo;

    let mut sysinfo = SystemInfo::new().map_err(|e| e.to_string())?;
    let mem = sysinfo.memory_info(cedar_auth).map_err(|e| e.to_string())?;
    let swap = sysinfo.swap_info(cedar_auth).map_err(|e| e.to_string())?;

    let mut map = Map::new();
    map.insert("memory".into(), Dynamic::from(mem));
    map.insert("swap".into(), Dynamic::from(swap));
    Ok(map)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn free(_cedar_auth: &CedarAuth) -> Result<Map, String> {
    Err("free is only supported on Linux".to_string())
}
