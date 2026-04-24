use core::clone::Clone;

use rustix::system::uname as rustix_uname;

use crate::{
    RustSysteminfoError,
    uname::{UnameInfo, UnameProvider},
};

#[derive(Clone, Debug)]
pub(crate) struct Uname;

impl UnameProvider for Uname {
    fn uname_info(&self) -> Result<UnameInfo, RustSysteminfoError> {
        let version: String = rustix_uname().sysname().to_str()?.to_string();
        let nodename_input: String = rustix_uname().nodename().to_str()?.to_string();
        let kernel_release_input: String = rustix_uname().release().to_str()?.to_string();
        let kernel_version_input: String = rustix_uname().version().to_str()?.to_string();
        let machine: String = rustix_uname().machine().to_str()?.to_string();
        Ok(UnameInfo {
            kernel_name: version,
            nodename: nodename_input,
            kernel_release: kernel_release_input,
            kernel_version: kernel_version_input,
            machine: machine.clone(),
            hardware_platform: machine.clone(),
            processor: machine,
            operating_system: "GNU/Linux".to_string(),
        })
    }
}
