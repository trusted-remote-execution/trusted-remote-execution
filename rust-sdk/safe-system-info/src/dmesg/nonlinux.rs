use super::common::{DmesgEntry, DmesgProvider};
use crate::DmesgOptions;
use crate::RustSysteminfoError;

#[derive(Debug, Clone)]
pub(crate) struct Dmesg;

impl DmesgProvider for Dmesg {
    fn dmesg_info(&self, _options: DmesgOptions) -> Result<Vec<DmesgEntry>, RustSysteminfoError> {
        Err(RustSysteminfoError::UnsupportedOperationError {
            reason: "dmesg functionality is only available on Linux systems".to_string(),
        })
    }
}
