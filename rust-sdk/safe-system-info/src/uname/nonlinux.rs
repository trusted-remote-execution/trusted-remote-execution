use super::common::{UnameInfo, UnameProvider};
use crate::RustSysteminfoError;

#[derive(Debug, Clone)]
pub(crate) struct Uname;

impl UnameProvider for Uname {
    fn uname_info(&self) -> Result<UnameInfo, RustSysteminfoError> {
        Err(RustSysteminfoError::UnsupportedOperationError {
            reason: "uname functionality is only available on Linux systems".to_string(),
        })
    }
}
