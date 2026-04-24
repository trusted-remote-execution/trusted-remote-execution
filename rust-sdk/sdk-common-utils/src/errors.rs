//! The error module defines various error types that can occur during common utility operations
//!
//! The `RustCommonUtilsError` enum provides specific error variants for different failure scenarios.
use thiserror::Error;
use time::error::ComponentRange;

/// Represents errors that can occur in common utility operations
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum RustCommonUtilsError {
    /// Error indicating formatting failed
    ///
    /// # Fields
    ///
    /// * `message` - Description of error
    #[error("Format Error: {message}")]
    FormatError { message: String },

    /// Error indicating an invalid options
    ///
    /// # Fields
    ///
    /// * `reason` - Description of error
    #[error("Invalid arguments: {message}")]
    InvalidArguments { message: String },

    /// Error parsing a value from string
    ///
    /// # Fields
    ///
    /// * `message` - Description of error
    #[error("Parse Error: {message}")]
    ParseError { message: String },
}

impl From<ComponentRange> for RustCommonUtilsError {
    fn from(err: ComponentRange) -> Self {
        RustCommonUtilsError::InvalidArguments {
            message: format!("Invalid time component: {err}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Given: A ComponentRange error
    /// When: Converting to RustCommonUtilsError
    /// Then: Creates InvalidArguments variant
    #[test]
    fn test_component_range_conversion() {
        let component_err = time::Time::from_hms(25, 0, 0).unwrap_err();
        let result: RustCommonUtilsError = component_err.into();

        assert!(matches!(
            result,
            RustCommonUtilsError::InvalidArguments { .. }
        ));
    }
}
