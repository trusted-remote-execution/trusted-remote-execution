use anyhow::Error as AnyhowError;
use std::error::Error as SourceError;
use thiserror::Error;

/// Represents errors that can occur during Rex logger operations.
///
/// This enum provides specific error variants for different types of failures that can occur
/// during logging operations
///
/// # Variants
///
/// * `InitializationError` - Error during logger initialization
/// * `Other` - `Anyhow` for other errors
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum RexLoggerError {
    /// Error indicating an initialization error
    ///
    /// # Fields
    ///
    /// * `reason` - Description of error
    /// * `source` - Underlying error that caused the failure
    #[error("Initialization error: {reason}")]
    InitializationError {
        reason: String,
        #[source]
        source: Option<Box<dyn SourceError + Send + Sync>>,
    },

    /// Anyhow for other errors
    #[error(transparent)]
    Other(#[from] AnyhowError),
}
