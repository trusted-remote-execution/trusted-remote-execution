use crate::error_constants::INVALID_SIZE;
use crate::errors::RustSafeIoError;
use crate::is_authorized;
use crate::options::SizeUnit;
use anyhow::Result;
use derive_builder::Builder;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::fs::entities::FileEntity;
use rustix::fs::ftruncate;

use crate::RcFileHandle;

/// Options for truncating a file to a specific length.
///
/// ```no_run
/// # use rust_safe_io::truncate::TruncateOptionsBuilder;
/// # use rust_safe_io::options::SizeUnit;
///
/// let truncate_options = TruncateOptionsBuilder::default()
///     .size(0)
///     .format(SizeUnit::Kibibytes)
///     .build();
/// ```
#[derive(Builder, Debug, Clone, Copy)]
#[builder(derive(Debug), build_fn(error = RustSafeIoError))]
pub struct TruncateOptions {
    #[builder(default = 0)]
    pub size: i64,
    #[builder(default = SizeUnit::Bytes)]
    pub format: SizeUnit,
}

impl RcFileHandle {
    /// Truncates or extends the underlying file to the specified length.
    ///
    /// This is not an atomic operation and instead truncates the file descriptor
    /// that is opened to mimic the Linux truncate command.
    ///
    /// # Arguments
    ///
    /// * `cedar_auth` - The Cedar authorization instance
    /// * `options` - [`TruncateOptions`] for the truncate operation
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The user is not authorized to truncate the file
    /// * Truncation fails
    pub fn safe_truncate(
        &self,
        cedar_auth: &CedarAuth,
        options: TruncateOptions,
    ) -> Result<(), RustSafeIoError> {
        is_authorized(
            cedar_auth,
            &FilesystemAction::Write,
            &FileEntity::from_string_path(&self.full_path())?,
        )?;

        if options.size < 0 {
            return Err(RustSafeIoError::InvalidArguments {
                reason: INVALID_SIZE.to_string(),
            });
        }

        // we validate size above
        #[allow(clippy::cast_sign_loss)]
        ftruncate(
            &self.file_handle.file,
            options.format.to_bytes(options.size) as u64,
        )?;

        Ok(())
    }
}
