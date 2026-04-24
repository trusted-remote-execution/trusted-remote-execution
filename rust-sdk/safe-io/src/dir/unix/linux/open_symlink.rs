use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{File, OpenOptions, OpenOptionsExt};
use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::fs::FileEntity;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rustix::fs::OFlags;
use std::path::Path;
use std::rc::Rc;

use crate::dir::common::validate_is_basename;
use crate::error_constants::NOT_A_SYMLINK;
use crate::errors::RustSafeIoError;
use crate::{RcDirHandle, RcSymlinkHandle, SymlinkHandle, build_path, is_authorized};

impl RcDirHandle {
    /// Opens a symlink (without following it) and returns a [`SymlinkHandle`] to the symlink itself.
    ///
    /// The symlink is opened with `O_PATH | O_NOFOLLOW` flags for metadata operations only,
    /// ensuring the symlink itself is opened, **not** its target file.
    /// You **cannot** use this handle to open, read, or write (I/O) the file that the symlink points to.
    ///
    ///
    /// ```no_run
    /// use rust_safe_io::DirConfigBuilder;
    /// use rust_safe_io::options::OpenDirOptionsBuilder;
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    ///
    /// let dir_path = "/tmp";
    /// let symlink_name = "my_symlink";
    /// let dir_handle = DirConfigBuilder::default()
    ///     .path(dir_path.to_string())
    ///     .build().unwrap()
    ///     .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap())
    ///     .unwrap();
    /// let symlink_handle = dir_handle.safe_open_symlink(&cedar_auth, symlink_name).unwrap();
    /// ```
    pub fn safe_open_symlink(
        &self,
        cedar_auth: &CedarAuth,
        symlink_name: &str,
    ) -> Result<RcSymlinkHandle, RustSafeIoError> {
        let full_path = build_path(&self.dir_handle.dir_config.path, symlink_name);
        is_authorized(
            cedar_auth,
            &FilesystemAction::Open,
            &FileEntity::from_string_path(&full_path)?,
        )?;

        validate_is_basename(Path::new(symlink_name))?;

        // Open the symlink itself (not its target) with O_PATH flag and without following symlinks.
        // Note: Setting read(true) is required for cap_std OpenOptions validation,
        // but the actual flags are controlled by custom_flags below. The O_PATH flag
        // will override the read mode, opening the symlink for metadata operations only.
        // Using FollowSymlinks::No ensures the symlink itself is opened rather than its target.
        let flags = i32::try_from(OFlags::PATH.bits())?;
        let symlink_file = self.dir_handle.dir.open_with(
            symlink_name,
            OpenOptions::new()
                .read(true)
                .follow(FollowSymlinks::No)
                .custom_flags(flags),
        )?;

        validate_is_symlink(&symlink_file)?;

        Ok(RcSymlinkHandle {
            symlink_handle: Rc::new(SymlinkHandle {
                fd: symlink_file,
                symlink_name: symlink_name.to_string(),
                dir_handle: Rc::clone(&self.dir_handle),
            }),
        })
    }
}

/// Validates that the given file represents a symlink.
///
/// This function checks if the file points to a symlink,
/// as opposed to a regular file or directory. This check prevents type
/// confusion and ensures operations intended for symlinks are only
/// performed on actual symlinks.
fn validate_is_symlink(file: &File) -> Result<(), RustSafeIoError> {
    let metadata = file.metadata()?;

    if !metadata.is_symlink() {
        return Err(RustSafeIoError::ValidationError {
            reason: NOT_A_SYMLINK.to_string(),
        });
    }

    Ok(())
}
