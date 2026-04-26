use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::fs::DirEntity;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rustix::mount::{UnmountFlags, unmount as rustix_unmount};
use std::path::Path;

use crate::auth::is_authorized;
use crate::errors::RustDiskinfoError;

use crate::options::UnmountOptions;

/// Unmounts a filesystem with Cedar authorization.
///
/// This function unmounts the filesystem at the specified path after performing Cedar
/// authorization checks. The unmount operation uses standard unmount flags.
///
/// Required capabilities:
/// * `CAP_SYS_ADMIN`
///
/// # Examples
///
/// ```no_run
/// use rust_safe_disk_info::{unmount, UnmountOptionsBuilder};
/// # use rex_cedar_auth::cedar_auth::CedarAuth;
/// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
/// #
/// # let cedar_auth = CedarAuth::new(
/// #     &get_default_test_rex_policy(),
/// #     get_default_test_rex_schema(),
/// #     "[]"
/// # ).unwrap().0;
///
/// let options = UnmountOptionsBuilder::default()
///     .path("/data".to_string())
///     .build()
///     .unwrap();
///
/// match unmount(&cedar_auth, options) {
///     Ok(()) => println!("Successfully unmounted /data"),
///     Err(e) => eprintln!("Failed to unmount: {}", e),
/// }
/// ```
#[allow(clippy::needless_pass_by_value)]
pub fn unmount(cedar_auth: &CedarAuth, options: UnmountOptions) -> Result<(), RustDiskinfoError> {
    // Note: This function operates on a path string rather than a file descriptor.
    // The umount syscall only accepts paths, and opening an FD to the mount point
    // would make it busy, causing unmount to fail.
    let entity = DirEntity::new(Path::new(&options.path))?;
    is_authorized(cedar_auth, &FilesystemAction::Unmount, &entity)?;

    // that unit test env do not have.
    // Always use NOFOLLOW to prevent following symlinks during unmount
    rustix_unmount(&options.path, UnmountFlags::NOFOLLOW).map_err(|e| {
        RustDiskinfoError::UnmountError {
            path: options.path.clone(),
            error: e.to_string(),
        }
    })?;

    Ok(())
}
