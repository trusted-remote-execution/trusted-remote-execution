use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::fs::entities::FileEntity;
use rex_logger::debug;

use cap_std::fs::{Dir, File};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use rustix::fs::{Mode, OFlags, openat};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::fd::AsFd;
use std::path::Path;
use std::rc::Rc;

use crate::RcDirHandle;
use crate::auth::is_authorized;
use crate::build_path;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::error_constants::INVALID_OPEN_FILE_OPTIONS;
use crate::error_constants::NOT_A_FILE;
use crate::errors::{RustSafeIoError, map_file_symlink_error};
use crate::file::FileHandle;
use crate::file::RcFileHandle;
use crate::options::OpenFileOptions;

use super::common::get_resolved_path_from_fd;
use super::validate_is_basename;

impl RcDirHandle {
    /// Opens or Creates a file by creating a [`FileHandle`] reference for use in I/O.
    ///
    /// Directory traversal and symlinks are blocked by default. When `follow_symlinks` is set to `true`,
    /// the returned file descriptor will point to the target file rather than the symlink itself.
    /// All subsequent file operations (read, write, chmod) will operate on the target file, while path operations (delete, move) operate on the symlink.
    ///
    /// ```no_run
    /// use rust_safe_io::DirConfigBuilder;
    /// use rust_safe_io::options::{OpenDirOptionsBuilder, OpenFileOptionsBuilder};
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
    /// let file_path = "test.txt";
    /// let dir_handle = DirConfigBuilder::default()
    ///     .path(dir_path.to_string())
    ///     .build().unwrap()
    ///     .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap())
    ///     .unwrap();
    /// let file_handle = dir_handle.safe_open_file(&cedar_auth, file_path, OpenFileOptionsBuilder::default().build().unwrap()).unwrap();
    ///
    /// // Opening a symlink with follow_symlinks=true returns a fd to the target file
    /// let symlink_handle = dir_handle.safe_open_file(
    ///     &cedar_auth,
    ///     "config_link", //config_link -> /etc/app/config.txt
    ///     OpenFileOptionsBuilder::default().read(true).follow_symlinks(true).build().unwrap()
    /// ).unwrap();
    /// ```
    pub fn safe_open_file(
        &self,
        cedar_auth: &CedarAuth,
        file_name: &str,
        open_file_options: OpenFileOptions,
    ) -> Result<RcFileHandle, RustSafeIoError> {
        let file_path = build_path(&self.dir_handle.dir_config.path, file_name);
        let entity = &FileEntity::from_string_path(&file_path)?;

        is_authorized(cedar_auth, &FilesystemAction::Open, entity).and_then(|()| {
            if open_file_options.create {
                is_authorized(cedar_auth, &FilesystemAction::Create, entity)
            } else {
                Ok(())
            }
        })?;

        let dir = &self.dir_handle.dir;
        let file_name_path = Path::new(file_name);

        validate_is_basename(file_name_path)?;

        let (file, resolved_path) = if open_file_options.follow_symlinks {
            let file = openat_file(dir, file_name_path, &open_file_options)?;
            let resolved_path = get_resolved_path_from_fd(&file)?;
            debug!(
                "Symlink resolved: symlink: '{}' -> target: '{}'",
                file_path, resolved_path
            );
            if resolved_path != file_path {
                is_authorized(
                    cedar_auth,
                    &FilesystemAction::Open,
                    &FileEntity::from_string_path(&resolved_path)?,
                )?;
            }
            (file, Some(resolved_path))
        } else {
            let file = dir
                .open_with(
                    file_name_path,
                    &open_file_options.to_cap_std_open_options()?,
                )
                .map_err(|e| map_file_symlink_error(e, &file_path))?;
            (file, None)
        };

        validate_is_file(&file)?;

        let file_handle = FileHandle {
            file,
            file_path: file_name.to_string(),
            resolved_path,
            dir_handle: Rc::clone(&self.dir_handle),
            open_options: open_file_options,
        };
        Ok(RcFileHandle {
            file_handle: Rc::new(file_handle),
        })
    }
}

/// Validates that the given file handle represents a regular file.
/// This function checks if the file handle points to a regular file,
/// as opposed to a directory or a symlink.
///
/// When opening a file in read-only mode using [`Dir::open_with`],
/// the system call does not distinguish between regular files and
/// directories. This check prevents potential issues by explicitly
/// verifying the file type before operations are performed.
fn validate_is_file(file: &File) -> Result<(), RustSafeIoError> {
    if !file.metadata()?.is_file() {
        return Err(RustSafeIoError::ValidationError {
            reason: NOT_A_FILE.to_string(),
        });
    }
    Ok(())
}

/// Linux and macOS function for opening files with symlink following support.
/// This function is only used for symlink operations when `follow_symlinks=true`.
/// For regular file operations, use cap-std open APIs directly.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn openat_file(
    dir: &Dir,
    path: &Path,
    open_options: &OpenFileOptions,
) -> Result<File, RustSafeIoError> {
    let flags = compute_oflags(open_options)?;
    let mode = compute_openat_mode(open_options)?;

    let fd = openat(dir.as_fd(), path, flags, mode)?;
    let cap_file = File::from_std(fd.into());

    Ok(cap_file)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn openat_file(
    _dir: &Dir,
    _path: &Path,
    _open_options: &OpenFileOptions,
) -> Result<File, RustSafeIoError> {
    Err(RustSafeIoError::UnsupportedOperationError {
        reason: "openat not supported on this platform".to_string(),
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn compute_oflags(open_options: &OpenFileOptions) -> Result<OFlags, RustSafeIoError> {
    let mut flags = match (open_options.read, open_options.write) {
        (true, true) => OFlags::RDWR,
        (true, false) => OFlags::RDONLY,
        (false, true) => OFlags::WRONLY,
        (false, false) => {
            return Err(RustSafeIoError::InvalidArguments {
                reason: INVALID_OPEN_FILE_OPTIONS.to_string(),
            });
        }
    };

    if open_options.create {
        flags |= OFlags::CREATE;
    }

    if !open_options.follow_symlinks {
        flags |= OFlags::NOFOLLOW;
    }

    Ok(flags)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn compute_openat_mode(open_options: &OpenFileOptions) -> Result<Mode, RustSafeIoError> {
    let mode_bits = if let Some(perms) = open_options.permissions {
        u16::try_from(perms & 0o777)?
    } else {
        0o644
    };

    Ok(Mode::from_raw_mode(mode_bits.into()))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::options::OpenFileOptionsBuilder;
    use rex_test_utils::assertions::assert_error_contains;
    use rstest::rstest;

    /// Given: valid open options
    /// When: computing OFlags from them
    /// Then: the expected value is returned
    #[rstest] // boolean values: read, write, create, follow
    #[case::ro_nocreate_nofollow(true, false, false, false, OFlags::RDONLY | OFlags::NOFOLLOW)]
    #[case::ro_create_nofollow(true, false, true, false, OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW)]
    #[case::ro_nocreate_follow(true, false, false, true, OFlags::RDONLY)]
    #[case::ro_create_follow(true, false, true, true, OFlags::RDWR | OFlags::CREATE)]
    #[case::wo_nocreate_nofollow(false, true, false, false, OFlags::WRONLY | OFlags::NOFOLLOW)]
    #[case::wo_create_nofollow(false, true, true, false, OFlags::WRONLY | OFlags::CREATE | OFlags::NOFOLLOW)]
    #[case::wo_nocreate_follow(false, true, false, true, OFlags::WRONLY)]
    #[case::wo_create_follow(false, true, true, true, OFlags::WRONLY | OFlags::CREATE)]
    #[case::rw_nocreate_nofollow(true, true, false, false, OFlags::RDWR | OFlags::NOFOLLOW)]
    #[case::rw_create_nofollow(true, true, true, false, OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW)]
    #[case::rw_nocreate_follow(true, true, false, true, OFlags::RDWR)]
    #[case::rw_create_follow(true, true, true, true, OFlags::RDWR | OFlags::CREATE)]
    // NB: create_only is effectively the same as write + create due to OpenFileOptionsBuilder override
    #[case::create_only_nofollow(false, false, true, false, OFlags::WRONLY | OFlags::CREATE | OFlags::NOFOLLOW)]
    #[case::create_only_follow(false, false, true, true, OFlags::WRONLY | OFlags::CREATE)]
    #[cfg(target_os = "linux")]
    fn test_compute_oflags_from_valid_open_options(
        #[case] read: bool,
        #[case] write: bool,
        #[case] create: bool,
        #[case] follow: bool,
        #[case] expected: OFlags,
    ) {
        let open_options = OpenFileOptionsBuilder::default()
            .read(read)
            .write(write)
            .create(create)
            .follow_symlinks(follow)
            .build()
            .unwrap();

        let result = compute_oflags(&open_options);

        assert_eq!(result.unwrap(), expected);
    }

    /// Given: invalid open options
    /// When: computing OFlags from them
    /// Then: an error is returned
    #[rstest]
    #[cfg(target_os = "linux")]
    fn test_compute_oflags_from_invalid_open_options(
        #[values(false)] create: bool, // create: true overrides the write option to true as well
        #[values(false, true)] follow: bool,
    ) {
        let open_options = OpenFileOptionsBuilder::default()
            .read(false)
            .write(false)
            .create(create)
            .follow_symlinks(follow)
            .build()
            .unwrap();

        let result = compute_oflags(&open_options);

        assert_error_contains(result, INVALID_OPEN_FILE_OPTIONS);
    }

    /// Given: valid open options
    /// When: computing Mode from them
    /// Then: the expected value is returned
    #[rstest]
    #[case::permissions_present(Some(0o400), 0o400)]
    #[case::permissions_absent(None, 0o644)]
    #[cfg(target_os = "linux")]
    fn test_compute_openat_mode(#[case] perms: Option<i64>, #[case] expected: u32) {
        let mut builder = OpenFileOptionsBuilder::default();
        builder.read(true);
        perms.map(|p| builder.permissions(p));

        let open_options = builder.build().unwrap();
        assert_eq!(
            compute_openat_mode(&open_options).unwrap(),
            Mode::from_raw_mode(expected.into())
        );
    }
}
