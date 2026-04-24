use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::fs::entities::FileEntity;

use cap_fs_ext::{DirExt, SystemTimeSpec as CapSystemTimeSpec};
use cap_std::fs::PermissionsExt;
use cap_std::time::SystemTime;
use cap_tempfile::TempFile;
use flate2::read::GzDecoder;
use fs_set_times::{SetTimes, SystemTimeSpec};
use std::io::Read;
use std::io::copy;
use std::time::{Duration, UNIX_EPOCH};
use tar::Archive;

use rex_logger::{debug, warn};

use crate::errors::RustSafeIoError;
use crate::options::{ChmodDirOptions, ExtractArchiveOptions, SetOwnershipOptions};
use crate::{RcDirHandle, RcFileHandle, build_path, is_authorized, set_ownership_inner};

impl RcFileHandle {
    /// Extracts a tar.gz archive to a destination directory with Cedar authorization.
    ///
    /// This method safety extracts archive contents with comprehensive security checks:
    /// - Cedar authorization for each extracted file and directory
    /// - Skips special file types (symlinks, devices, etc.)
    /// - Optional preservation of permissions, ownership, and timestamps (see [`ExtractArchiveOptions`] for defaults)
    ///   - Permissions: preserved by default, when disabled files use system default permissions
    ///   - Ownership: not preserved by default, when enabled attempts to maintain original ownership (requires elevated privileges)
    ///   - Timestamps: preserved by default, when disabled files use current extraction time
    /// - Best effort approach, it continues processing extraction even after encountering errors
    ///
    /// Only supported for Unix-based platforms due to permission and ownership handling requirements.
    ///
    /// # Arguments
    ///
    /// * `cedar_auth` - The Cedar authorization instance
    /// * `dest_dir` - The destination directory handle where archive contents will be extracted
    /// * `options` - [`ExtractArchiveOptions`] controlling extraction behavior
    ///
    /// # Returns
    ///
    /// * `Result<()>`
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The principal doesn't have permission to read the archive file
    /// * The principal doesn't have permission to create files/directories in the destination
    /// * The principal doesn't have permission to write files in the destination
    /// * The archive file is corrupted or cannot be read
    /// * The archive file was not opened with read open options
    /// * Any I/O errors occur during extraction
    ///
    /// # Logging
    ///
    /// This method provides detailed logging:
    /// - Debug messages for successfully extracted files and directories
    /// - Warning messages for failed extractions (extraction continues)
    /// - Info messages for skipped special file types
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_safe_io::DirConfigBuilder;
    /// use rust_safe_io::options::{OpenDirOptionsBuilder, OpenFileOptionsBuilder, ExtractArchiveOptionsBuilder};
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    ///
    /// let source_dir = DirConfigBuilder::default()
    ///     .path("/tmp/source".to_string())
    ///     .build().unwrap()
    ///     .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap())
    ///     .unwrap();
    ///
    /// let dest_dir = DirConfigBuilder::default()
    ///     .path("/tmp/dest".to_string())
    ///     .build().unwrap()
    ///     .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().create(true).build().unwrap())
    ///     .unwrap();
    ///
    /// let archive_handle = source_dir.safe_open_file(
    ///     &cedar_auth,
    ///     "archive.tar.gz",
    ///     OpenFileOptionsBuilder::default().read(true).build().unwrap()
    /// ).unwrap();
    ///
    /// let options = ExtractArchiveOptionsBuilder::default()
    ///     .preserve_permissions(true)
    ///     .preserve_ownership(true)
    ///     .preserve_timestamps(true)
    ///     .build().unwrap();
    ///
    /// archive_handle.safe_extract_archive(&cedar_auth, dest_dir, options).unwrap();
    /// ```
    #[allow(clippy::needless_pass_by_value)]
    pub fn safe_extract_archive(
        &self,
        cedar_auth: &CedarAuth,
        dest_dir: RcDirHandle,
        options: ExtractArchiveOptions,
    ) -> Result<(), RustSafeIoError> {
        self.validate_read_open_option(cedar_auth)?;

        let file_clone = self.file_handle.file.try_clone()?;
        let reader: Box<dyn Read> = Box::new(GzDecoder::new(file_clone));
        let mut archive = Archive::new(reader);

        let mut directories = Vec::new();
        for entry_result in archive.entries()? {
            let mut entry = entry_result?;
            let path = entry.path()?;
            let header = entry.header();
            let path_str = path.to_string_lossy().to_string();

            match header.entry_type() {
                tar::EntryType::Directory => {
                    directories.push((path_str, header.clone()));
                }
                tar::EntryType::Regular => {
                    match extract_archive_file(
                        cedar_auth,
                        dest_dir.clone(),
                        &path_str,
                        &mut entry,
                        options,
                    ) {
                        Ok(()) => {
                            debug!("Extracted file: {path_str}");
                        }
                        Err(e) => {
                            warn!("Failed to extract file {path_str}: {e}");
                        }
                    }
                }
                _ => {
                    debug!(
                        "Skipping entry type {:?}: {}",
                        header.entry_type(),
                        path.display()
                    );
                }
            }
        }

        // Sort directories by depth (deepest first) to avoid permission conflicts when applying restrictive permissions to parent directories
        directories.sort_by(|a, b| b.0.cmp(&a.0));

        // Apply directory metadata after all files are extracted to ensure each directory gets its preserved attributes from the tar archive
        for (path_str, header) in directories {
            match apply_archive_directory_attributes(
                cedar_auth,
                dest_dir.clone(),
                &path_str,
                &header,
                options,
            ) {
                Ok(()) => {}
                Err(e) => {
                    warn!("Failed to apply directory attributes {path_str}: {e}");
                }
            }
        }

        Ok(())
    }
}

/// Creates directory path and applies tar archive metadata to the target directory.
///
/// This function is called during tar extraction to recreate directory structure
/// with preserved attributes. It ensures the full directory path exists, then applies
/// preservation settings (permissions, ownership, timestamps) only to the final
/// directory specified by `path`. Any intermediate directories created get default
/// system attributes.
///
/// Only supported for Unix-based platforms due to permission and ownership handling requirements.
///
/// # Arguments
///
/// * `cedar_auth` - The Cedar authorization instance
/// * `dest_dir` - The destination directory handle where the directory will be created
/// * `path` - The relative path of the directory to create within the destination
/// * `header` - The tar header containing directory metadata
/// * `options` - [`ExtractArchiveOptions`] controlling extraction behavior
///
/// # Returns
///
/// * `Result<()>`
///
/// # Errors
///
/// Returns an error if:
/// * The principal doesn't have permission to create the directory
/// * Directory creation fails due to I/O errors
///
/// Permission, ownership, and timestamp preservation failures are logged as warnings but do not cause errors.
#[allow(clippy::needless_pass_by_value)]
fn apply_archive_directory_attributes(
    cedar_auth: &CedarAuth,
    dest_dir: RcDirHandle,
    path: &str,
    header: &tar::Header,
    options: ExtractArchiveOptions,
) -> Result<(), RustSafeIoError> {
    dest_dir.safe_create_sub_directories(cedar_auth, path)?;

    let dir_handle = if let Ok(handle) = dest_dir.safe_open_subdir(cedar_auth, path) {
        handle
    } else {
        let mut current_dir = dest_dir;
        for component in path.split('/').filter(|c| !c.is_empty()) {
            current_dir = current_dir.safe_open_subdir(cedar_auth, component)?;
        }
        current_dir
    };

    if options.preserve_permissions {
        let mode = header.mode()?;
        match dir_handle.safe_chmod(
            cedar_auth,
            ChmodDirOptions {
                permissions: i64::from(mode),
                recursive: false,
            },
        ) {
            Ok(()) => {}
            Err(e) => {
                warn!("Could not set permissions for directory {path}: {e}");
            }
        }
    }

    if options.preserve_ownership {
        let username = header.username()?.map(ToString::to_string);
        let groupname = header.groupname()?.map(ToString::to_string);

        match dir_handle.set_ownership(
            cedar_auth,
            SetOwnershipOptions {
                user: username,
                group: groupname,
                recursive: false,
            },
        ) {
            Ok(()) => {}
            Err(e) => {
                warn!("Could not preserve ownership for directory {path}: {e}");
            }
        }
    }

    if options.preserve_timestamps {
        let mtime = header.mtime()?;
        let std_time = UNIX_EPOCH + Duration::from_secs(mtime);
        let cap_time = SystemTime::from_std(std_time);
        let mtime_spec = CapSystemTimeSpec::from(cap_time);

        if let Err(e) = DirExt::set_times(&dir_handle.dir_handle.dir, ".", None, Some(mtime_spec)) {
            warn!("Could not preserve timestamps for directory {path}: {e}");
        }
    }

    Ok(())
}

/// Extracts a regular file entry from a tar archive with Cedar authorization and metadata preservation.
///
/// This internal function handles the extraction of regular file entries from tar archives,
/// including atomic file creation using temporary files and optional preservation of
/// permissions, ownership, and timestamps based on the provided options.
///
/// Only supported for Unix-based platforms due to permission and ownership handling requirements.
///
/// # Arguments
///
/// * `cedar_auth` - The Cedar authorization instance
/// * `dest_dir` - The destination directory handle where the file will be created
/// * `path` - The relative path of the file to create within the destination
/// * `entry` - The mutable tar entry containing file data and metadata
/// * `options` - [`ExtractArchiveOptions`] controlling extraction behavior
///
/// # Returns
///
/// * `Result<()>` - Success or error
///
/// # Errors
///
/// Returns an error if:
/// * The principal doesn't have permission to create the file
/// * File creation or data copying fails due to I/O errors
/// * Permission, ownership, or timestamp preservation fails (logged as warnings)
#[allow(clippy::needless_pass_by_value)]
fn extract_archive_file(
    cedar_auth: &CedarAuth,
    dest_dir: RcDirHandle,
    path: &str,
    entry: &mut tar::Entry<Box<dyn Read>>,
    options: ExtractArchiveOptions,
) -> Result<(), RustSafeIoError> {
    let full_path = build_path(&dest_dir.dir_handle.dir_config.path, path);
    let file_entity = &FileEntity::from_string_path(&full_path)?;

    is_authorized(cedar_auth, &FilesystemAction::Create, file_entity)?;
    is_authorized(cedar_auth, &FilesystemAction::Write, file_entity)?;

    if let Some(last_slash) = path.rfind('/') {
        let parent_path = &path[..last_slash];
        dest_dir.safe_create_sub_directories(cedar_auth, parent_path)?;
    }

    let temp_file = TempFile::new(&dest_dir.dir_handle.dir)?;

    copy(entry, &mut temp_file.as_file())?;

    if options.preserve_permissions {
        let result = is_authorized(cedar_auth, &FilesystemAction::Chmod, file_entity)
            .and_then(|()| entry.header().mode().map_err(Into::into))
            .and_then(|mode| {
                let permissions = PermissionsExt::from_mode(mode);
                temp_file
                    .as_file()
                    .set_permissions(permissions)
                    .map_err(Into::into)
            });

        if let Err(e) = result {
            warn!("Could not set permissions for file {path}: {e}");
        }
    }

    if options.preserve_ownership {
        let result =
            is_authorized(cedar_auth, &FilesystemAction::Chown, file_entity).and_then(|()| {
                let username = entry.header().username()?.map(ToString::to_string);
                let groupname = entry.header().groupname()?.map(ToString::to_string);
                set_ownership_inner(temp_file.as_file(), username, groupname)
            });

        if let Err(e) = result {
            warn!("Could not preserve ownership for file {path}: {e}");
        }
    }

    if options.preserve_timestamps {
        let mtime = entry.header().mtime()?;
        let mtime_spec = SystemTimeSpec::from(UNIX_EPOCH + Duration::from_secs(mtime));
        temp_file.as_file().set_times(None, Some(mtime_spec))?;
    }

    temp_file.as_file().sync_all()?;
    temp_file.replace(path)?;

    Ok(())
}
