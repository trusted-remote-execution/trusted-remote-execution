use crate::dir_entry::Metadata;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::fs::entities::DirEntity;
use rex_logger::{RUNNER_AND_SYSLOG_TARGET, info};

use std::path::{Path, PathBuf};

use crate::auth::{is_authorized, is_authorized_with_context};
use crate::dir::cfg_if;
use crate::errors::{MoveDetails, RustSafeIoError};
use crate::options::{
    CreateSymlinkOptions, DeleteDirOptions, DirWalkOptions, MoveOptions, OpenDirOptionsBuilder,
    OpenFileOptionsBuilder, SetOwnershipOptions,
};
use crate::recursive::{DirWalk, WalkEntry};
use crate::{DirEntry, RcDirHandle, RcFileHandle, build_path, get_user_and_group_names};
use fs_set_times::{SystemTimeSpec, set_symlink_times, set_times};

cfg_if! {
    if #[cfg(target_os = "linux")] {
        use cap_fs_ext::OsMetadataExt;
    }
}

impl RcDirHandle {
    /// Moves a directory from one location to another, which can be either within the same parent directory or to a different parent directory.
    ///
    /// This operation is atomic when performed within the same filesystem. The method performs authorization checks
    /// to ensure the principal has permission to read from the source and write to the destination.
    ///
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_safe_io::DirConfigBuilder;
    /// use rust_safe_io::options::{OpenDirOptionsBuilder, MoveOptionsBuilder};
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    ///
    /// let src_parent_dir = DirConfigBuilder::default()
    ///     .path("/tmp/source_parent".to_string())
    ///     .build()
    ///     .unwrap()
    ///     .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap())
    ///     .unwrap();
    ///
    /// let src_dir = DirConfigBuilder::default()
    ///     .path("/tmp/source_parent/source".to_string())
    ///     .build()
    ///     .unwrap()
    ///     .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap())
    ///     .unwrap();
    ///      
    /// let dest_parent_dir = DirConfigBuilder::default()
    ///     .path("/tmp/dest".to_string())
    ///     .build().unwrap()
    ///     .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap())
    ///     .unwrap();
    ///
    /// let moved_dir = src_parent_dir.safe_move(
    ///     &cedar_auth,
    ///     src_dir,
    ///     dest_parent_dir,
    ///     "test_dir_moved",
    ///     MoveOptionsBuilder::default().build().unwrap()
    /// ).unwrap();
    /// ```
    #[allow(clippy::needless_pass_by_value)]
    #[allow(clippy::too_many_lines)]
    pub fn safe_move(
        &self,
        cedar_auth: &CedarAuth,
        src_dir: RcDirHandle,
        dest_parent_dir: RcDirHandle,
        dest_dirname: &str,
        move_options: MoveOptions,
    ) -> Result<RcDirHandle, RustSafeIoError> {
        let src_dirname = src_dir.basename();

        let src_path = build_path(&self.dir_handle.dir_config.path, src_dirname);
        let dest_path = build_path(&dest_parent_dir.dir_handle.dir_config.path, dest_dirname);

        let dest_context = serde_json::json!({
            "destination": {
                "path": dest_path,
                "name": dest_dirname,
                "parent_path": dest_parent_dir.dir_handle.dir_config.path
            }
        });

        is_authorized_with_context(
            cedar_auth,
            &FilesystemAction::Move,
            &DirEntity::new(Path::new(&src_path))?,
            &dest_context,
        )
        .map_err(|e| match e {
            RustSafeIoError::PermissionDenied {
                principal,
                action,
                resource_type,
                resource_id,
                ..
            } => RustSafeIoError::PermissionDenied {
                principal,
                action,
                resource_type,
                resource_id,
                move_details: Some(Box::new(MoveDetails {
                    source_resource_type: "Dir".to_string(),
                    source_resource_id: src_path.clone(),
                    dest_resource_type: "Dir".to_string(),
                    dest_resource_id: dest_path.clone(),
                })),
            },
            other => other,
        })?;

        is_authorized(
            cedar_auth,
            &FilesystemAction::Create,
            &DirEntity::new(Path::new(&dest_path))?,
        )?;

        let src_dir_handle = &self.dir_handle.dir;
        let dest_parent_dir_handle = &dest_parent_dir.dir_handle.dir;

        match src_dir_handle.rename(src_dirname, dest_parent_dir_handle, dest_dirname) {
            Ok(()) => Ok(()),
            Err(e) => match e.kind() {
                std::io::ErrorKind::DirectoryNotEmpty => {
                    // Since dest_parent_dir/dest_dirname already exists and is not empty,
                    // we then try to move into dest_parent_dir/dest_dirname/src_dirname.
                    let dest_dir_handle =
                        dest_parent_dir.safe_open_subdir(cedar_auth, dest_dirname)?;
                    let dest_path =
                        build_path(&dest_dir_handle.dir_handle.dir_config.path, src_dirname);
                    src_dir_handle.rename(src_dirname, &dest_dir_handle.dir_handle.dir, src_dirname)
                        .map_err(|e| match e.kind() {
                            std::io::ErrorKind::DirectoryNotEmpty => RustSafeIoError::DirectoryNotEmpty {
                                path: PathBuf::from(&dest_path),
                                source: Box::new(e),
                            },
                            _ => RustSafeIoError::DirectoryError {
                                reason: format!(
                                    "Error moving dir {src_dirname} from '{src_path}' to '{dest_path}'"
                                ),
                                path: PathBuf::from(&src_path),
                                source: Box::new(e),
                            },
                        })?;
                    if move_options.verbose {
                        info!(
                            target: RUNNER_AND_SYSLOG_TARGET,
                            "Moved from '{}' to '{}'",
                            src_path,
                            dest_path
                        );
                    }

                    return dest_dir_handle.safe_open_subdir(cedar_auth, src_dirname);
                }

                // DirEntity::new() validates the paths but we add special handling
                // for invalid paths in case DirEntity::new() doesn't catch it.
                // Ignoring coverage because we cannot test for that case right now.
                std::io::ErrorKind::PermissionDenied => Err(RustSafeIoError::InvalidPath {
                    reason: e.to_string(),
                    path: PathBuf::new(), // cap-std's rename does not specify which path is escaping the sandbox so I am passing in an empty path
                }),

                std::io::ErrorKind::CrossesDevices => {
                    let result_dir = self.move_dir_cross_filesystem(
                        &src_dir,
                        &dest_parent_dir,
                        dest_dirname,
                        cedar_auth,
                        move_options,
                    );

                    // delete source dir after everything successfully moved to the dest dir
                    src_dir.safe_delete(
                        cedar_auth,
                        DeleteDirOptions {
                            force: false,
                            recursive: true,
                        },
                    )?;

                    // return dir handle early so that it does not run the log and safe_open_subdir at the end
                    return result_dir;
                }
                _ => Err(RustSafeIoError::DirectoryError {
                    reason: format!(
                        "Error moving dir {src_dirname} from '{src_path}' to '{dest_path}'"
                    ),
                    path: PathBuf::from(&src_path),
                    source: Box::new(e),
                }),
            },
        }?;
        if move_options.verbose {
            info!(
                target: RUNNER_AND_SYSLOG_TARGET,
                "Moved from '{}' to '{}'",
                src_path,
                dest_path
            );
        }

        dest_parent_dir.safe_open_subdir(cedar_auth, dest_dirname)
    }

    /// This method determines the destination dir handle of a move operation. Only
    /// needed for cross filesystem move for directories.
    ///
    /// Best case: `dest_parent_dir` doesn't have subdir called `dest_dirname`
    /// return dir handle of subdir called `dest_dirname` after creating it.
    ///
    /// If `dest_parent_dir` already has a subdir with `dest_dirname`, the method checks if `dest_dirname` is empty.
    /// 1. If it's empty, we return that `dest_dirname` dir handle.  
    /// 2. If it's not empty, we check if directory `dest_parent_dir/dest_dirname/src_dirname` exists
    ///
    /// If `dest_parent_dir/dest_dirname/src_dirname` exists:
    /// 1. But is empty, return dir handle of `dest_parent_dir/dest_dirname/src_dirname`
    /// 2. If not empty, throw a `DirectoryNotEmpty` error
    #[allow(clippy::too_many_lines)]
    fn get_dest_dir_handle_of_move(
        dest_parent_dir: &RcDirHandle,
        dest_dirname: &str,
        src_dirname: &str,
        cedar_auth: &CedarAuth,
    ) -> Result<RcDirHandle, RustSafeIoError> {
        // first check if we can move into dest_parent_dir/dest_dirname
        let entries = dest_parent_dir.safe_list_dir(cedar_auth)?;
        let dest_dir_entry = entries.iter().find(|entry| entry.name() == dest_dirname);
        match dest_dir_entry {
            Some(entry) if entry.is_dir() => {
                let dest_dir = dest_parent_dir.safe_open_subdir(cedar_auth, dest_dirname)?;
                is_authorized(
                    cedar_auth,
                    &FilesystemAction::Read,
                    &DirEntity::new(Path::new(&dest_dir.dir_handle.dir_config.path))?,
                )?;

                let entries = dest_dir.safe_list_dir(cedar_auth)?;
                let dest_dir_has_entries = !entries.is_empty();
                // if dest_parent_dir/dest_dirname exists and is not empty, we try to move into dest_parent_dir/dest_dirname/src_dirname
                if dest_dir_has_entries {
                    let src_dir_entry = entries.iter().find(|entry| entry.name() == src_dirname);
                    match src_dir_entry {
                        Some(entry) if entry.is_dir() => {
                            let nested_dir = dest_dir.safe_open_subdir(cedar_auth, src_dirname)?;
                            is_authorized(
                                cedar_auth,
                                &FilesystemAction::Read,
                                &DirEntity::new(Path::new(&nested_dir.dir_handle.dir_config.path))?,
                            )?;
                            let nested_dir_is_empty =
                                nested_dir.dir_handle.dir.entries()?.next().is_none();
                            if nested_dir_is_empty {
                                Ok(nested_dir)
                            } else {
                                Err(RustSafeIoError::DirectoryNotEmpty {
                                    path: PathBuf::from(&nested_dir.dir_handle.dir_config.path),
                                    source: Box::new(std::io::Error::new(
                                        std::io::ErrorKind::DirectoryNotEmpty,
                                        "Directory not empty",
                                    )),
                                })
                            }
                        }
                        Some(_) => Err(RustSafeIoError::InvalidPath {
                            reason: format!("Cannot create directory '{src_dirname}': file exists"),
                            path: PathBuf::from(&build_path(
                                &dest_dir.dir_handle.dir_config.path,
                                src_dirname,
                            )),
                        }),
                        _none => {
                            dest_dir.dir_handle.dir.create_dir(src_dirname)?;
                            dest_dir.safe_open_subdir(cedar_auth, src_dirname)
                        }
                    }
                } else {
                    Ok(dest_dir)
                }
            }
            Some(_) => Err(RustSafeIoError::InvalidPath {
                reason: format!("Cannot create directory '{dest_dirname}': file exists"),
                path: PathBuf::from(&build_path(
                    &dest_parent_dir.dir_handle.dir_config.path,
                    dest_dirname,
                )),
            }),
            _none => {
                // `dest_parent_dir` doesn't have a subdir called `dest_dirname` so we create one and return it
                dest_parent_dir.dir_handle.dir.create_dir(dest_dirname)?;
                dest_parent_dir.safe_open_subdir(cedar_auth, dest_dirname)
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn move_dir_cross_filesystem(
        &self,
        src_dir_handle: &RcDirHandle,
        dest_parent_dir: &RcDirHandle,
        dest_dirname: &str,
        cedar_auth: &CedarAuth,
        move_options: MoveOptions,
    ) -> Result<RcDirHandle, RustSafeIoError> {
        let src_dirname = src_dir_handle.basename();

        let dest_dir_handle = RcDirHandle::get_dest_dir_handle_of_move(
            dest_parent_dir,
            dest_dirname,
            src_dirname,
            cedar_auth,
        )?;

        let src_path = build_path(&self.dir_handle.dir_config.path, src_dirname);
        let dest_path = dest_dir_handle.dir_handle.dir_config.path.clone();
        let nested_path = build_path(
            &build_path(&dest_parent_dir.dir_handle.dir_config.path, dest_dirname),
            src_dirname,
        );
        let is_nested = dest_path == nested_path;

        for entry in DirWalk::new(src_dir_handle, cedar_auth, &DirWalkOptions::default()) {
            match entry? {
                WalkEntry::Entry(mut dir_entry) => {
                    if dir_entry.is_file() {
                        let file_handle = dir_entry.open_as_file(
                            cedar_auth,
                            OpenFileOptionsBuilder::default().read(true).build()?,
                        )?;
                        file_handle.move_file_cross_filesystem_no_backup(
                            &dest_dir_handle,
                            dir_entry.name(),
                            cedar_auth,
                        )?;
                    } else if dir_entry.is_dir() {
                        let subdir_handle = dir_entry
                            .open_as_dir(cedar_auth, OpenDirOptionsBuilder::default().build()?)?;
                        subdir_handle.move_dir_cross_filesystem(
                            &subdir_handle,
                            &dest_dir_handle,
                            dir_entry.name(),
                            cedar_auth,
                            move_options,
                        )?;
                        // more file types may be added in the future
                    } else if dir_entry.is_socket() {
                        // An empty file is created instead of a socket file at the destination because when a socket is moved
                        // cross filesystem in linux mv, it stops working and has to be recreated so it's safer to just create
                        // a empty file at the destination as a placeholder for the socket
                        let metadata = dir_entry.metadata(cedar_auth)?;
                        let perms = metadata.permissions();

                        let file_handle = dest_dir_handle.safe_open_file(
                            cedar_auth,
                            dir_entry.name(),
                            OpenFileOptionsBuilder::default()
                                .write(true)
                                .create(true)
                                .permissions(perms)
                                .build()?,
                        )?;

                        Self::set_file_ownership_and_timestamps(
                            &file_handle,
                            &mut dir_entry,
                            cedar_auth,
                            &dest_dir_handle,
                            &metadata,
                        )?;
                    } else if dir_entry.is_symlink() {
                        let metadata = dir_entry.metadata(cedar_auth)?;
                        Self::move_symlink_cross_filesystem(
                            &mut dir_entry,
                            src_dir_handle,
                            &dest_dir_handle,
                            cedar_auth,
                            &metadata,
                        )?;
                    } else {
                        return Err(RustSafeIoError::UnsupportedOperationError {
                            reason: format!(
                                "{} directory entry is not supported",
                                dir_entry.entry_type()
                            ),
                        });
                    }
                }
                WalkEntry::DirPre(_) | WalkEntry::DirPost(_) | WalkEntry::File(_) => {}
            }
        }
        if move_options.verbose {
            info!(
                target: RUNNER_AND_SYSLOG_TARGET,
                "Moved from '{}' to '{}'",
                src_path,
                dest_path
            );
        }

        // We need to reopen the dir handle of the destination dir so that it has the moved files and dirs
        if is_nested {
            dest_parent_dir
                .safe_open_subdir(cedar_auth, dest_dirname)?
                .safe_open_subdir(cedar_auth, src_dirname)
        } else {
            dest_parent_dir.safe_open_subdir(cedar_auth, dest_dirname)
        }
    }

    #[allow(clippy::cast_possible_wrap)]
    fn move_symlink_cross_filesystem(
        dir_entry: &mut DirEntry,
        src_dir_handle: &RcDirHandle,
        dest_dir_handle: &RcDirHandle,
        cedar_auth: &CedarAuth,
        metadata: &Metadata,
    ) -> Result<(), RustSafeIoError> {
        let symlink_name = dir_entry.name();
        let link_target = src_dir_handle.safe_read_link_target(cedar_auth, symlink_name)?;

        // creating a symlink and then opening it in order to get the FD to set the ownership
        // is TOCTOU but we don't have a way to preventing this since symlink() and symlinkat()
        // syscalls do not return a fd to the symlink
        dest_dir_handle.safe_create_symlink(
            cedar_auth,
            &link_target,
            symlink_name,
            CreateSymlinkOptions { force: false },
        )?;

        let symlink_handle = dest_dir_handle.safe_open_symlink(cedar_auth, symlink_name)?;

        let (username, groupname) = get_user_and_group_names(
            metadata.cap_std_metadata().uid(),
            metadata.cap_std_metadata().gid(),
        )?;

        let ownership_options = SetOwnershipOptions {
            user: Some(username),
            group: Some(groupname),
            recursive: false,
        };
        symlink_handle.set_ownership(cedar_auth, ownership_options)?;

        if let (Ok(atime), Ok(mtime)) = (
            metadata.cap_std_metadata().accessed(),
            metadata.cap_std_metadata().modified(),
        ) {
            let dest_path =
                Path::new(&dest_dir_handle.dir_handle.dir_config.path).join(symlink_name);
            let _ = set_symlink_times(
                &dest_path,
                Some(SystemTimeSpec::Absolute(atime.into_std())),
                Some(SystemTimeSpec::Absolute(mtime.into_std())),
            );
        }

        Ok(())
    }

    fn set_file_ownership_and_timestamps(
        file_handle: &RcFileHandle,
        dir_entry: &mut DirEntry,
        cedar_auth: &CedarAuth,
        dest_dir_handle: &RcDirHandle,
        metadata: &Metadata,
    ) -> Result<(), RustSafeIoError> {
        let (username, groupname) = get_user_and_group_names(
            metadata.cap_std_metadata().uid(),
            metadata.cap_std_metadata().gid(),
        )?;
        let ownership_options = SetOwnershipOptions {
            user: Some(username),
            group: Some(groupname),
            recursive: false,
        };
        file_handle.set_ownership(cedar_auth, ownership_options)?;

        if let (Ok(atime), Ok(mtime)) = (
            metadata.cap_std_metadata().accessed(),
            metadata.cap_std_metadata().modified(),
        ) {
            let dest_path =
                Path::new(&dest_dir_handle.dir_handle.dir_config.path).join(dir_entry.name());
            let _ = set_times(
                &dest_path,
                Some(SystemTimeSpec::Absolute(atime.into_std())),
                Some(SystemTimeSpec::Absolute(mtime.into_std())),
            );
        }

        Ok(())
    }
}
