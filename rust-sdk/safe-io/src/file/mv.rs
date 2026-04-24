use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::fs::entities::FileEntity;
use rex_logger::{RUNNER_AND_SYSLOG_TARGET, info};

use crate::errors::{MoveDetails, RustSafeIoError};
use crate::options::{
    CopyFileOptions, DeleteFileOptions, MoveOptions, OpenFileOptionsBuilder, WriteOptionsBuilder,
};
use crate::{RcDirHandle, RcFileHandle, build_path, is_authorized, is_authorized_with_context};

use cap_std::time::SystemTime;
use fs_set_times::{SetTimes, SystemTimeSpec};
use std::path::{Path, PathBuf};

impl RcFileHandle {
    /// Moves a file from one location to another, which can be either within the same directory or to a different directory.
    ///
    /// This operation performs atomic moves when both source and destination are on the same filesystem
    /// using the underlying `rename` system call. For cross-filesystem moves, the method falls back to
    /// a copy-and-delete operation when the `backup` option is enabled in `MoveOptions`.
    /// When `backup` is true, the function uses `safe_write()` which writes to a destination file
    /// atomically using a temporary file as backup.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_safe_io::DirConfigBuilder;
    /// use rust_safe_io::options::{OpenDirOptionsBuilder, OpenFileOptionsBuilder, MoveOptionsBuilder};
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    ///
    /// let src_dir = DirConfigBuilder::default()
    ///     .path("/tmp/source".to_string())
    ///     .build().unwrap()
    ///     .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap())
    ///     .unwrap();
    ///
    /// let dest_dir = DirConfigBuilder::default()
    ///     .path("/tmp/dest".to_string())
    ///     .build().unwrap()
    ///     .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap())
    ///     .unwrap();
    ///
    /// let src_file = src_dir.safe_open_file(
    ///     &cedar_auth,
    ///     "test.txt",
    ///     OpenFileOptionsBuilder::default().read(true).write(true).build().unwrap()
    /// ).unwrap();
    ///
    /// let moved_file = src_file.safe_move(
    ///     &cedar_auth,
    ///     dest_dir,
    ///     "test_moved.txt",
    ///     MoveOptionsBuilder::default().build().unwrap()
    /// ).unwrap();
    /// ```
    #[allow(clippy::needless_pass_by_value)]
    pub fn safe_move(
        &self,
        cedar_auth: &CedarAuth,
        dest_dir: RcDirHandle,
        dest_filename: &str,
        move_options: MoveOptions,
    ) -> Result<RcFileHandle, RustSafeIoError> {
        let src_path = build_path(self.dir_path(), self.path());
        let dest_path = build_path(&dest_dir.dir_handle.dir_config.path, dest_filename);

        let src_filename = Path::new(&src_path)
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or_default();

        let dest_context = serde_json::json!({
            "destination": {
                "path": dest_path,
                "name": dest_filename,
                "parent_path": dest_dir.dir_handle.dir_config.path
            }
        });

        is_authorized_with_context(
            cedar_auth,
            &FilesystemAction::Move,
            &FileEntity::from_string_path(&src_path)?,
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
                    source_resource_type: "File".to_string(),
                    source_resource_id: src_path.clone(),
                    dest_resource_type: "File".to_string(),
                    dest_resource_id: dest_path.clone(),
                })),
            },
            other => other,
        })?;

        is_authorized(
            cedar_auth,
            &FilesystemAction::Create,
            &FileEntity::from_string_path(&dest_path)?,
        )?;

        let src_dir = &self.file_handle.dir_handle.dir;
        let dest_dir_handle = &dest_dir.dir_handle.dir;

        match src_dir.rename(src_filename, dest_dir_handle, dest_filename) {
            Ok(()) => Ok(()),
            Err(e) => match e.kind() {
                // FileEntity::new() validates the paths but we add special handling
                // for invalid paths in case FileEntity::new() doesn't catch it.
                // Ignoring coverage because we cannot test for that case right now.
                std::io::ErrorKind::PermissionDenied => Err(RustSafeIoError::InvalidPath {
                    reason: e.to_string(),
                    path: PathBuf::new(), // cap-std's rename does not specify which path is escaping the sandbox so I am passing in an empty path
                }),

                std::io::ErrorKind::CrossesDevices => {
                    if move_options.backup {
                        self.move_file_cross_filesystem_with_backup(
                            &dest_dir,
                            dest_filename,
                            cedar_auth,
                        )?;
                    } else {
                        self.move_file_cross_filesystem_no_backup(
                            &dest_dir,
                            dest_filename,
                            cedar_auth,
                        )?;
                    }
                    self.safe_delete(cedar_auth, DeleteFileOptions { force: false })?;
                    Ok(())
                }
                _ => Err(RustSafeIoError::FileError {
                    reason: format!(
                        "Error moving file {src_filename} from '{src_path}' to '{dest_path}'"
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

        dest_dir.safe_open_file(cedar_auth, dest_filename, self.file_handle.open_options)
    }

    pub fn move_file_cross_filesystem_with_backup(
        &self,
        dest_dir_handle: &RcDirHandle,
        dest_file_name: &str,
        cedar_auth: &CedarAuth,
    ) -> Result<(), RustSafeIoError> {
        let content = self.safe_read(cedar_auth)?;
        let src_metadata = self.metadata(cedar_auth)?;

        let dest_file = dest_dir_handle.safe_open_file(
            cedar_auth,
            dest_file_name,
            OpenFileOptionsBuilder::default()
                .write(true)
                .create(true)
                .build()?,
        )?;

        let new_dest_file = dest_file.safe_write_with_options(
            cedar_auth,
            &content,
            WriteOptionsBuilder::default()
                .preserve_ownership(true)
                .build()?,
        )?;

        new_dest_file
            .file_handle
            .file
            .set_permissions(src_metadata.cap_std_metadata().permissions())?;

        #[cfg(unix)]
        {
            let to_spec = |cap_time: SystemTime| -> SystemTimeSpec {
                SystemTimeSpec::from(cap_time.into_std())
            };
            new_dest_file.file_handle.file.set_times(
                src_metadata.cap_std_metadata().modified().ok().map(to_spec),
                src_metadata.cap_std_metadata().accessed().ok().map(to_spec),
            )?;
        }

        Ok(())
    }

    pub fn move_file_cross_filesystem_no_backup(
        &self,
        dest_dir_handle: &RcDirHandle,
        dest_file_name: &str,
        cedar_auth: &CedarAuth,
    ) -> Result<(), RustSafeIoError> {
        let dest_file = dest_dir_handle.safe_open_file(
            cedar_auth,
            dest_file_name,
            OpenFileOptionsBuilder::default()
                .write(true)
                .create(true)
                .build()?,
        )?;

        self.safe_copy(
            cedar_auth,
            dest_file,
            CopyFileOptions {
                force: true,
                preserve: false,
            },
        )?;

        Ok(())
    }
}
