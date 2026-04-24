use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::fs::entities::FileEntity;

use cap_std::fs::File;
use cap_std::time::SystemTime;
use cfg_if::cfg_if;
use fs_set_times::{SetTimes, SystemTimeSpec};
use std::cmp;
use std::io::{Read, Write};
use std::path::PathBuf;

cfg_if! {
    if #[cfg(target_os = "linux")] {
        use std::sync::atomic::{AtomicBool, Ordering};
        use rustix::fs::copy_file_range;
        use std::os::fd::AsFd;
    }
}

use rex_logger::debug;

use crate::errors::RustSafeIoError;
use crate::options::CopyFileOptions;
use crate::{RcFileHandle, is_authorized};

impl RcFileHandle {
    /// Copies a file to a destination file with configurable options
    ///
    /// # Arguments
    ///
    /// * `cedar_auth` - The Cedar authorization instance
    /// * `destination` - The destination file handle where content will be copied to
    /// * `copy_file_options` - [`CopyFileOptions`] that has the configurations for copying a file
    ///
    /// # Returns
    ///
    /// * `Result<RcFileHandle>` - The destination file handle if successful
    ///
    /// After copy: source position unchanged, destination/returned handle at beginning of file.
    ///
    /// # Logging
    /// This method logs debug information about the copy operation, including the number of bytes copied and file paths.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The principal doesn't have permission to read the source file
    /// * The principal doesn't have permission to write to the destination file
    /// * The destination file exists and is not empty when force=false
    /// * The file was not opened with read permissions (source) or write permissions (destination)
    /// * Any I/O errors occur during the copy operation
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_safe_io::{DirConfigBuilder, RcFileHandle};
    /// use rust_safe_io::options::{OpenDirOptionsBuilder, OpenFileOptionsBuilder, CopyFileOptionsBuilder};
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    ///
    /// let dir_handle = DirConfigBuilder::default()
    ///     .path("/tmp".to_string())
    ///     .build().unwrap()
    ///     .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap())
    ///     .unwrap();
    ///
    /// let source = dir_handle.safe_open_file(
    ///     &cedar_auth,
    ///     "source.txt",
    ///     OpenFileOptionsBuilder::default().read(true).build().unwrap()
    /// ).unwrap();
    ///
    /// let dest = dir_handle.safe_open_file(
    ///     &cedar_auth,
    ///     "dest.txt",
    ///     OpenFileOptionsBuilder::default().create(true).build().unwrap()
    /// ).unwrap();
    ///
    /// let copy_options = CopyFileOptionsBuilder::default()
    ///     .force(true)
    ///     .preserve(true)
    ///     .build()
    ///     .unwrap();
    ///
    /// let dest_handle = source.safe_copy(&cedar_auth, dest, copy_options).unwrap();
    /// ```
    #[allow(clippy::needless_pass_by_value)]
    pub fn safe_copy(
        &self,
        cedar_auth: &CedarAuth,
        destination: RcFileHandle,
        copy_file_options: CopyFileOptions,
    ) -> Result<RcFileHandle, RustSafeIoError> {
        self.validate_read_open_option(cedar_auth)?;

        is_authorized(
            cedar_auth,
            &FilesystemAction::Write,
            &FileEntity::from_string_path(&destination.full_path())?,
        )?;
        destination.validate_write_open_option()?;

        let src_file = &self.file_handle.file;
        let dest_file = &destination.file_handle.file;

        if !copy_file_options.force && dest_file.metadata()?.len() > 0 {
            return Err(RustSafeIoError::DestinationFileNotEmptyError {
                destination_path: PathBuf::from(&destination.full_path()),
                file_size: dest_file.metadata()?.len(),
            });
        }

        let copy_result = CopyFileHelper::copy_file_impl(src_file, dest_file);

        // regardless of whether the copy succeeded or failed, we always want to try to rewind the source file. If rewinding failed,
        // we still want to continue with updating the destination file
        let _ = self.rewind();

        let bytes_copied = copy_result?;

        dest_file.set_len(bytes_copied)?;
        destination.rewind()?;

        if copy_file_options.preserve {
            let src_metadata = src_file.metadata()?;
            dest_file.set_permissions(src_metadata.permissions())?;

            #[cfg(unix)]
            {
                let to_spec = |cap_time: SystemTime| -> SystemTimeSpec {
                    SystemTimeSpec::from(cap_time.into_std())
                };
                dest_file.set_times(
                    src_metadata.modified().ok().map(to_spec),
                    src_metadata.accessed().ok().map(to_spec),
                )?;
            }
        }

        debug!(
            "Copied {} bytes from {} to {}",
            bytes_copied,
            self.full_path(),
            destination.full_path()
        );

        Ok(destination.clone())
    }
}

/// Helper struct for file copy operations
struct CopyFileHelper;

impl CopyFileHelper {
    /// Copies the contents of a source file to a destination file
    ///
    /// Uses platform-specific optimizations where available:
    /// - Linux: `copy_file_range` for zero-copy transfers, falls back to buffered copy if not supported
    /// - Other platforms: Buffered copy
    ///
    /// Note: This implementation is adapted from cap-std's `copy_impl` function:
    /// <https://github.com/bytecodealliance/cap-std/blob/main/cap-primitives/src/rustix/fs/copy_impl.rs>
    ///
    /// # Arguments
    ///
    /// * `src` - The source file
    /// * `dest` - The destination file
    ///
    /// # Returns
    ///
    /// * `Result<u64>` - The number of bytes copied
    #[cfg(target_os = "linux")]
    fn copy_file_impl(src: &File, dest: &File) -> Result<u64, RustSafeIoError> {
        Self::try_copy_file_range(src, dest)
    }

    #[cfg(not(target_os = "linux"))]
    fn copy_file_impl(src: &File, dest: &File) -> Result<u64, RustSafeIoError> {
        let len = src.metadata()?.len();
        Self::fallback_copy(src, dest, len)
    }

    #[cfg(target_os = "linux")]
    fn try_copy_file_range(src: &File, dest: &File) -> Result<u64, RustSafeIoError> {
        static HAS_COPY_FILE_RANGE: AtomicBool = AtomicBool::new(true);

        let len = src.metadata()?.len();

        let has_copy_file_range = HAS_COPY_FILE_RANGE.load(Ordering::Relaxed);
        let mut written = 0_u64;

        while written < len {
            let copy_result = if has_copy_file_range {
                let bytes_to_copy = cmp::min(len - written, usize::MAX as u64);

                let bytes_to_copy = usize::try_from(bytes_to_copy).unwrap_or(usize::MAX);

                let src_fd = src.as_fd();
                let dest_fd = dest.as_fd();
                let copy_result = copy_file_range(src_fd, None, dest_fd, None, bytes_to_copy);
                // Excluded: OS-dependent error paths that can't be reliably tested in the test enviroment
                // These handle cases like missing syscall support (NOSYS) and filesystem-specific errors.

                if let Err(rustix::io::Errno::NOSYS | rustix::io::Errno::PERM) = copy_result {
                    HAS_COPY_FILE_RANGE.store(false, Ordering::Relaxed);
                }
                copy_result
            } else {
                Err(rustix::io::Errno::NOSYS)
            };

            match copy_result {
                Ok(ret) => written += ret as u64,
                Err(err) => {
                    match err {
                        rustix::io::Errno::NOSYS
                        | rustix::io::Errno::XDEV
                        | rustix::io::Errno::INVAL
                        | rustix::io::Errno::PERM => {
                            // Fall back to standard copy if either:
                            // - Kernel version is < 4.5 (ENOSYS)
                            // - Files are mounted on different fs (EXDEV)
                            // - copy_file_range is disallowed, e.g., by seccomp (EPERM)
                            // - copy_file_range cannot be used with pipes or device nodes (EINVAL)
                            assert_eq!(written, 0);
                            return Self::fallback_copy(src, dest, len);
                        }
                        _ => {
                            return Err(RustSafeIoError::FileCopyError {
                                source: Box::new(err),
                            });
                        }
                    }
                }
            }
        }

        Ok(written)
    }

    /// Standard buffered copy implementation for when platform-specific optimizations fail or are unavailable
    #[allow(clippy::indexing_slicing)]
    fn fallback_copy(
        mut src: &File,
        mut dest: &File,
        max_bytes: u64,
    ) -> Result<u64, RustSafeIoError> {
        const BUFFER_SIZE: usize = 8 * 1024;
        let mut buffer = [0u8; BUFFER_SIZE];
        let mut copied = 0u64;

        while copied < max_bytes {
            let remaining = max_bytes - copied;
            let to_read = cmp::min(BUFFER_SIZE as u64, remaining);
            let to_read = usize::try_from(to_read).unwrap_or(BUFFER_SIZE);

            match src.read(&mut buffer[..to_read]) {
                Ok(0) => break,
                Ok(n) => {
                    {
                        dest.write_all(&buffer[..n])?;
                    }
                    copied += n as u64;
                }
                // Error handler for rare read failures that are difficult to simulate
                Err(e) => {
                    return Err(RustSafeIoError::FileReadError {
                        source: Box::new(e),
                    });
                }
            }
        }

        dest.flush()?;
        Ok(copied)
    }
}

#[cfg(test)]
#[cfg(target_os = "linux")] // We're only testing the linux-specific implementation here
mod tests {
    use super::*;
    use crate::options::READ_ONLY_FILE_OPTIONS;
    use crate::{DirConfig, DirHandle, FileHandle};
    use anyhow::Result;
    use cap_std::fs::Dir;
    use rex_test_utils::io::create_temp_dir_and_path;
    use std::rc::Rc;

    /// Given: A source file and a FIFO (named pipe) as destination
    /// When: Using copy_file_impl directly with a FIFO
    /// Then: The copy succeeds using the fallback copy mechanism
    #[test]
    fn test_copy_file_impl_with_fifo() -> Result<()> {
        let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

        let src_path = temp_dir.path().join("src.txt");
        let fifo_path = temp_dir.path().join("fifo");
        let test_content = "test content";
        std::fs::write(&src_path, test_content)?;

        std::process::Command::new("mkfifo")
            .arg(fifo_path.to_str().unwrap())
            .status()?;

        let fifo_path_clone = fifo_path.clone();
        let reader_thread = std::thread::spawn(move || {
            let mut buffer = vec![0u8; 1024];
            let mut file = std::fs::File::open(fifo_path_clone).unwrap();
            let bytes_read = file.read(&mut buffer).unwrap_or(0);
            buffer.truncate(bytes_read);
            String::from_utf8(buffer).unwrap()
        });

        let src_file = std::fs::File::open(&src_path)?;
        let src_file = cap_std::fs::File::from_std(src_file);

        let fifo_file = std::fs::OpenOptions::new().write(true).open(&fifo_path)?;
        let fifo_file = cap_std::fs::File::from_std(fifo_file);

        let rc_file_handle = RcFileHandle {
            file_handle: Rc::new(FileHandle {
                file: src_file,
                file_path: "src.txt".to_string(),
                resolved_path: None,
                dir_handle: Rc::new(DirHandle {
                    dir_config: DirConfig {
                        path: temp_dir_path.clone(),
                    },
                    dir: Dir::open_ambient_dir(temp_dir.path(), cap_std::ambient_authority())?,
                    basename: crate::get_basename(&temp_dir_path),
                }),
                open_options: READ_ONLY_FILE_OPTIONS,
            }),
        };

        let result = CopyFileHelper::copy_file_impl(&rc_file_handle.file_handle.file, &fifo_file);

        assert!(result.is_ok());

        let read_content = reader_thread.join().unwrap();

        assert_eq!(read_content, test_content);
        Ok(())
    }
}
