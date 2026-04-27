//! The rust safe IO module provides configuration options for file system operations
//!
//! Each struct implements a builder pattern with chainable methods for setting options
//! that are disabled by default

use crate::constants::error_constants::{
    DISK_USAGE_SUMMARIZE_ALL_FILES_ERR, INVALID_LENGTH, INVALID_READ_LINES_PAGINATION_COUNT_ERR,
    INVALID_START_LINE_ERR, SPECIAL_FILE_REQUIRES_WRITE_ERR,
};
use crate::error_constants::INVALID_OPEN_FILE_OPTIONS;
use crate::errors::RustSafeIoError;
use anyhow::Result;
use bytesize::ByteSize;
use cap_fs_ext::{FollowSymlinks, OpenOptions, OpenOptionsExt, OpenOptionsFollowExt};
use derive_builder::Builder;
use rust_sdk_common_utils::types::datetime::DateTime;

/// Configuration parameters for opening a directory
///
/// This struct is used to specify how a directory should be opened or created
///
/// # Arguments
///
/// * `create` - A bool [`OpenDirOptions::create`] indicating whether the create option is enabled. [`OpenDirOptions::create`] = true is used for creating directory, and [`OpenDirOptions::create`] = false  is used otherwise
/// * `recursive` - A bool [`OpenDirOptions::recursive`] that only applies when [`OpenDirOptions::create`] = true indicating whether recursive option is enabled. [`OpenDirOptions::recursive`] = true is used for creation of sub-directories, and [`OpenDirOptions::recursive`] = false is used otherwise
/// * `follow_symlinks` - A bool [`OpenDirOptions::follow_symlinks`] indicating whether to follow symbolic links when opening directories (default = false). The [`OpenDirOptions::create`] and [`OpenDirOptions::recursive`] options are ignored and the target directory must already exist
///
/// # Examples
///
/// ```no_run
/// use rust_safe_io::options::OpenDirOptionsBuilder;
///
/// let open_dir_options = OpenDirOptionsBuilder::default()
///     .create(true)
///     .recursive(true)
///     .build();
/// ```
#[derive(Builder, Debug, Clone, Copy)]
#[builder(derive(Debug), build_fn(error = RustSafeIoError))]
pub struct OpenDirOptions {
    #[builder(default = false)]
    pub create: bool,
    #[builder(default = false)]
    pub recursive: bool,
    #[builder(default = false)]
    pub follow_symlinks: bool,
}

/// Configuration parameters for deleting a directory
///
/// This struct is used to specify how a directory should be deleted
///
/// # Arguments
///
/// * `force` - A bool [`DeleteDirOptions::force`] indicating whether the force option is enabled. [`DeleteDirOptions::force`] = true is used for force deletion, and [`DeleteDirOptions::force`] = false  is used otherwise.
/// * `recursive` - A bool [`DeleteDirOptions::recursive`] indicating whether the recursive option is enabled. [`DeleteDirOptions::recursive`] = true is used for deletion of sub-directories, and [`OpenDirOptions::recursive`] = false is used otherwise.
///
/// # Examples
///
/// ```no_run
/// use rust_safe_io::options::DeleteDirOptionsBuilder;
///
/// let delete_dir_options = DeleteDirOptionsBuilder::default()
///     .force(true)
///     .recursive(true)
///     .build();
/// ```
#[derive(Builder, Debug, Clone, Copy)]
#[builder(derive(Debug))]
pub struct DeleteDirOptions {
    #[builder(default = false)]
    pub force: bool,
    #[builder(default = false)]
    pub recursive: bool,
}

/// Configuration parameters for opening a file
///
/// This struct is used to specify how a file should be opened. The flags on this struct generally correspond
/// to those on `cap_std::fs::OpenOptions`.
///
/// At least one of the options must be set to true when converting the `OpenFileOptions` to `OpenOptions`, otherwise
/// an error is returned.
///
/// # Clippy Allow Annotation
///
/// The `#[allow(clippy::struct_excessive_bools)]` annotation is required because this struct contains more than 3 boolean fields.
/// Clippy's `struct_excessive_bools` lint suggests replacing structs with many booleans with an enum, as it recognizes
/// multiple booleans as a potential state machine. However, this recommendation doesn't apply to builder option structs
/// like this one, where we need to support multiple independent combinations of parameters (e.g., `read + write`,
/// `create + write + permissions`, `read + follow_symlinks`, etc.). An enum would not provide the flexibility
/// needed for these orthogonal configuration options.
///
/// # Arguments
/// * `read` - - A bool [`OpenFileOptions::read`] indicating whether file is opened with read access (default = false).
/// * `write` - - A bool [`OpenFileOptions::write`] indicating whether file is opened with write access (default = false).
///   This flag is overridden to true if `create` is set.
/// * `create` - A bool [`OpenFileOptions::create`] indicating whether the create option is enabled (default = false).
///   Using the create option on an existing file will simply open the existing file.
///     * Note that setting the create option to true will also set the write option to true. This is because in Unix,
///       create requires the write open flag to be set, otherwise opening the file errors with "Invalid argument (os error 22)".
///       In the Rhai SDK however, create and write are distinct actions with separate permissions, so a script writer may
///       wonder why the write option is needed to create a file but the write permission isn't. To avoid this confusion,
///       we override the write option to true when the create option is set to true.
/// * `permissions` - An optional u32 [`OpenFileOptions::permissions`] specifying the file permissions to use when creating a file.
///   Only applies when [`OpenFileOptions::create`] = true and only on Unix systems. On Windows, this setting has no effect.
///   Default permission is effectively 0o644 (rw-r--r--) in most environments, derived from a base permission of 0o666 with the system's umask (typically 0o022) applied.
///   When using `.mode()` to set file permissions, the function only considers the last 9 bits (corresponding to 0o777) for regular file permissions.
///   Any permission bits beyond 0o777 in the provided value will be disregarded.
/// * `follow_symlinks` - A bool [`OpenFileOptions::follow_symlinks`] indicating whether to follow symbolic links when opening files (default = false).
/// * `special_file` - A bool [`OpenFileOptions::special_file`] indicating this is a special file (e.g., /proc/sys) where truncate/sync/rewind operations
///   should be skipped in `safe_write_in_place` (default = false). Only valid when `write = true`. Rejected by `safe_write` (atomic writes).
///   Special files are kernel-managed files that don't exist on disk - the kernel generates their content dynamically.
///
/// # Examples
///
/// ```no_run
/// use rust_safe_io::options::OpenFileOptionsBuilder;
///
/// let open_file_options = OpenFileOptionsBuilder::default()
///     .create(true)
///     .permissions(0o600)
///     .build();
/// ```
#[allow(clippy::struct_excessive_bools)]
#[derive(Builder, Debug, Clone, Copy)]
#[builder(derive(Debug), build_fn(validate = "Self::validate", error = RustSafeIoError))]
pub struct OpenFileOptions {
    #[builder(default = false)]
    pub read: bool,

    #[builder(default = false)]
    pub write: bool,

    #[builder(default = false, setter(custom))]
    pub create: bool,

    #[builder(default = None, setter(strip_option))]
    pub permissions: Option<i64>,

    #[builder(default = false)]
    pub follow_symlinks: bool,

    #[builder(default = false)]
    pub special_file: bool,
}

impl OpenFileOptionsBuilder {
    /// Custom create setter that overrides the write option when create is true.
    pub const fn create(&mut self, create: bool) -> &mut Self {
        self.create = Some(create);
        if create {
            self.write = Some(true);
        }
        self
    }

    /// Validate `special_file` requires write=true
    fn validate(&self) -> Result<(), String> {
        let write = self.write.unwrap_or(false);
        let special_file = self.special_file.unwrap_or(false);

        if special_file && !write {
            return Err(SPECIAL_FILE_REQUIRES_WRITE_ERR.to_string());
        }

        Ok(())
    }
}

impl OpenFileOptions {
    /// Convert the `OpenFileOptions` to `cap_std::fs::OpenOptions`. This will return an error
    /// if none of the flags on `OpenFileOptions` are set to true.
    pub(crate) fn to_cap_std_open_options(self) -> Result<OpenOptions, RustSafeIoError> {
        if !self.read && !self.write {
            return Err(RustSafeIoError::InvalidArguments {
                reason: INVALID_OPEN_FILE_OPTIONS.to_string(),
            });
        }

        let mut opts = OpenOptions::new();
        opts.read(self.read)
            .write(self.write)
            .create(self.create)
            .follow(FollowSymlinks::follow(self.follow_symlinks));

        #[cfg(unix)]
        if let Some(perms) = self.permissions {
            let safe_perms = perms & 0o777;
            opts.mode(u32::try_from(safe_perms)?);
        }

        Ok(opts)
    }
}

pub const READ_ONLY_FILE_OPTIONS: OpenFileOptions = OpenFileOptions {
    read: true,
    write: false,
    create: false,
    permissions: None,
    follow_symlinks: false,
    special_file: false,
};

/// Configuration parameters for text replacement operations in files.
///
/// This struct controls how text replacement is performed when using functions like `replace_text`.
/// It allows you to specify whether to use regex patterns, replace all occurrences or just the first one.
///
/// # Arguments
///
/// * `is_regex` - When true, interprets search string as regex pattern, otherwise it's treated as literal text. Default: false.
/// * `replace_all` - When true, replaces all occurrences, otherwise, only the first occurence is replaced. Default: false.
///
/// /// # Examples
///
/// Using the builder pattern (recommended):
///
/// ```no_run
/// use rust_safe_io::options::ReplacementOptionsBuilder;
///
/// // Replace all occurrences using regex pattern
/// let regex_options = ReplacementOptionsBuilder::default()
///     .is_regex(true)
///     .replace_all(true)
///     .build()
///     .unwrap();
///
/// // Replace only first occurrence using literal string
/// let literal_options = ReplacementOptionsBuilder::default()
///     .is_regex(false)
///     .replace_all(false)
///     .build()
///     .unwrap();
/// ```
///
/// Direct struct initialization (not recommended):
///
/// ```no_run
/// use rust_safe_io::options::ReplacementOptions;
///
/// let options = ReplacementOptions {
///     is_regex: true,
///     replace_all: true,
/// };
/// ```
#[derive(Builder, Debug, Clone, Copy)]
#[builder(derive(Debug))]
pub struct ReplacementOptions {
    #[builder(default = false)]
    pub is_regex: bool,
    #[builder(default = false)]
    pub replace_all: bool,
}

/// Configuration parameters for deleting a file
///
/// This struct is used to specify how a file should be deleted
///
/// # Arguments
///
/// * `force` - A bool [`DeleteFileOptions::force`] indicating whether the force option is enabled. [`DeleteFileOptions::force`] = true is used for force deletion, and [`DeleteFileOptions::force`] = false  is used otherwise
///
/// # Examples
///
/// ```no_run
/// use rust_safe_io::options::DeleteFileOptionsBuilder;
///
/// let delete_file_options = DeleteFileOptionsBuilder::default()
///     .force(true)
///     .build();
/// ```
#[derive(Builder, Debug, Clone, Copy)]
#[builder(derive(Debug))]
pub struct DeleteFileOptions {
    #[builder(default = false)]
    pub force: bool,
}

/// Configuration parameters for changing directory permissions
///
/// This struct is used to specify how directory permissions should be changed
///
/// # Arguments
///
/// * `permissions` - A u32 [`ChmodDirOptions::permissions`] specifying the octal directory permissions (e.g., 0o755 for rwxr-xr-x)
/// * `recursive` - A bool [`ChmodDirOptions::recursive`] indicating whether the recursive option is enabled. [`ChmodDirOptions::recursive`] = true is used for chmoding of sub-directories.
///
/// # Examples
///
/// ```no_run
/// use rust_safe_io::options::ChmodDirOptionsBuilder;
///
/// let chmod_dir_options = ChmodDirOptionsBuilder::default()
///     .permissions(0o755)
///     .recursive(true)
///     .build()
///     .unwrap();
/// ```
#[derive(Builder, Debug, Clone, Copy)]
#[builder(derive(Debug))]
pub struct ChmodDirOptions {
    pub permissions: i64,
    #[builder(default = "false")]
    pub recursive: bool,
}

/// # Arguments
///
/// * 'backup' - A bool [`MoveOptions::backup`] only for move file operations specifying whether to backup the destination file, if it exists, with the same name as the source file
/// * 'verbose' - a bool [`MoveOptions::verbose`] indicating whether to log src file/dir and dest file/dir after a move is successfully completed.
///
/// # Examples
///
/// ```no_run
/// use rust_safe_io::options::MoveOptionsBuilder;
///
/// let move_options = MoveOptionsBuilder::default()
///     .backup(true)
///     .build()
///     .unwrap();
/// ```
#[derive(Builder, Debug, Clone, Copy)]
#[builder(derive(Debug))]
pub struct MoveOptions {
    #[builder(default = false)]
    // only for move file operations specifying whether to backup the destination file, if it exists, with the same name as the source file
    pub backup: bool,
    #[builder(default = false)]
    // indicating whether to log src file/dir and dest file/dir after a move is successfully completed.
    pub verbose: bool,
}

/// Configuration parameters for setting ownership of files and directories
///
/// This struct is used to specify how ownership should be changed
///
/// # Arguments
///
/// * `user` - An optional String [`SetOwnershipOptions::user`] specifying the new owner username
/// * `group` - An optional String [`SetOwnershipOptions::group`] specifying the new group name
/// * `recursive` - A bool [`SetOwnershipOptions::recursive`] indicating whether to recursively change ownership of directory contents (default = false)
///
/// # Examples
///
/// ```no_run
/// use rust_safe_io::options::SetOwnershipOptionsBuilder;
///
/// let set_ownership_options = SetOwnershipOptionsBuilder::default()
///     .user("newuser".to_string())
///     .group("newgroup".to_string())
///     .recursive(true)
///     .build()
///     .unwrap();
/// ```
#[derive(Builder, Debug, Clone)]
#[builder(derive(Debug))]
pub struct SetOwnershipOptions {
    #[builder(setter(into, strip_option), default)]
    pub user: Option<String>,
    #[builder(setter(into, strip_option), default)]
    pub group: Option<String>,
    #[builder(default = "false")]
    pub recursive: bool,
}

/// Configuration parameters for reading files
///
/// This struct is used to specify how files should be read using one of three modes:
/// - Read the first N lines
/// - Read the last N lines  
/// - Read from a specific line number to the end
///
/// Only one mode can be active at a time.
///
/// Note that the start option is 1-indexed. See [`crate::file::RcFileHandle::safe_read_lines`] for more information.
///
/// # Examples
///
/// ```no_run
/// use rust_safe_io::options::ReadLinesOptionsBuilder;
///
/// // Read first 10 lines
/// let read_first = ReadLinesOptionsBuilder::default()
///     .count(10)
///     .build()
///     .unwrap();
///
/// // Read last 10 lines
/// let read_last = ReadLinesOptionsBuilder::default()
///     .count(-10)
///     .build()
///     .unwrap();
///
/// // Read from line 20 to end
/// let read_from = ReadLinesOptionsBuilder::default()
///     .start(20)
///     .build()
///     .unwrap();
/// ```
#[derive(Builder, Debug, Clone, Copy)]
#[builder(derive(Debug), build_fn(validate = "Self::validate", error = RustSafeIoError))]
pub struct ReadLinesOptions {
    /// Number of lines to read.
    /// - Positive value = read first N lines (head)
    /// - Negative value = read last N lines (tail)
    #[builder(default, setter(strip_option))]
    pub count: Option<isize>,

    /// Start reading from this line number (1-indexed).
    #[builder(default, setter(strip_option))]
    pub start: Option<usize>,
}

impl ReadLinesOptionsBuilder {
    fn validate(&self) -> Result<(), String> {
        if let Some(Some(start)) = &self.start
            && *start < 1
        {
            return Err(format!("{INVALID_START_LINE_ERR}: {start}"))?;
        }
        Ok(())
    }
}

/// Configuration parameters for copying a file
///
/// This struct is used to specify how a file should be copied
///
/// # Arguments
///
/// * `force` - A bool [`CopyFileOptions::force`] indicating whether to overwrite the destination file if it exists (default: false)
/// * `preserve` - A bool [`CopyFileOptions::preserve`] indicating whether to preserve file timestamps and permissions during copy (default: false)
///
/// # Examples
///
/// ```no_run
/// # use rust_safe_io::{DirConfigBuilder, options::{OpenDirOptionsBuilder, OpenFileOptionsBuilder, CopyFileOptionsBuilder}};
/// # use rex_cedar_auth::cedar_auth::CedarAuth;
/// #
/// let cedar_auth = CedarAuth::new("", "", "").unwrap().0;
///
/// let dir_config = DirConfigBuilder::default()
///     .path("/tmp".to_string())
///     .build().unwrap();
/// let dir_handle = dir_config.safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap()).unwrap();
///
/// let dest_file = dir_handle.safe_open_file(
///     &cedar_auth,
///     "dest.txt",
///     OpenFileOptionsBuilder::default().create(true).build().unwrap()
/// ).unwrap();
///
/// let copy_file_options = CopyFileOptionsBuilder::default()
///     .force(true)
///     .preserve(true)
///     .build()
///     .unwrap();
/// ```
#[derive(Builder, Debug, Clone, Copy)]
#[builder(derive(Debug))]
pub struct CopyFileOptions {
    #[builder(default = false)]
    pub force: bool,
    #[builder(default = false)]
    pub preserve: bool,
}

/// Configuration parameters for atomic file writes.
///
/// # Arguments
///
/// * `preserve_ownership` - A bool [`WriteOptions::preserve_ownership`] indicating whether to attempt to preserve
///   the original file's ownership (uid/gid) after the atomic write (default = true). When true, the temp file is
///   chowned to the original file's owner before the rename. Requires `CAP_CHOWN` when the file is owned by a
///   different user. When false, the file will be owned by the current user and group.
///
/// # Examples
///
/// ```no_run
/// use rust_safe_io::options::WriteOptionsBuilder;
///
/// let options = WriteOptionsBuilder::default()
///     .preserve_ownership(false)
///     .build()
///     .unwrap();
/// ```
#[derive(Builder, Debug, Clone, Copy, Default)]
#[builder(derive(Debug), build_fn(error = RustSafeIoError))]
pub struct WriteOptions {
    #[builder(default = true)]
    pub preserve_ownership: bool,
}

/// Configuration parameters for archive extraction
///
/// This struct is used to specify how archives should be extracted, controlling whether
/// to preserve file attributes from the original archive.
///
/// # Arguments
///
/// * `preserve_permissions` - A bool [`ExtractArchiveOptions::preserve_permissions`] indicating whether to preserve file permissions from the archive (default = true).
///   When true, extracted files and directories will maintain their original permission modes. When false, files will use default system permissions.
/// * `preserve_ownership` - A bool [`ExtractArchiveOptions::preserve_ownership`] indicating whether to preserve file ownership from the archive (default = false).
///   When true, extracted files and directories will attempt to maintain their original user and group ownership. This may require elevated privileges.
/// * `preserve_timestamps` - A bool [`ExtractArchiveOptions::preserve_timestamps`] indicating whether to preserve file modification times from the archive (default = true).
///   When true, extracted files and directories will maintain their original modification timestamps. When false, files will use current extraction time.
///
/// # Examples
///
/// ```no_run
/// use rust_safe_io::options::ExtractArchiveOptionsBuilder;
///
/// // Extract with all preservation options enabled
/// let full_preserve_options = ExtractArchiveOptionsBuilder::default()
///     .preserve_permissions(true)
///     .preserve_ownership(true)
///     .preserve_timestamps(true)
///     .build()
///     .unwrap();
/// ```
#[allow(clippy::struct_excessive_bools)]
#[derive(Builder, Debug, Clone, Copy)]
#[allow(clippy::struct_field_names)]
#[builder(derive(Debug))]
pub struct ExtractArchiveOptions {
    #[builder(default = "true")]
    pub preserve_permissions: bool,

    #[builder(default = "false")]
    pub preserve_ownership: bool,

    #[builder(default = "true")]
    pub preserve_timestamps: bool,
}

/// Configuration parameters for creating symbolic links
///
/// This struct is used to specify how symbolic links should be created
///
/// # Arguments
///
/// * `force` - A bool [`CreateSymlinkOptions::force`] indicating whether to force overwrite existing files at the symlink location (default = false).
///   When true, any existing file at the link location will be atomically replaced. When false, creation will fail if a file already exists at the target location.
///
/// # Examples
///
/// ```no_run
/// use rust_safe_io::options::CreateSymlinkOptionsBuilder;
///
/// // Create symlink with force overwrite enabled
/// let force_options = CreateSymlinkOptionsBuilder::default()
///     .force(true)
///     .build()
///     .unwrap();
/// ```
#[derive(Builder, Debug, Clone, Copy)]
#[builder(derive(Debug))]
pub struct CreateSymlinkOptions {
    #[builder(default = "false")]
    pub force: bool,
}

/// Configuration parameters for finding files and directories
///
/// This struct is used to specify search criteria when finding files and directories.
///
/// # Examples
///
/// ```no_run
/// use rust_safe_io::options::{FindOptionsBuilder, SizeRange, SizeUnit};
///
/// // Find all .txt files
/// let txt_options = FindOptionsBuilder::default()
///     .name("*.txt".to_string())
///     .build()
///     .unwrap();
///
/// // Find files larger than 1MB, case-insensitive pattern
/// let large_files = FindOptionsBuilder::default()
///     .iname("*.log".to_string())
///     .size_range(SizeRange::min_only(1, SizeUnit::Megabytes))
///     .build()
///     .unwrap();
///
/// // Find files following symlinks
/// let follow_links = FindOptionsBuilder::default()
///     .name("*.txt".to_string())
///     .follow_symlinks(true)
///     .build()
///     .unwrap();
/// ```
#[derive(Builder, Default, Debug, Clone)]
#[builder(
    derive(Debug),
    default,
    build_fn(error = "RustSafeIoError", validate = "Self::validate")
)]
pub struct FindOptions {
    // Case sensitive glob pattern matching for matching file/directory names
    #[builder(setter(into, strip_option), default)]
    pub name: Option<String>,

    // Case insensitive glob pattern matching for matching file/directory names
    #[builder(setter(into, strip_option), default)]
    pub iname: Option<String>,

    // Regex pattern matching for matching file/directory names
    #[builder(setter(into, strip_option), default)]
    pub regex: Option<String>,

    // negate the `name` or `iname` pattern
    #[builder(default)]
    pub negate_name: bool,

    // Filter files by size with optional minimum/maximum bounds and configurable units
    #[builder(setter(strip_option), default)]
    pub size_range: Option<SizeRange>,

    // Minimum directory depth to include in search results
    #[builder(default = 0)]
    pub min_depth: i64,

    // Maximum directory depth to include in search results
    #[builder(default = i64::MAX)]
    pub max_depth: i64,

    // Minimum creation time
    #[builder(setter(strip_option), default)]
    pub min_creation_time: Option<DateTime>,

    // Maximum creation time
    #[builder(setter(strip_option), default)]
    pub max_creation_time: Option<DateTime>,

    // Minimum last modification time
    #[builder(setter(strip_option), default)]
    pub min_modification_time: Option<DateTime>,

    // Maximum last modification time
    #[builder(setter(strip_option), default)]
    pub max_modification_time: Option<DateTime>,

    // Follow symbolic links during traversal
    #[builder(default = false)]
    pub follow_symlinks: bool,
}

/// Represents a size range with minimum and maximum bounds
///
/// This struct defines optional minimum and maximum size thresholds with configurable units.
#[derive(Debug, Clone, Copy)]
pub struct SizeRange {
    pub min: Option<i64>,
    pub max: Option<i64>,
    pub unit: SizeUnit,
}

impl SizeRange {
    pub const fn min_only(min: i64, unit: SizeUnit) -> Self {
        Self {
            min: Some(min),
            max: None,
            unit,
        }
    }

    pub const fn max_only(max: i64, unit: SizeUnit) -> Self {
        Self {
            min: None,
            max: Some(max),
            unit,
        }
    }

    pub const fn between(min: i64, max: i64, unit: SizeUnit) -> Self {
        Self {
            min: Some(min),
            max: Some(max),
            unit,
        }
    }

    pub fn min_bytes(&self) -> Option<i64> {
        self.min.map(|min| self.unit.to_bytes(min))
    }

    pub fn max_bytes(&self) -> Option<i64> {
        self.max.map(|max| self.unit.to_bytes(max))
    }

    pub fn matches(&self, file_size_bytes: i64) -> bool {
        if let Some(min) = self.min_bytes()
            && file_size_bytes < min
        {
            return false;
        }
        if let Some(max) = self.max_bytes()
            && file_size_bytes > max
        {
            return false;
        }
        true
    }
}

/// Size units for file operations and measurements
///
/// This enum provides different units for specifying file sizes. It includes both
/// decimal (base-10) and binary (base-2) units:
///
/// **Decimal units (base-10):**
/// - 1 kilobyte (KB) = 1,000 bytes
/// - 1 megabyte (MB) = 1,000,000 bytes  
/// - 1 gigabyte (GB) = 1,000,000,000 bytes
///
/// **Binary units (base-2):**
/// - 1 kibibyte (KiB) = 1,024 bytes
/// - 1 mebibyte (MiB) = 1,048,576 bytes
/// - 1 gibibyte (GiB) = 1,073,741,824 bytes
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum SizeUnit {
    Bytes,
    Kilobytes,
    Kibibytes,
    Megabytes,
    Mebibytes,
    Gigabytes,
    Gibibytes,
}

#[allow(clippy::cast_possible_wrap)]
#[allow(clippy::cast_sign_loss)]
impl SizeUnit {
    pub const fn to_bytes(self, value: i64) -> i64 {
        let u64_value = value as u64;

        match self {
            SizeUnit::Bytes => value,
            SizeUnit::Kilobytes => ByteSize::kb(u64_value).as_u64() as i64,
            SizeUnit::Kibibytes => ByteSize::kib(u64_value).as_u64() as i64,
            SizeUnit::Megabytes => ByteSize::mb(u64_value).as_u64() as i64,
            SizeUnit::Mebibytes => ByteSize::mib(u64_value).as_u64() as i64,
            SizeUnit::Gigabytes => ByteSize::gb(u64_value).as_u64() as i64,
            SizeUnit::Gibibytes => ByteSize::gib(u64_value).as_u64() as i64,
        }
    }
}

impl FindOptionsBuilder {
    fn validate(&self) -> Result<(), RustSafeIoError> {
        let has_name = self.name.as_ref().and_then(|opt| opt.as_ref()).is_some();
        let has_i_name = self.iname.as_ref().and_then(|opt| opt.as_ref()).is_some();
        let has_regex = self.regex.as_ref().and_then(|opt| opt.as_ref()).is_some();

        let pattern_count = [has_name, has_i_name, has_regex]
            .iter()
            .filter(|&&x| x)
            .count();

        if pattern_count > 1 {
            return Err(RustSafeIoError::ValidationError {
                reason: "Only one of 'name', 'iname', or 'regex' can be specified".to_string(),
            });
        }

        let negate_name = self.negate_name.unwrap_or(false);
        if negate_name && !has_name && !has_i_name {
            return Err(RustSafeIoError::ValidationError {
                reason: "negate_name can only be used with 'name' or 'iname' patterns".to_string(),
            });
        }

        if let Some(Some(size_range)) = self.size_range.as_ref() {
            if let Some(min) = size_range.min
                && min < 0
            {
                return Err(RustSafeIoError::ValidationError {
                    reason: "Size range minimum must be non-negative".to_string(),
                });
            }
            if let Some(max) = size_range.max
                && max < 0
            {
                return Err(RustSafeIoError::ValidationError {
                    reason: "Size range maximum must be non-negative".to_string(),
                });
            }
        }

        Ok(())
    }
}

/// Configuration parameters for directory tree traversal
///
/// # Examples
///
/// ```no_run
/// use rust_safe_io::options::DirWalkOptionsBuilder;
///
///
/// let unlimited_options = DirWalkOptionsBuilder::default()
///     .build()
///     .unwrap();
///
/// // Skip root and immediate children then traverse up to 5 levels deep
/// let limited_options = DirWalkOptionsBuilder::default()
///     .min_depth(2)
///     .max_depth(5)
///     .build()
///     .unwrap();
///
/// // Only traverse immediate children
/// let shallow_options = DirWalkOptionsBuilder::default()
///     .max_depth(1)
///     .build()
///     .unwrap();
/// ```
#[derive(Builder, Debug, Clone, Copy)]
#[builder(default, build_fn(error = RustSafeIoError))]
pub struct DirWalkOptions {
    #[builder(default = "0")]
    pub min_depth: usize,

    #[builder(default = "usize::MAX")]
    pub max_depth: usize,

    #[builder(default = "false")]
    pub follow_symlinks: bool,

    #[builder(default = "false")]
    pub skip_visited_inodes: bool,
}

impl Default for DirWalkOptions {
    fn default() -> Self {
        Self {
            min_depth: 0,
            max_depth: usize::MAX,
            follow_symlinks: false,
            skip_visited_inodes: false,
        }
    }
}

/// Configuration parameters for reading a page of lines from a file
///
/// # Examples
///
/// ```no_run
/// # use rust_safe_io::options::ReadPageOptionsBuilder;
/// #
/// // Read a page of 100 lines
/// let page_options = ReadPageOptionsBuilder::default()
///     .num_lines(100)
///     .build()
///     .unwrap();
/// ```
#[derive(Builder, Debug, Clone, Copy)]
#[builder(derive(Debug), build_fn(validate = "Self::validate", error = RustSafeIoError))]
pub struct ReadPageOptions {
    pub num_lines: usize,
}

impl ReadPageOptionsBuilder {
    fn validate(&self) -> Result<(), String> {
        if let Some(num_lines) = &self.num_lines
            && *num_lines == 0
        {
            return Err(format!(
                "{INVALID_READ_LINES_PAGINATION_COUNT_ERR}: {num_lines}"
            ))?;
        }
        Ok(())
    }
}

/// Configuration parameters for disk usage calculations
///
/// This struct supports common `du` command flags used in Dynamic Action scripts.
///
/// # Arguments
///
/// * `summarize` - A bool [`DiskUsageOptions::summarize`] indicating whether to summarize (return total size only) (default = false)
/// * `all_files` - A bool [`DiskUsageOptions::all_files`] indicating whether to include all files, not just directories. Cannot be used with [`DiskUsageOptions::summarize`]. (default = false)
/// * `one_file_system` - A bool [`DiskUsageOptions::one_file_system`] indicating whether to stay on one filesystem/don't cross mount points (default = false)
/// * `count_hard_links` - A bool [`DiskUsageOptions::count_hard_links`] indicating whether to count hard links separately (default = false)
/// * `apparent_size` - A bool [`DiskUsageOptions::apparent_size`] indicating whether to use file size instead of allocated blocks (default = false)
/// * `max_depth` - A usize [`DiskUsageOptions::max_depth`] specifying the maximum recursion depth (default = `usize::MAX` for unlimited)
/// * `track_largest_subdir` - A bool [`DiskUsageOptions::track_largest_subdir`] indicating whether to keep a file descriptor to the largest subdirectory [`crate::DiskUsageResult::largest_subdir_handle`] for TOCTOU safe operations. Root directory is excluded from tracking. (default = false)
///
/// # Examples
///
/// ```no_run
/// use rust_safe_io::options::DiskUsageOptionsBuilder;
///
/// let options = DiskUsageOptionsBuilder::default()
///     .summarize(true)
///     .build()
///     .unwrap();
/// ```
#[allow(clippy::struct_excessive_bools)]
#[derive(Builder, Debug, Clone, Copy)]
#[builder(derive(Debug), build_fn(validate = "Self::validate", error = RustSafeIoError))]
pub struct DiskUsageOptions {
    #[builder(default = "false")]
    pub summarize: bool,

    #[builder(default = "false")]
    pub all_files: bool,

    #[builder(default = "false")]
    pub one_file_system: bool,

    #[builder(default = "false")]
    pub count_hard_links: bool,

    #[builder(default = "false")]
    pub apparent_size: bool,

    #[builder(default = "i64::MAX")]
    pub max_depth: i64,

    #[builder(default = "false")]
    pub track_largest_subdir: bool,
}

impl DiskUsageOptionsBuilder {
    fn validate(&self) -> Result<(), RustSafeIoError> {
        let summarize = self.summarize.unwrap_or(false);
        let all_files = self.all_files.unwrap_or(false);

        if summarize && all_files {
            return Err(RustSafeIoError::ValidationError {
                reason: DISK_USAGE_SUMMARIZE_ALL_FILES_ERR.to_string(),
            });
        }

        Ok(())
    }
}

/// Configuration parameters for preallocating disk space for a file.
///
/// # Examples
///
/// ```ignore
/// # use rust_safe_io::DiskAllocationOptionsBuilder;
/// # use rust_safe_io::options::SizeUnit;
///
/// // Preallocate 10 GB
/// let options = DiskAllocationOptionsBuilder::default()
///     .length(10)
///     .format(SizeUnit::Gigabytes)
///     .build()
///     .unwrap();
///
/// // Preallocate 1 MB (using default Bytes unit)
/// let options = DiskAllocationOptionsBuilder::default()
///     .length(1048576)
///     .build()
///     .unwrap();
/// ```
#[derive(Builder, Debug, Clone, Copy)]
#[builder(derive(Debug), build_fn(error = RustSafeIoError, validate = "Self::validate"))]
pub struct DiskAllocationOptions {
    /// Length of space to allocate.
    pub length: i64,

    /// Unit for length value. Default: `SizeUnit::Bytes`.
    #[builder(default = SizeUnit::Bytes)]
    pub format: SizeUnit,
}

impl DiskAllocationOptionsBuilder {
    fn validate(&self) -> Result<(), RustSafeIoError> {
        if let Some(length) = &self.length
            && *length <= 0
        {
            return Err(RustSafeIoError::ValidationError {
                reason: INVALID_LENGTH.to_string(),
            });
        }
        Ok(())
    }
}

/// Configuration parameters for gzip compression
///
/// This struct is used to specify compression settings when using the gzip compress function.
///
/// # Arguments
///
/// * `level` - Compression level from 1-9 (1=fastest, 9=best compression, default=6)
///
/// # Examples
///
/// ```no_run
/// use rust_safe_io::options::CompressGzipOptionsBuilder;
///
/// // Fast compression (level 1)
/// let fast_options = CompressGzipOptionsBuilder::default()
///     .level(1)
///     .build()
///     .unwrap();
///
/// // Best compression (level 9)
/// let best_options = CompressGzipOptionsBuilder::default()
///     .level(9)
///     .build()
///     .unwrap();
///
/// // Default balanced compression (level 6)
/// let default_options = CompressGzipOptionsBuilder::default()
///     .build()
///     .unwrap();
/// ```
#[derive(Builder, Debug, Clone, Copy)]
#[builder(derive(Debug), build_fn(validate = "Self::validate", error = RustSafeIoError))]
pub struct CompressGzipOptions {
    #[builder(default = "6")]
    pub level: u32,
}

impl CompressGzipOptionsBuilder {
    fn validate(&self) -> Result<(), RustSafeIoError> {
        if let Some(level) = self.level
            && !(1..=9).contains(&level)
        {
            return Err(RustSafeIoError::ValidationError {
                reason: format!("Compression level must be between 1 and 9, got {level}"),
            });
        }
        Ok(())
    }
}

/// Options for searching gzipped files with filtering capabilities.
///
/// # Examples
///
/// ```no_run
/// use rust_safe_io::options::SearchGzipOptionsBuilder;
///
/// // Basic search with exclude pattern
/// let options = SearchGzipOptionsBuilder::default()
///     .exclude_pattern("debug".to_string())
///     .build()
///     .unwrap();
///
/// // Case insensitive search with result limit
/// let options = SearchGzipOptionsBuilder::default()
///     .case_insensitive(true)
///     .max_results(100)
///     .build()
///     .unwrap();
/// ```
#[derive(Builder, Debug, Clone, Default)]
#[builder(derive(Debug), default)]
pub struct SearchGzipOptions {
    /// Exclude lines matching this regex pattern (grep -v equivalent).
    /// Applied AFTER the main pattern match.
    #[builder(setter(into, strip_option), default)]
    pub exclude_pattern: Option<String>,

    /// Case insensitive matching for the main pattern (grep -i equivalent).
    #[builder(default = "false")]
    pub case_insensitive: bool,

    /// Maximum results to return.
    /// - Positive value = return first N matches (head)
    /// - Negative value = return last N matches (tail)
    /// - 0 = return all matches (default)
    #[builder(default = "0")]
    pub max_results: isize,
}

/// Configuration parameters for setting extended attributes on files
///
/// This struct is used to specify the extended attribute name and `SELinux` context
///
/// # Arguments
///
/// * `name` - A String [`SetXAttrOptions::name`] specifying the extended attribute name (e.g., "user.comment")
/// * `selinux_type` - An optional String [`SetXAttrOptions::selinux_type`] specifying the `SELinux` type
/// * `selinux_user` - An optional String [`SetXAttrOptions::selinux_user`] specifying the `SELinux` user
/// * `selinux_role` - An optional String [`SetXAttrOptions::selinux_role`] specifying the `SELinux` role
/// * `selinux_level` - An optional String [`SetXAttrOptions::selinux_level`] specifying the `SELinux` level (MLS/MCS security level)
///
/// # Examples
///
/// ```no_run
/// use rust_safe_io::options::SetXAttrOptionsBuilder;
///
/// let setxattr_options = SetXAttrOptionsBuilder::default()
///     .name("user.comment".to_string())
///     .selinux_type("text".to_string())
///     .build()
///     .unwrap();
///
/// // With full SELinux context
/// let setxattr_options_full = SetXAttrOptionsBuilder::default()
///     .name("security.selinux".to_string())
///     .selinux_type("httpd_sys_content_t".to_string())
///     .selinux_user("system_u".to_string())
///     .selinux_role("object_r".to_string())
///     .selinux_level("s0".to_string())
///     .build()
///     .unwrap();
/// ```
#[derive(Builder, Debug, Clone)]
#[builder(derive(Debug))]
pub struct SetXAttrOptions {
    pub name: String,
    #[builder(setter(into, strip_option), default)]
    pub selinux_type: Option<String>,
    #[builder(setter(into, strip_option), default)]
    pub selinux_user: Option<String>,
    #[builder(setter(into, strip_option), default)]
    pub selinux_role: Option<String>,
    #[builder(setter(into, strip_option), default)]
    pub selinux_level: Option<String>,
}

#[cfg(test)]
mod tests {
    use crate::error_constants::{
        DISK_USAGE_SUMMARIZE_ALL_FILES_ERR, INVALID_OPEN_FILE_OPTIONS,
        INVALID_READ_LINES_PAGINATION_COUNT_ERR, INVALID_START_LINE_ERR,
    };
    use crate::options::{FindOptionsBuilder, ReadLinesOptionsBuilder, ReadPageOptionsBuilder};
    use crate::options::{SizeRange, SizeUnit};
    use anyhow::{Ok, Result};
    use rex_test_utils::assertions::assert_error_contains;

    // We can't unit test positive test cases here because `OpenOptions` accessors are all crate-private.
    // We test the various open options in integration tests.

    /// Given: `OpenFileOptions` where all option flags are false
    /// When: `to_cap_std_open_options` is called
    /// Then: an error is thrown
    #[test]
    fn open_file_options_to_cap_std_open_options_error_when_all_flags_are_false() -> Result<()> {
        use crate::options::OpenFileOptionsBuilder;

        let result = OpenFileOptionsBuilder::default()
            .build()?
            .to_cap_std_open_options();
        assert_error_contains(result, INVALID_OPEN_FILE_OPTIONS);

        Ok(())
    }

    /// Given: Different SizeUnit variants with known values
    /// When: `to_bytes` is called on each variant
    /// Then: The correct byte conversion is returned for each unit type
    #[test]
    fn unit_to_bytes_conversions() -> Result<()> {
        assert_eq!(SizeUnit::Bytes.to_bytes(100), 100);
        assert_eq!(SizeUnit::Kilobytes.to_bytes(1), 1000);
        assert_eq!(SizeUnit::Kibibytes.to_bytes(1), 1024);
        assert_eq!(SizeUnit::Megabytes.to_bytes(1), 1_000_000);
        assert_eq!(SizeUnit::Mebibytes.to_bytes(1), 1_048_576);
        assert_eq!(SizeUnit::Gigabytes.to_bytes(1), 1_000_000_000);
        assert_eq!(SizeUnit::Gibibytes.to_bytes(1), 1_073_741_824);

        Ok(())
    }

    /// Given: FindOptionsBuilder with invalid configurations
    /// When: `build` is called with validation errors
    /// Then: Appropriate validation errors are returned
    #[test]
    fn find_options_builder_validation() -> Result<()> {
        let result = FindOptionsBuilder::default()
            .name("*.txt".to_string())
            .iname("*.log".to_string())
            .build();
        assert_error_contains(
            result,
            "Only one of 'name', 'iname', or 'regex' can be specified",
        );

        let result = FindOptionsBuilder::default().negate_name(true).build();
        assert_error_contains(
            result,
            "negate_name can only be used with 'name' or 'iname' patterns",
        );

        let result = FindOptionsBuilder::default()
            .regex(".*\\.txt$".to_string())
            .negate_name(true)
            .build();
        assert_error_contains(
            result,
            "negate_name can only be used with 'name' or 'iname' patterns",
        );

        let invalid_min = SizeRange::min_only(-100, SizeUnit::Bytes);

        let result = FindOptionsBuilder::default()
            .size_range(invalid_min)
            .build();

        assert_error_contains(result, "Size range minimum must be non-negative");

        let invalid_max = SizeRange::max_only(-100, SizeUnit::Bytes);
        let result = FindOptionsBuilder::default()
            .size_range(invalid_max)
            .build();

        assert_error_contains(result, "Size range maximum must be non-negative");

        Ok(())
    }

    /// Given: ReadLinesOptionsBuilder with invalid start line (zero)
    /// When: `build` is called with validation errors
    /// Then: Appropriate validation errors are returned
    #[test]
    fn read_lines_options_invalid_start_line() -> Result<()> {
        let result = ReadLinesOptionsBuilder::default().start(0).build();
        assert_error_contains(result, INVALID_START_LINE_ERR);

        Ok(())
    }

    /// Given: ReadPageOptionsBuilder with valid num_lines
    /// When: `build` is called
    /// Then: validation succeeds
    #[test]
    fn read_page_options_valid_num_lines() -> Result<()> {
        let result = ReadPageOptionsBuilder::default().num_lines(5).build();
        assert!(result.is_ok());
        Ok(())
    }

    /// Given: ReadPageOptionsBuilder with invalid num_lines (zero)
    /// When: `build` is called
    /// Then: Appropriate validation errors are returned
    #[test]
    fn read_page_options_invalid_num_lines() -> Result<()> {
        let result = ReadPageOptionsBuilder::default().num_lines(0).build();
        assert_error_contains(result, INVALID_READ_LINES_PAGINATION_COUNT_ERR);

        Ok(())
    }

    /// Given: ReadPageOptionsBuilder with missing num_lines
    /// When: `build` is called
    /// Then: Appropriate validation errors are returned
    #[test]
    fn read_page_options_missing_num_lines() -> Result<()> {
        let result = ReadPageOptionsBuilder::default().build();
        assert!(result.is_err());
        Ok(())
    }

    /// Given: DiskUsageOptionsBuilder with both summarize and all_files set to true
    /// When: `build` is called
    /// Then: A validation error is returned (matches GNU du behavior)
    #[test]
    fn disk_usage_options_summarize_and_all_files_incompatible() -> Result<()> {
        use crate::options::DiskUsageOptionsBuilder;

        let result = DiskUsageOptionsBuilder::default()
            .summarize(true)
            .all_files(true)
            .build();

        assert_error_contains(result, DISK_USAGE_SUMMARIZE_ALL_FILES_ERR);

        Ok(())
    }

    /// Given: OpenFileOptionsBuilder with special_file=true and write=false
    /// When: `build` is called
    /// Then: A validation error is returned
    #[test]
    fn open_file_options_special_file_requires_write() -> Result<()> {
        use crate::error_constants::SPECIAL_FILE_REQUIRES_WRITE_ERR;
        use crate::options::OpenFileOptionsBuilder;

        let result = OpenFileOptionsBuilder::default().special_file(true).build();

        assert_error_contains(result, SPECIAL_FILE_REQUIRES_WRITE_ERR);

        Ok(())
    }

    /// Given: OpenFileOptionsBuilder with special_file=true and write=true
    /// When: `build` is called
    /// Then: Build succeeds
    #[test]
    fn open_file_options_special_file_with_write_succeeds() -> Result<()> {
        use crate::options::OpenFileOptionsBuilder;

        let result = OpenFileOptionsBuilder::default()
            .write(true)
            .special_file(true)
            .build();

        assert!(result.is_ok());
        let options = result?;
        assert!(options.write);
        assert!(options.special_file);

        Ok(())
    }

    /// Given: OpenFileOptionsBuilder with write=true and special_file not set
    /// When: `build` is called
    /// Then: special_file defaults to false
    #[test]
    fn open_file_options_special_file_defaults_false() -> Result<()> {
        use crate::options::OpenFileOptionsBuilder;

        let options = OpenFileOptionsBuilder::default().write(true).build()?;

        assert!(!options.special_file);

        Ok(())
    }
}
