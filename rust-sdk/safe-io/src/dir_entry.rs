#[cfg(target_os = "linux")]
use crate::RcSymlinkHandle;
use crate::constants::BLOCK_SIZE_BYTES;
use crate::constants::error_constants::{
    DIR_ENTRY_NOT_A_DIR, DIR_ENTRY_NOT_A_FILE, DIR_ENTRY_UNKNOWN_TYPE_FOR_OPEN,
};
use crate::errors::RustSafeIoError;
use crate::options::{
    OpenDirOptions, OpenDirOptionsBuilder, OpenFileOptions, OpenFileOptionsBuilder,
};
use crate::{
    DirConfigBuilder, Ownership, RcDirHandle, RcFileHandle, build_path, get_user_and_group_names,
    is_authorized,
};
use anyhow::Result;
use cap_fs_ext::{Metadata as CapStdMetadata, OsMetadataExt};
use cap_std::fs::{DirEntry as CapStdDirEntry, FileType};
use derive_getters::Getters;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::fs::entities::FileEntity;
use serde::Serialize;
use serde::ser::{Error as SerdeError, SerializeStruct};
use std::fmt;
#[cfg(unix)]
use std::os::unix::fs::DirEntryExt;

/// Represents basic metadata for a generic directory entry that can be either a File or a Dir.
///
/// If the entry has been opened via `DirEntry::open*` methods (for example to `stat` the file/dir), we keep
/// a reference to the opened file descriptor that must be reused to prevent future TOCTOU issues.  
#[derive(Clone, Debug, Getters, Serialize)]
pub struct DirEntry {
    /// The file or directory name of the `DirEntry`
    name: String,
    /// The file type as provided by `cap_primitives::fs::FileType`
    #[getter(skip)]
    #[serde(skip)]
    file_type: FileType,
    /// The file type as an enum value instead of the more unwieldy `FileType`.
    #[getter(skip)] // A manual getter is implemented for `entry_type`.
    #[serde(rename = "type")]
    entry_type: EntryType,
    /// a reference to the parent dir (for opening subdirs and files)
    #[getter(skip)]
    #[serde(skip)]
    parent_dir: RcDirHandle,
    /// The inode number of the `DirEntry`
    #[cfg(unix)]
    inode: u64,
    /// A memoization for the file or dir if it has been opened already through one of the the `DirEntry::open` methods.
    #[getter(skip)]
    #[serde(skip)]
    opened: Option<OpenedFsEntity>,
    /// Indicates if this entry represents a resolved symlink target
    #[serde(skip)]
    is_resolved_symlink_entry: bool,
}

/// Represents the type of a directory entry.
///
/// This enum covers the common file system entry types that can be encountered
/// when listing directory contents. It provides a more ergonomic interface than
/// the raw `FileType` from the standard library.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum EntryType {
    /// A regular file
    File,
    /// A directory
    Dir,
    /// A symbolic link
    Symlink,
    /// An unknown or unsupported file type
    Unknown,
    /// Extended file types (Unix-specific)
    Ext(EntryTypeExt),
}

/// Extended entry types available on Unix systems.
///
/// These represent special file types that are available on Unix-like operating
/// systems but not on other platforms.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum EntryTypeExt {
    /// A named pipe (FIFO)
    #[cfg(unix)]
    Fifo,
    /// A Unix domain socket
    #[cfg(unix)]
    Socket,
    /// A character device
    #[cfg(unix)]
    CharDevice,
    /// A block device
    #[cfg(unix)]
    BlockDevice,
}

impl Serialize for EntryType {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl fmt::Display for EntryType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            EntryType::Ext(ext) => write!(f, "{ext}"),
            _ => write!(f, "{self:?}"),
        }
    }
}

impl fmt::Display for EntryTypeExt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        #[cfg(unix)]
        {
            match self {
                EntryTypeExt::Fifo => write!(f, "Fifo"),
                EntryTypeExt::Socket => write!(f, "Socket"),
                EntryTypeExt::CharDevice => write!(f, "CharDevice"),
                EntryTypeExt::BlockDevice => write!(f, "BlockDevice"),
            }
        }
        #[cfg(not(unix))]
        {
            write!(f, "Unknown")
        }
    }
}

/// The metadata for a directory or file.
///
/// In addition to fields provided by `cap_primitives::fs::Metadata` (file size, block size,
/// number of hard links, permissions, uid/gid owners, last modified time, and more), this adds the
/// Ownership struct containing the owning user and group names.
#[allow(clippy::struct_field_names)]
#[derive(Clone, Debug)]
pub struct Metadata {
    cap_std_metadata: CapStdMetadata,
    #[cfg(unix)]
    ownership: Ownership,
    /// The target path of a symlink, if this metadata is for a symlink.
    /// Exposed via `symlink_target()` as `Option<String>` (`None` for non-symlinks or when target was not read).
    symlink_target: Option<String>,
}

/// A generic type that can represent a File or Dir.
#[derive(Clone, Debug)]
enum OpenedFsEntity {
    File(RcFileHandle),
    Dir(RcDirHandle),
    #[cfg(target_os = "linux")]
    Symlink(RcSymlinkHandle),
}

fn file_type_to_entry_type(file_type: FileType) -> EntryType {
    if file_type.is_file() {
        EntryType::File
    } else if file_type.is_dir() {
        EntryType::Dir
    } else if file_type.is_symlink() {
        EntryType::Symlink
    } else {
        #[cfg(unix)]
        {
            use cap_std::fs::FileTypeExt;
            if file_type.is_fifo() {
                return EntryType::Ext(EntryTypeExt::Fifo);
            } else if file_type.is_socket() {
                return EntryType::Ext(EntryTypeExt::Socket);
            } else if file_type.is_char_device() {
                return EntryType::Ext(EntryTypeExt::CharDevice);
            } else if file_type.is_block_device() {
                return EntryType::Ext(EntryTypeExt::BlockDevice);
            }
        }
        EntryType::Unknown
    }
}

impl DirEntry {
    /// Returns the entry type for this directory entry.
    ///
    /// This is a convenience method that converts the internal `FileType`
    /// to our more ergonomic `EntryType` enum.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rust_safe_io::DirConfigBuilder;
    /// # use rust_safe_io::options::OpenDirOptionsBuilder;
    /// # use rust_safe_io::dir_entry::EntryType;
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    /// #
    /// # let dir_config = DirConfigBuilder::default()
    /// #    .path("/some/path".to_string())
    /// #    .build().unwrap();
    /// #
    /// let dir_handle = dir_config.safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap()).unwrap();
    /// let entries = dir_handle.safe_list_dir(&cedar_auth).unwrap();
    /// for entry in entries {
    ///     match entry.entry_type() {
    ///         EntryType::File => println!("{} is a file", entry.name()),
    ///         EntryType::Dir => println!("{} is a directory", entry.name()),
    ///         EntryType::Symlink => println!("{} is a symlink", entry.name()),
    ///         _ => println!("{} is something else", entry.name()),
    ///     }
    /// }
    /// ```
    pub fn entry_type(&self) -> EntryType {
        file_type_to_entry_type(self.file_type)
    }

    /// Create a new `DirEntry` from a `cap_std::fs::DirEntry`.
    #[allow(clippy::missing_panics_doc)] // ignore a possible panic caused by unwrapping the file type, which can't happen on flavours of unix we care about
    pub fn from_cap_std(parent_dir: &RcDirHandle, cap_std_dir_entry: &CapStdDirEntry) -> DirEntry {
        // for the flavours of unix we care about, getting file type can't fail with IoError, so just unwrap the result here
        #[allow(clippy::unwrap_used)]
        let file_type = cap_std_dir_entry.file_type().unwrap();

        DirEntry {
            name: cap_std_dir_entry.file_name().to_string_lossy().to_string(),
            file_type,
            entry_type: file_type_to_entry_type(file_type),
            #[cfg(unix)]
            inode: cap_std_dir_entry.ino(),
            parent_dir: parent_dir.clone(),
            opened: None,
            is_resolved_symlink_entry: false,
        }
    }

    /// Create a new `DirEntry` from an already-opened `RcSymlinkHandle`.
    ///
    /// This constructor is useful when you have already opened a symlink and want to
    /// create a `DirEntry` for it without needing to list the parent directory.
    /// The symlink handle is cached in the `opened` field, ensuring TOCTOU safety
    /// for subsequent operations.
    ///
    /// # Arguments
    ///
    /// * `parent_dir` - The parent directory handle containing the symlink
    /// * `symlink_handle` - The already-opened symlink handle
    ///
    /// # Errors
    ///
    /// Returns an error if the symlink metadata cannot be retrieved (needed for inode).
    ///
    #[cfg(target_os = "linux")]
    pub fn from_symlink_handle(
        parent_dir: &RcDirHandle,
        symlink_handle: RcSymlinkHandle,
    ) -> Result<DirEntry, RustSafeIoError> {
        let name = symlink_handle.symlink_handle.symlink_name.clone();
        // fstat to populate inode and file_type fields
        let metadata = symlink_handle.symlink_handle.fd.metadata()?;
        let file_type = metadata.file_type();

        Ok(DirEntry {
            name,
            file_type,
            entry_type: EntryType::Symlink,
            inode: metadata.ino(),
            parent_dir: parent_dir.clone(),
            opened: Some(OpenedFsEntity::Symlink(symlink_handle)),
            is_resolved_symlink_entry: false,
        })
    }

    /// The file type of the `DirEntry`, as represented by `cap_primitives::fs::FileType`. This is not an enum but
    /// rather an object where the type can be queried using `is_file`, `is_dir` or `is_symlink` methods.
    pub const fn dir_entry_type(&self) -> FileType {
        self.file_type
    }

    /// Opens a `DirEntry` as a `RcFileHandle` and keeps a reference to the `RcFileHandle` in the `DirEntry` for use
    /// later. The same `RcFileHandle` must be used for all subsequent operations on this file for the program's
    /// lifetime to prevent TOCTOU.
    ///
    /// # Returns
    ///
    /// * `Result<RcFileHandle>` - The [`RcFileHandle`] object if it was open/created successfully.
    ///
    /// # Errors
    ///
    /// In addition to erroring in any way that `RcDirHandle::safe_open_file` can error, this method can
    /// also return an error if the `DirEntry` does not actually represent a file.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rust_safe_io::DirConfigBuilder;
    /// # use rust_safe_io::options::{OpenDirOptionsBuilder, OpenFileOptionsBuilder};
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    /// #
    /// # let dir_config = DirConfigBuilder::default()
    /// #    .path("/some/path".to_string())
    /// #    .build().unwrap();
    /// #
    /// let dir_handle = dir_config.safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap()).unwrap();
    /// let entries = dir_handle.safe_list_dir(&cedar_auth).unwrap();
    /// for mut entry in entries {
    ///     if entry.is_file() {
    ///         let file_handle = entry.open_as_file(&cedar_auth, OpenFileOptionsBuilder::default().read(true).build().unwrap()).unwrap();
    ///     }
    /// }
    /// ```
    pub fn open_as_file(
        &mut self,
        cedar_auth: &CedarAuth,
        open_file_options: OpenFileOptions,
    ) -> Result<RcFileHandle, RustSafeIoError> {
        if let OpenedFsEntity::File(file_handle) =
            self.open_file_internal(cedar_auth, open_file_options)?
        {
            Ok(file_handle)
        } else {
            Err(RustSafeIoError::EntryTypeMismatchError {
                reason: DIR_ENTRY_NOT_A_FILE.to_string(),
            })
        }
    }

    /// Internal implementation of `open_file` that handles memoizing the `OpenedFsEntity`.
    fn open_file_internal(
        &mut self,
        cedar_auth: &CedarAuth,
        mut open_file_options: OpenFileOptions,
    ) -> Result<OpenedFsEntity, RustSafeIoError> {
        // Force follow_symlinks=true for resolved symlink entries
        if self.is_resolved_symlink_entry {
            open_file_options.follow_symlinks = true;
        }

        if let Some(opened) = &self.opened {
            Ok(opened.clone())
        } else {
            let file = self
                .parent_dir
                .safe_open_file(cedar_auth, &self.name, open_file_options)?;
            let fs_entity = OpenedFsEntity::File(file);
            self.opened = Some(fs_entity.clone());
            Ok(fs_entity)
        }
    }

    /// Opens a `DirEntry` as a `RcDirHandle` and keeps a reference to the `RcDirHandle` in the `DirEntry` for use
    /// later. The same `RcDirHandle` must be used for all subsequent operations on this directory for the program's
    /// lifetime to prevent TOCTOU.
    ///
    /// # Arguments
    ///
    /// * `cedar_auth` - The Cedar authorization instance
    /// * `open_dir_options` - [`OpenDirOptions`] that has the configurations for opening a directory
    ///
    /// # Returns
    /// * `Result<RcDirHandle>` - The [`RcDirHandle`] object if it was open/created successfully.
    ///
    /// # Errors
    ///
    /// In addition to erroring in any way that `DirConfig::safe_open` can error, this method can
    /// also return an error if the `DirEntry` does not actually represent a directory.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rust_safe_io::DirConfigBuilder;
    /// # use rust_safe_io::options::OpenDirOptionsBuilder;
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    /// #
    /// # let dir_config = DirConfigBuilder::default()
    /// #    .path("/some/path".to_string())
    /// #    .build().unwrap();
    ///
    /// let dir_handle = dir_config.safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap()).unwrap();
    /// let entries = dir_handle.safe_list_dir(&cedar_auth).unwrap();
    /// for mut entry in entries {  
    ///     if entry.is_dir() {
    ///         let subdir_handle = entry.open_as_dir(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap()).unwrap();
    ///     }
    /// }
    /// ```
    pub fn open_as_dir(
        &mut self,
        cedar_auth: &CedarAuth,
        open_dir_options: OpenDirOptions,
    ) -> Result<RcDirHandle, RustSafeIoError> {
        if let OpenedFsEntity::Dir(dir_handle) =
            self.open_dir_internal(cedar_auth, open_dir_options)?
        {
            Ok(dir_handle)
        } else {
            Err(RustSafeIoError::EntryTypeMismatchError {
                reason: DIR_ENTRY_NOT_A_DIR.to_string(),
            })
        }
    }

    /// Opens a `DirEntry` as a `RcSymlinkHandle` if it represents a symlink.
    ///
    /// This method is only available on Linux platforms and allows opening symlink entries
    /// to operate on the symlink itself (rather than following it).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rust_safe_io::DirConfigBuilder;
    /// # use rust_safe_io::options::OpenDirOptionsBuilder;
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    /// #
    /// # let dir_config = DirConfigBuilder::default()
    /// #    .path("/some/path".to_string())
    /// #    .build().unwrap();
    ///
    /// let dir_handle = dir_config.safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap()).unwrap();
    /// let entries = dir_handle.safe_list_dir(&cedar_auth).unwrap();
    /// for mut entry in entries {  
    ///     if entry.is_symlink() {
    ///         let symlink_handle = entry.open_as_symlink(&cedar_auth).unwrap();
    ///     }
    /// }
    /// ```
    #[cfg(target_os = "linux")]
    pub fn open_as_symlink(
        &mut self,
        cedar_auth: &CedarAuth,
    ) -> Result<RcSymlinkHandle, RustSafeIoError> {
        if let OpenedFsEntity::Symlink(symlink_handle) = self.open_symlink_internal(cedar_auth)? {
            Ok(symlink_handle)
        } else {
            Err(RustSafeIoError::EntryTypeMismatchError {
                reason: "Entry is not a symlink".to_string(),
            })
        }
    }

    /// Internal implementation of `open_symlink` that handles memoizing the `OpenedFsEntity`.
    #[cfg(target_os = "linux")]
    fn open_symlink_internal(
        &mut self,
        cedar_auth: &CedarAuth,
    ) -> Result<OpenedFsEntity, RustSafeIoError> {
        if let Some(opened) = &self.opened {
            Ok(opened.clone())
        } else {
            let symlink = self.parent_dir.safe_open_symlink(cedar_auth, &self.name)?;
            let fs_entity = OpenedFsEntity::Symlink(symlink);
            self.opened = Some(fs_entity.clone());
            Ok(fs_entity)
        }
    }

    /// Internal implementation of `open_dir` that handles memoizing the `OpenedFsEntity`.
    /// Note that `open_dir_options` is not used, because the options available (create and recursive) are not
    /// relevant for opening a (presumably existing) directory. We provide it as a parameter anyway in case we need
    /// to support other options in the future.
    fn open_dir_internal(
        &mut self,
        cedar_auth: &CedarAuth,
        _open_dir_options: OpenDirOptions,
    ) -> Result<OpenedFsEntity, RustSafeIoError> {
        if let Some(opened) = &self.opened {
            Ok(opened.clone())
        } else {
            let dir = if self.is_symlink() || self.is_resolved_symlink_entry {
                // Follow symlink
                let full_path = build_path(&self.parent_dir.dir_handle.dir_config.path, &self.name);
                DirConfigBuilder::default()
                    .path(full_path)
                    .build()?
                    .safe_open(
                        cedar_auth,
                        OpenDirOptionsBuilder::default()
                            .follow_symlinks(true)
                            .build()?,
                    )?
            } else {
                self.parent_dir.safe_open_subdir(cedar_auth, &self.name)?
            };

            let fs_entity = OpenedFsEntity::Dir(dir);
            self.opened = Some(fs_entity.clone());
            Ok(fs_entity)
        }
    }

    /// An internal method to properly open an `OpenedFsEntity` based on its file type. For regular files and
    /// directories, this method returns the memoized dir/file/symlink handle if it has already been opened, otherwise
    /// it opens using the default (read-only) open options.
    fn open(&mut self, cedar_auth: &CedarAuth) -> Result<OpenedFsEntity, RustSafeIoError> {
        self.opened.clone().map_or_else(
            || -> Result<OpenedFsEntity, RustSafeIoError> {
                if self.is_file() {
                    self.open_file_internal(
                        cedar_auth,
                        OpenFileOptionsBuilder::default().read(true).build()?,
                    )
                } else if self.is_dir() {
                    self.open_dir_internal(cedar_auth, OpenDirOptionsBuilder::default().build()?)
                } else if self.is_symlink() {
                    #[cfg(target_os = "linux")]
                    {
                        self.open_symlink_internal(cedar_auth)
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        Err(RustSafeIoError::UnsupportedOperationError {
                            reason: "symlink operations are only supported on Linux".to_string(),
                        })
                    }
                } else {
                    Err(RustSafeIoError::InvalidFsEntity {
                        reason: DIR_ENTRY_UNKNOWN_TYPE_FOR_OPEN.to_string(),
                        path: build_path(&self.parent_dir.dir_handle.dir_config.path, self.name())
                            .into(),
                    })
                }
            },
            Ok,
        )
    }

    /// Gets the metadata of the target for a symlink `DirEntry`
    /// Behaviour is identical to `DirEntry::metadata()` when called on an `RcFileHandle` or `RcDirHandle`
    #[allow(clippy::missing_panics_doc)]
    pub(crate) fn symlink_target_metadata(
        &mut self,
        cedar_auth: &CedarAuth,
    ) -> Result<Metadata, RustSafeIoError> {
        if self.is_file() || self.is_dir() {
            self.open(cedar_auth).and_then(|fs_entity| match fs_entity {
                OpenedFsEntity::File(file_handle) => file_handle.metadata(cedar_auth),
                OpenedFsEntity::Dir(dir_handle) => dir_handle.metadata(cedar_auth),
                #[cfg(target_os = "linux")]
                OpenedFsEntity::Symlink(symlink_handle) => symlink_handle.metadata(cedar_auth),
            })
        } else {
            let file_entity = &FileEntity::from_string_path(&self.full_path())?;
            is_authorized(cedar_auth, &FilesystemAction::Stat, file_entity)?;

            // Try opening as file first
            if let Ok(file_handle) = self.open_as_file(
                cedar_auth,
                OpenFileOptionsBuilder::default()
                    .read(true)
                    .follow_symlinks(true)
                    .build()?,
            ) {
                return file_handle.metadata(cedar_auth);
            }

            // If that fails, try opening as directory
            if let Ok(dir_handle) = self.open_as_dir(
                cedar_auth,
                OpenDirOptionsBuilder::default()
                    .follow_symlinks(true)
                    .build()?,
            ) {
                return dir_handle.metadata(cedar_auth);
            }

            Err(RustSafeIoError::InvalidFsEntity {
                reason: DIR_ENTRY_UNKNOWN_TYPE_FOR_OPEN.to_string(),
                path: build_path(&self.parent_dir.dir_handle.dir_config.path, self.name()).into(),
            })
        }
    }

    /// Gets the metadata for a `DirEntry`, including file size, permissions, ownership, and other attributes.
    /// This method will first open the entry (as a file or directory depending on its type) if it hasn't
    /// been opened already, and then retrieve its metadata.
    ///
    /// # Arguments
    ///
    /// * `cedar_auth` - The Cedar authorization instance
    ///
    /// # Returns
    ///
    /// * `Result<Metadata>` - The [`Metadata`] object containing information about the file or directory
    ///
    /// # Safety
    /// Note that TOCTOU safety is currently only guaranteed for regular files and directories. File descriptors are not
    /// currently cached for other file types, so the underlying file may change after the metadata is retrieved.
    ///
    /// # Errors
    ///
    /// This method will return an error if:
    /// * The principal doesn't have permission to access the file or directory metadata
    /// * The entry cannot be opened
    /// * The metadata cannot be retrieved
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rust_safe_io::DirConfigBuilder;
    /// # use rust_safe_io::options::OpenDirOptionsBuilder;
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    /// #
    /// # let dir_config = DirConfigBuilder::default()
    /// #    .path("/some/path".to_string())
    /// #    .build().unwrap();
    ///
    /// let dir_handle = dir_config.safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap()).unwrap();
    /// let entries = dir_handle.safe_list_dir(&cedar_auth).unwrap();
    ///
    /// for mut entry in entries {
    ///     let metadata = entry.metadata(&cedar_auth).unwrap();
    ///     println!("File size: {}", metadata.cap_std_metadata().len());
    ///     
    ///     // On Unix systems, you can also access ownership information
    ///     #[cfg(unix)]
    ///     {
    ///         let ownership = metadata.ownership();
    ///         println!("Owner: {}, Group: {}", ownership.user(), ownership.group());
    ///     }
    /// }
    /// ```
    pub fn metadata(&mut self, cedar_auth: &CedarAuth) -> Result<Metadata, RustSafeIoError> {
        if self.is_file() || self.is_dir() || self.is_symlink() {
            self.open(cedar_auth).and_then(|fs_entity| match fs_entity {
                OpenedFsEntity::File(file_handle) => file_handle.metadata(cedar_auth),
                OpenedFsEntity::Dir(dir_handle) => dir_handle.metadata(cedar_auth),
                #[cfg(target_os = "linux")]
                OpenedFsEntity::Symlink(symlink_handle) => symlink_handle.metadata(cedar_auth),
            })
        } else {
            // Pretend the entry is a file for the purposes of authorizing the stat call
            let file_entity = &FileEntity::from_string_path(&self.full_path())?;
            is_authorized(cedar_auth, &FilesystemAction::Stat, file_entity)?;

            // `symlink_metadata` is a misleading name, it'll get the metadata for any file type. Unlike `Dir::metadata`
            // though, it has `FollowSymlinks` set to `No`.
            let cap_std_metadata = self
                .parent_dir
                .dir_handle
                .dir
                .symlink_metadata(&self.name)?;
            Metadata::from_cap_std_metadata(cap_std_metadata)
        }
    }

    /// Returns true if the `DirEntry` represents a directory.
    pub fn is_dir(&self) -> bool {
        self.file_type.is_dir()
    }

    /// Returns true if the `DirEntry` represents a regular file. This method will return false for symlinks.
    pub fn is_file(&self) -> bool {
        self.file_type.is_file()
    }

    /// Returns true if the `DirEntry` represents a symlink.
    pub fn is_symlink(&self) -> bool {
        self.file_type.is_symlink()
    }

    /// Returns true if the `DirEntry` represents a socket.
    #[cfg(unix)]
    pub fn is_socket(&self) -> bool {
        use cap_std::fs::FileTypeExt;
        self.file_type.is_socket()
    }

    /// Return the full canonical path of the `dir_entry`.
    pub fn full_path(&self) -> String {
        build_path(&self.parent_dir.dir_handle.dir_config.path, &self.name)
    }

    /// Replace the symlink entry file type with the target file type and mark is as a resolved symlink entry
    #[must_use]
    pub(crate) fn convert_to_resolved_symlink_entry(self, target_file_type: FileType) -> DirEntry {
        DirEntry {
            name: self.name,
            file_type: target_file_type,
            entry_type: file_type_to_entry_type(target_file_type),
            parent_dir: self.parent_dir,
            inode: self.inode,
            opened: None,
            is_resolved_symlink_entry: true,
        }
    }
}

impl Metadata {
    /// Create a new Metadata object from `cap_primitives::fs::Metadata`.
    pub fn from_cap_std_metadata(
        cap_std_metadata: CapStdMetadata,
    ) -> Result<Metadata, RustSafeIoError> {
        // Assume the cedar auth check is done elsewhere so we don't need to do it here.
        #[cfg(unix)]
        let (owner, group) =
            get_user_and_group_names(cap_std_metadata.uid(), cap_std_metadata.gid())?;

        Ok(Metadata {
            cap_std_metadata,
            #[cfg(unix)]
            ownership: Ownership { owner, group },
            symlink_target: None,
        })
    }

    /// Get the underlying `cap_std` metadata
    pub const fn cap_std_metadata(&self) -> &CapStdMetadata {
        &self.cap_std_metadata
    }

    // Get the ownership struct containing the owning user name and group name
    #[cfg(unix)]
    pub const fn ownership(&self) -> &Ownership {
        &self.ownership
    }

    /// Get Unix permissions for this inode as an octal value
    #[cfg(unix)]
    pub fn permissions(&self) -> i64 {
        // mode() returns u32, which can always fit in i64, so no safe casting needed
        i64::from(self.cap_std_metadata().mode())
    }

    /// Get the device ID for this file
    #[cfg(unix)]
    pub fn device(&self) -> u64 {
        self.cap_std_metadata().dev()
    }

    /// Get the inode number for this file
    #[cfg(unix)]
    pub fn ino(&self) -> u64 {
        self.cap_std_metadata().ino()
    }

    /// Get the file type
    pub fn file_type(&self) -> FileType {
        self.cap_std_metadata().file_type()
    }

    /// Returns the entry type for this metadata.
    ///
    /// This method converts the internal `FileType` from the metadata
    /// to our more ergonomic `EntryType` enum.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rust_safe_io::DirConfigBuilder;
    /// # use rust_safe_io::options::OpenDirOptionsBuilder;
    /// # use rust_safe_io::dir_entry::EntryType;
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    /// #
    /// # let dir_config = DirConfigBuilder::default()
    /// #    .path("/some/path".to_string())
    /// #    .build().unwrap();
    /// #
    /// let dir_handle = dir_config.safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap()).unwrap();
    /// let entries = dir_handle.safe_list_dir(&cedar_auth).unwrap();
    /// for mut entry in entries {
    ///     let metadata = entry.metadata(&cedar_auth).unwrap();
    ///     match metadata.entry_type() {
    ///         EntryType::File => println!("It's a file"),
    ///         EntryType::Dir => println!("It's a directory"),
    ///         _ => println!("It's something else"),
    ///     }
    /// }
    /// ```
    pub fn entry_type(&self) -> EntryType {
        file_type_to_entry_type(self.cap_std_metadata().file_type())
    }

    /// Get the size of a file in bytes.
    ///
    /// This method returns the file size as reported by the filesystem.
    /// For directories and other non-regular files, the meaning of this
    /// value is filesystem-dependent.
    ///
    /// ```no_run
    /// # use rust_safe_io::DirConfigBuilder;
    /// # use rust_safe_io::options::OpenDirOptionsBuilder;
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    /// #
    /// # let dir_config = DirConfigBuilder::default()
    /// #    .path("/some/path".to_string())
    /// #    .build().unwrap();
    /// #
    /// let dir_handle = dir_config.safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap()).unwrap();
    /// let entries = dir_handle.safe_list_dir(&cedar_auth).unwrap();
    /// for mut entry in entries {
    ///     if entry.is_file() {
    ///         let mut metadata = entry.metadata(&cedar_auth).unwrap();
    ///         let size = metadata.file_size().unwrap();
    ///         println!("File size: {} bytes", size);
    ///     }
    /// }
    /// ```
    #[cfg(unix)]
    pub fn file_size(&self) -> Result<i64, RustSafeIoError> {
        match i64::try_from(self.cap_std_metadata().size()) {
            Ok(val) => Ok(val),
            Err(e) => Err(RustSafeIoError::TryFromIntError(e)),
        }
    }

    /// Get the number of 512-byte blocks allocated to this file.
    ///
    /// This represents the actual disk space used by the file, which may be
    /// different from the file size due to filesystem block allocation and
    /// sparse files.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rust_safe_io::DirConfigBuilder;
    /// # use rust_safe_io::options::OpenDirOptionsBuilder;
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    /// #
    /// # let dir_config = DirConfigBuilder::default()
    /// #    .path("/some/path".to_string())
    /// #    .build().unwrap();
    /// #
    /// let dir_handle = dir_config.safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap()).unwrap();
    /// let entries = dir_handle.safe_list_dir(&cedar_auth).unwrap();
    /// for mut entry in entries {
    ///     let mut metadata = entry.metadata(&cedar_auth).unwrap();
    ///     let blocks = metadata.blocks().unwrap();
    ///     println!("Disk blocks used: {}", blocks);
    /// }
    /// ```
    #[cfg(unix)]
    pub fn blocks(&self) -> Result<i64, RustSafeIoError> {
        match i64::try_from(self.cap_std_metadata().blocks()) {
            Ok(val) => Ok(val),
            Err(e) => Err(RustSafeIoError::TryFromIntError(e)),
        }
    }

    /// Get the size of blocks allocated to this file in bytes.
    ///
    /// This represents the actual disk space used by the file, which may be
    /// different from the file size due to filesystem block allocation and
    /// sparse files.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rust_safe_io::DirConfigBuilder;
    /// # use rust_safe_io::options::OpenDirOptionsBuilder;
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    /// #
    /// # let dir_config = DirConfigBuilder::default()
    /// #    .path("/some/path".to_string())
    /// #    .build().unwrap();
    /// #
    /// let dir_handle = dir_config.safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap()).unwrap();
    /// let entries = dir_handle.safe_list_dir(&cedar_auth).unwrap();
    /// for mut entry in entries {
    ///     let mut metadata = entry.metadata(&cedar_auth).unwrap();
    ///     let allocated_size = metadata.allocated_size().unwrap();
    ///     println!("Block size used: {}", allocated_size);
    /// }
    /// ```
    #[cfg(unix)]
    pub fn allocated_size(&self) -> Result<i64, RustSafeIoError> {
        match i64::try_from(self.cap_std_metadata().blocks() * BLOCK_SIZE_BYTES as u64) {
            Ok(val) => Ok(val),
            Err(e) => Err(RustSafeIoError::TryFromIntError(e)),
        }
    }

    /// Get the last modified time for this file as a Unix timestamp.
    ///
    /// This returns the modification time as seconds since the Unix epoch
    /// (January 1, 1970, 00:00:00 UTC).
    ///
    /// ```no_run
    /// # use rust_safe_io::DirConfigBuilder;
    /// # use rust_safe_io::options::OpenDirOptionsBuilder;
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    /// #
    /// # let dir_config = DirConfigBuilder::default()
    /// #    .path("/some/path".to_string())
    /// #    .build().unwrap();
    /// #
    /// let dir_handle = dir_config.safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap()).unwrap();
    /// let entries = dir_handle.safe_list_dir(&cedar_auth).unwrap();
    /// for mut entry in entries {
    ///     let mut metadata = entry.metadata(&cedar_auth).unwrap();
    ///     let mtime = metadata.mtime();
    ///     println!("Last modified: {} seconds since Unix epoch", mtime);
    /// }
    /// ```
    #[cfg(unix)]
    pub fn mtime(&self) -> i64 {
        self.cap_std_metadata().mtime()
    }

    /// Get the nanoseconds component of the last modified time for this file.
    ///
    /// This returns the fractional nanoseconds component (0-999,999,999) of the
    /// modification time. To get the complete timestamp with nanosecond precision,
    /// combine this with `mtime()`
    ///
    /// ```no_run
    /// # use rust_safe_io::DirConfigBuilder;
    /// # use rust_safe_io::options::OpenDirOptionsBuilder;
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    /// #
    /// # let dir_config = DirConfigBuilder::default()
    /// #    .path("/some/path".to_string())
    /// #    .build().unwrap();
    /// #
    /// let dir_handle = dir_config.safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap()).unwrap();
    /// let entries = dir_handle.safe_list_dir(&cedar_auth).unwrap();
    /// for mut entry in entries {
    ///     let mut metadata = entry.metadata(&cedar_auth).unwrap();
    ///     let mtime_sec = metadata.mtime();
    ///     let mtime_nsec = metadata.mtime_nsec();
    ///     println!("Last modified: {}.{} seconds since Unix epoch", mtime_sec, mtime_nsec);
    /// }
    /// ```
    #[cfg(unix)]
    pub fn mtime_nsec(&self) -> i64 {
        self.cap_std_metadata().mtime_nsec()
    }

    /// Get the creation time for this file as a Unix timestamp.
    ///
    /// This returns the creation time as seconds since the Unix epoch
    /// (January 1, 1970, 00:00:00 UTC).
    ///
    /// ```no_run
    /// # use rust_safe_io::DirConfigBuilder;
    /// # use rust_safe_io::options::OpenDirOptionsBuilder;
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    /// #
    /// # let dir_config = DirConfigBuilder::default()
    /// #    .path("/some/path".to_string())
    /// #    .build().unwrap();
    /// #
    /// let dir_handle = dir_config.safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap()).unwrap();
    /// let entries = dir_handle.safe_list_dir(&cedar_auth).unwrap();
    /// for mut entry in entries {
    ///     let mut metadata = entry.metadata(&cedar_auth).unwrap();
    ///     let ctime = metadata.ctime();
    ///     println!("Created: {} seconds since Unix epoch", ctime);
    /// }
    /// ```
    #[cfg(unix)]
    pub fn ctime(&self) -> i64 {
        self.cap_std_metadata().ctime()
    }

    /// Get the number of hard links to this file.
    ///
    /// This returns the number of directory entries that point to the same
    /// inode as this file. Regular files typically have a link count of 1,
    /// but this can be higher if the file has been hard-linked.
    ///
    /// Returns a `RustSafeIoError::TryFromIntError` if the link count cannot be
    /// converted to an `i64`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rust_safe_io::DirConfigBuilder;
    /// # use rust_safe_io::options::OpenDirOptionsBuilder;
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    /// #
    /// # let dir_config = DirConfigBuilder::default()
    /// #    .path("/some/path".to_string())
    /// #    .build().unwrap();
    /// #
    /// let dir_handle = dir_config.safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap()).unwrap();
    /// let entries = dir_handle.safe_list_dir(&cedar_auth).unwrap();
    /// for mut entry in entries {
    ///     let mut metadata = entry.metadata(&cedar_auth).unwrap();
    ///     let links = metadata.num_hardlinks().unwrap();
    ///     println!("Number of hard links: {}", links);
    /// }
    /// ```
    #[cfg(unix)]
    pub fn num_hardlinks(&self) -> Result<i64, RustSafeIoError> {
        match i64::try_from(self.cap_std_metadata().nlink()) {
            Ok(val) => Ok(val),
            Err(e) => Err(RustSafeIoError::TryFromIntError(e)),
        }
    }

    /// Get the symlink target path.
    ///
    /// Returns `None` for regular files and directories, or `Some(target)` for symlinks
    /// where the target was read.
    pub fn symlink_target(&self) -> Option<String> {
        self.symlink_target.clone()
    }

    /// Set the symlink target path for this metadata.
    ///
    /// This is used internally when creating metadata for symlinks.
    /// Pass `None` to indicate no symlink target, or `Some(target)` for symlinks.
    pub fn set_symlink_target(&mut self, target: Option<String>) {
        self.symlink_target = target;
    }
}

impl Serialize for Metadata {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[cfg(unix)]
        let struct_size = 9;
        #[cfg(not(unix))]
        let struct_size = 2;

        let mut s = serializer.serialize_struct("Metadata", struct_size)?;
        s.serialize_field("type", &self.entry_type())?;

        #[cfg(unix)]
        {
            s.serialize_field("permissions", &self.permissions())?;
            s.serialize_field(
                "file_size",
                &self
                    .file_size()
                    .map_err(|e| SerdeError::custom(e.to_string()))?,
            )?;
            s.serialize_field(
                "allocated_size",
                &self
                    .allocated_size()
                    .map_err(|e| SerdeError::custom(e.to_string()))?,
            )?;
            s.serialize_field("last_modified_time", &self.mtime())?;
            s.serialize_field(
                "num_hardlinks",
                &self
                    .num_hardlinks()
                    .map_err(|e| SerdeError::custom(e.to_string()))?,
            )?;
            s.serialize_field("owner_user", &self.ownership().owner)?;
            s.serialize_field("owner_group", &self.ownership().group)?;
        }
        s.serialize_field("symlink_target", &self.symlink_target)?;
        s.end()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::DirConfigBuilder;
    use crate::errors::RustSafeIoError;
    use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    use rstest::rstest;
    use std::os::unix::fs::PermissionsExt;

    use rex_test_utils::io::{create_temp_dir_and_path, create_test_file};

    fn get_test_cedar_auth() -> CedarAuth {
        let (cedar_auth, _) = CedarAuth::new(
            &get_default_test_rex_policy(),
            get_default_test_rex_schema(),
            "[]",
        )
        .expect("Failed to initialize CedarAuth for tests");
        cedar_auth
    }

    fn open_test_dir_handle(temp_dir_path: &str) -> Result<RcDirHandle, RustSafeIoError> {
        DirConfigBuilder::default()
            .path(temp_dir_path.to_string())
            .build()?
            .safe_open(
                &get_test_cedar_auth(),
                OpenDirOptionsBuilder::default().build().unwrap(),
            )
    }

    /// Given: a DirEntry corresponding to a file
    /// When: get_metadata is called then open_as_file is called
    /// Then: the `opened` field is the same after both invocations
    #[test]
    fn test_memoization_file_metadata_then_open() -> Result<()> {
        let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

        let file_name = "test_file.txt";
        let _ = create_test_file(&temp_dir, file_name, b"test content")?;

        let dir_handle = open_test_dir_handle(&temp_dir_path)?;
        let mut entries = dir_handle.safe_list_dir(&get_test_cedar_auth())?;
        let file_entry = entries.get_mut(0).unwrap();

        let _metadata = file_entry.metadata(&get_test_cedar_auth())?;
        let OpenedFsEntity::File(file_handle_1) = file_entry.opened.as_ref().unwrap() else {
            panic!("Expected internal FS entity to be a file")
        };

        // Clone so we can close out the reference from getting `file_entry.opened` and allow the open_as_file
        // to get the next mutable reference
        let file_handle_1 = file_handle_1.clone();

        let file_handle_2 = file_entry.open_as_file(
            &get_test_cedar_auth(),
            OpenFileOptionsBuilder::default()
                .read(true)
                .build()
                .unwrap(),
        )?;

        assert_eq!(
            file_handle_1, file_handle_2,
            "Expected the first file handle to be the same as the second file handle"
        );

        Ok(())
    }

    /// Given: a DirEntry corresponding to a file
    /// When: open_as_file is called then get_metadata is called
    /// Then: the `opened` field is the same after both invocations
    #[test]
    fn test_memoization_file_open_then_metadata() -> Result<()> {
        let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

        let file_name = "test_file.txt";
        let _ = create_test_file(&temp_dir, file_name, b"test content")?;

        let dir_handle = open_test_dir_handle(&temp_dir_path)?;
        let mut entries = dir_handle.safe_list_dir(&get_test_cedar_auth())?;
        let file_entry = entries.get_mut(0).unwrap();

        let file_handle_1 = file_entry.open_as_file(
            &get_test_cedar_auth(),
            OpenFileOptionsBuilder::default()
                .read(true)
                .build()
                .unwrap(),
        )?;

        let _ = file_entry.metadata(&get_test_cedar_auth());

        let OpenedFsEntity::File(file_handle_2) = file_entry.opened.as_ref().unwrap() else {
            panic!("Expected internal FS entity to be a file")
        };

        // Clone so we can close out the reference from getting `dir_entry.opened` and allow the open_as_dir
        // to get the next mutable reference
        let file_handle_2 = file_handle_2.clone();

        assert_eq!(
            file_handle_1, file_handle_2,
            "Expected the first file handle to be the same as the second file handle"
        );

        Ok(())
    }

    /// Given: a DirEntry corresponding to a directory
    /// When: get_metadata is called then open_as_dir is called
    /// Then: the `opened` field is the same after both invocations
    #[test]
    fn test_memoization_dir_metadata_then_open() -> Result<()> {
        let (_temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

        let subdir_name = "test_subdir";
        let _ = std::fs::create_dir(temp_dir_path.clone() + "/" + subdir_name);

        let dir_handle = open_test_dir_handle(&temp_dir_path)?;
        let mut entries = dir_handle.safe_list_dir(&get_test_cedar_auth())?;
        let dir_entry = entries.get_mut(0).unwrap();

        let _metadata = dir_entry.metadata(&get_test_cedar_auth())?;
        let OpenedFsEntity::Dir(dir_handle_1) = dir_entry.opened.as_ref().unwrap() else {
            panic!("Expected internal FS entity to be a directory")
        };

        // Clone so we can close out the reference from getting `dir_entry.opened` and allow the open_as_dir
        // to get the next mutable reference
        let dir_handle_1 = dir_handle_1.clone();

        let dir_handle_2 = dir_entry.open_as_dir(
            &get_test_cedar_auth(),
            OpenDirOptionsBuilder::default().build().unwrap(),
        )?;

        assert_eq!(
            dir_handle_1, dir_handle_2,
            "Expected the first directory handle to be the same as the second directory handle"
        );

        Ok(())
    }

    /// Given: a DirEntry corresponding to a directory
    /// When: open_as_dir is called then get_metadata is called
    /// Then: the `opened` field is the same after both invocations
    #[test]
    fn test_memoization_dir_open_then_metadata() -> Result<()> {
        let (_temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
        let subdir_name = "test_subdir";
        let subdir_path = temp_dir_path.clone() + "/" + subdir_name;
        std::fs::create_dir(&subdir_path)?;
        std::fs::set_permissions(&subdir_path, std::fs::Permissions::from_mode(0o755))?;

        let dir_handle = open_test_dir_handle(&temp_dir_path)?;
        let mut entries = dir_handle.safe_list_dir(&get_test_cedar_auth())?;
        let dir_entry = entries.get_mut(0).unwrap();
        assert_eq!(
            dir_entry.metadata(&get_test_cedar_auth())?.permissions() & 0o7777,
            0o755,
            "Expected directory permissions to be 0o755 (rwxr-xr-x)"
        );

        let dir_handle_1 = dir_entry.open_as_dir(
            &get_test_cedar_auth(),
            OpenDirOptionsBuilder::default().build().unwrap(),
        )?;

        let _ = dir_entry.metadata(&get_test_cedar_auth());

        let OpenedFsEntity::Dir(dir_handle_2) = dir_entry.opened.as_ref().unwrap() else {
            panic!("Expected internal FS entity to be a directory")
        };

        // Clone so we can close out the reference from getting `dir_entry.opened` and allow the open_as_dir
        // to get the next mutable reference
        let dir_handle_2 = dir_handle_2.clone();

        assert_eq!(
            dir_handle_1, dir_handle_2,
            "Expected the first directory handle to be the same as the second directory handle"
        );

        Ok(())
    }

    /// Given: an EntryType
    /// When: to_string is called
    /// Then: the appropriate string is returned
    #[test]
    fn test_rhai_file_type_to_string() {
        assert_eq!(EntryType::File.to_string(), "File");
        assert_eq!(EntryType::Dir.to_string(), "Dir");
        assert_eq!(EntryType::Symlink.to_string(), "Symlink");
        assert_eq!(EntryType::Unknown.to_string(), "Unknown");

        #[cfg(unix)]
        {
            assert_eq!(EntryTypeExt::Fifo.to_string(), "Fifo");
            assert_eq!(EntryTypeExt::BlockDevice.to_string(), "BlockDevice");
            assert_eq!(EntryTypeExt::CharDevice.to_string(), "CharDevice");
            assert_eq!(EntryTypeExt::Socket.to_string(), "Socket");
        }
    }

    /// Given: a FileType
    /// When: entry_type is called
    /// Then: the appropriate EntryType is returned
    #[rstest]
    #[case::file(FileType::file(), EntryType::File)]
    #[case::file(FileType::dir(), EntryType::Dir)]
    #[case::file(FileType::unknown(), EntryType::Unknown)]
    fn test_entry_type(#[case] f_type: FileType, #[case] e_type: EntryType) {
        assert_eq!(file_type_to_entry_type(f_type), e_type);
    }
}
