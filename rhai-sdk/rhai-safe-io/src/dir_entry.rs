//! Directory entry types and metadata.
#![allow(
    unused_variables,
    unreachable_code,
    clippy::unreachable,
    clippy::needless_pass_by_value
)]
use cap_std::fs::FileType;
#[cfg(unix)]
use rhai::{Module, export_module};
#[cfg(unix)]
use rust_safe_io::Ownership;
use rust_safe_io::{
    Metadata, RcFileHandle,
    options::{OpenDirOptions, OpenFileOptions},
};

#[allow(clippy::wildcard_imports)] // rhai prefix import must be imported as wildcard
use rhai::plugin::*;

/// Represents an entry within a directory listing.
#[derive(Debug, Clone, Copy)]
pub struct DirEntry;

/// File or directory metadata such as size, permissions, and timestamps.
#[derive(Debug, Clone, Copy)]
pub struct FileMetadata;

#[export_module]
#[allow(clippy::unwrap_used)] // not sure where unwrap is used, probably within export_module somewhere. I assume rhai has safeguards to ensure values are never actually None
pub mod dir_entry_type_mod {
    use rust_safe_io::dir_entry::{EntryType, EntryTypeExt};

    pub const FILE: EntryType = EntryType::File;
    pub const DIR: EntryType = EntryType::Dir;
    pub const SYMLINK: EntryType = EntryType::Symlink;
    pub const UNKNOWN: EntryType = EntryType::Unknown;
    #[cfg(unix)]
    pub const FIFO: EntryType = EntryType::Ext(EntryTypeExt::Fifo);
    #[cfg(unix)]
    pub const SOCKET: EntryType = EntryType::Ext(EntryTypeExt::Socket);
    #[cfg(unix)]
    pub const CHAR_DEVICE: EntryType = EntryType::Ext(EntryTypeExt::CharDevice);
    #[cfg(unix)]
    pub const BLOCK_DEVICE: EntryType = EntryType::Ext(EntryTypeExt::BlockDevice);

    /// '==' operator
    #[rhai_fn(global, name = "==", pure)]
    pub fn eq(type_1: &mut EntryType, type_2: EntryType) -> bool {
        if let EntryType::Ext(ext) = type_1
            && let EntryType::Ext(ext2) = type_2
        {
            return ext == &ext2;
        }
        type_1 == &type_2
    }

    /// '!=' operator
    #[rhai_fn(global, name = "!=", pure)]
    pub fn neq(type_1: &mut EntryType, type_2: EntryType) -> bool {
        if let EntryType::Ext(ext) = type_1
            && let EntryType::Ext(ext2) = type_2
        {
            return ext != &ext2;
        }
        type_1 != &type_2
    }
}

impl DirEntry {
    /// Get the `DirEntry`'s file or directory name
    pub fn name(&mut self) -> String {
        unreachable!("This method exists only for documentation.")
    }

    /// Convert the file type object to an enum type
    pub fn dir_entry_type(&mut self) -> FileType {
        unreachable!("This method exists only for documentation.")
    }

    /// Get the inode number of the `DirEntry`. Returns an error if the underlying value is greater than `i64::MAX`
    #[cfg(unix)]
    pub fn inode(&mut self) -> Result<i64, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Open the `DirEntry` as a file.
    ///
    /// This internally caches the file handle, so calling this function multiple times returns the same file handle to prevent TOCTOU.
    ///
    /// Returns an error if the `DirEntry` does not represent a file, or if the user is not authorized to open the file.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// #     &mut scope,
    /// #     r#"
    /// let dir_config = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build();
    /// let dir_handle = dir_config.open(OpenDirOptions().build());
    /// let entries = dir_handle.list_entries();
    /// for entry in entries.values() {
    ///     if entry.type() == FileType::FILE {
    ///         let file_handle = entry.open_as_file(OpenFileOptions().read(true).build());
    ///     }
    /// }
    /// #     "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    pub fn open_as_file(
        &mut self,
        open_file_options: OpenFileOptions,
    ) -> Result<RcFileHandle, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Open the `DirEntry` as a directory.
    ///
    /// This internally caches the dir handle, so calling this function multiple times returns the same dir handle to prevent TOCTOU.
    ///
    /// Returns an error if the `DirEntry` does not represent a directory, or if the user is not authorized to open the directory.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// #     &mut scope,
    /// #     r#"
    /// let dir_config = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build();
    /// let dir_handle = dir_config.open(OpenDirOptions().build());
    /// let entries = dir_handle.list_entries();
    /// for entry in entries.values() {
    ///     if entry.type() == FileType::DIR {
    ///         let dir_handle = entry.open_as_dir(OpenDirOptions().build());
    ///     }
    /// }
    /// #     "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    pub fn open_as_dir(
        &mut self,
        open_dir_options: OpenDirOptions,
    ) -> Result<RcFileHandle, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Retrieve the [`FileMetadata`] for the `DirEntry`.
    ///
    /// Note that in unix, getting metadata requires opening and `stat`-ing the file. To prevent TOCTOU, calling this function will
    /// open the file in read-only mode, and cache the opened file descriptor, similar to `open_as_file` and `open_as_dir` functions.
    /// Calling `open_as_*` functions on `DirEntry` before or after `get_metadata` will return the same file descriptor.
    ///
    /// Returns an error if the user is not authorized to retrieve metadata for the file or dir the `DirEntry` refers to.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// #     &mut scope,
    /// #     r#"
    /// let dir_config = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build();
    /// let dir_handle = dir_config.open(OpenDirOptions().build());
    /// let entries = dir_handle.list_entries();
    /// for entry in entries.values() {
    ///     let metadata = entry.metadata();
    /// }
    /// #     "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    pub fn get_metadata(&mut self) -> Result<Metadata, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }
}

impl FileMetadata {
    /// Get the type of the file
    pub fn dir_entry_type(&mut self) -> Result<FileType, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Get the size of a file
    #[cfg(unix)]
    pub fn file_size(&mut self) -> Result<i64, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Get the number of 512B blocks allocated to this file.
    #[cfg(unix)]
    pub fn blocks(&mut self) -> Result<i64, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Get the allocated size of this file in bytes. This is equal to `blocks() * 512`.
    #[cfg(unix)]
    pub fn allocated_size(&mut self) -> Result<i64, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Get the number of hardlinks to this file.
    #[cfg(unix)]
    pub fn num_hardlinks(&mut self) -> Result<i64, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Get the last modified time for this file
    #[cfg(unix)]
    pub fn last_modified_time(&mut self) -> i64 {
        unreachable!("This method exists only for documentation.")
    }

    /// Get Unix permissions for this file as an octal value
    #[cfg(unix)]
    pub fn permissions(&mut self) -> i64 {
        unreachable!("This method exists only for documentation.")
    }

    /// Get the owning user and group names for this file
    #[cfg(unix)]
    pub fn owner(&mut self) -> Ownership {
        unreachable!("This method exists only for documentation.")
    }
}

#[cfg(test)]
mod test {
    use crate::dir_entry::dir_entry_type_mod::*;

    use super::*;
    use rstest::rstest;
    #[cfg(unix)]
    use rust_safe_io::dir_entry::EntryType;

    /// Given: two RhaiFileTypes
    /// When: they are compared using the equals "==" operator
    /// Then: the correct result is returned
    #[rstest]
    // Basic types compared with each other
    #[case(FILE, FILE, true)]
    #[case(FILE, DIR, false)]
    #[case(FILE, SYMLINK, false)]
    #[case(FILE, UNKNOWN, false)]
    #[case(DIR, FILE, false)]
    #[case(DIR, DIR, true)]
    #[case(DIR, SYMLINK, false)]
    #[case(DIR, UNKNOWN, false)]
    #[case(SYMLINK, FILE, false)]
    #[case(SYMLINK, DIR, false)]
    #[case(SYMLINK, SYMLINK, true)]
    #[case(SYMLINK, UNKNOWN, false)]
    #[case(UNKNOWN, FILE, false)]
    #[case(UNKNOWN, DIR, false)]
    #[case(UNKNOWN, SYMLINK, false)]
    #[case(UNKNOWN, UNKNOWN, true)]
    // Basic types compared with Ext types (using Fifo as representative)
    #[cfg(unix)]
    #[case(FILE, FIFO, false)]
    #[cfg(unix)]
    #[case(DIR, FIFO, false)]
    #[cfg(unix)]
    #[case(SYMLINK, FIFO, false)]
    #[cfg(unix)]
    #[case(UNKNOWN, FIFO, false)]
    #[cfg(unix)]
    #[case(FIFO, FILE, false)]
    #[cfg(unix)]
    #[case(FIFO, DIR, false)]
    #[cfg(unix)]
    #[case(FIFO, SYMLINK, false)]
    #[cfg(unix)]
    #[case(FIFO, UNKNOWN, false)]
    // Ext types compared with each other
    #[cfg(unix)]
    #[case(FIFO, FIFO, true)]
    #[cfg(unix)]
    #[case(FIFO, SOCKET, false)]
    #[cfg(unix)]
    #[case(FIFO, CHAR_DEVICE, false)]
    #[cfg(unix)]
    #[case(FIFO, BLOCK_DEVICE, false)]
    #[cfg(unix)]
    #[case(SOCKET, FIFO, false)]
    #[cfg(unix)]
    #[case(SOCKET, SOCKET, true)]
    #[cfg(unix)]
    #[case(SOCKET, CHAR_DEVICE, false)]
    #[cfg(unix)]
    #[case(SOCKET, BLOCK_DEVICE, false)]
    #[cfg(unix)]
    #[case(CHAR_DEVICE, FIFO, false)]
    #[cfg(unix)]
    #[case(CHAR_DEVICE, SOCKET, false)]
    #[cfg(unix)]
    #[case(CHAR_DEVICE, CHAR_DEVICE, true)]
    #[cfg(unix)]
    #[case(CHAR_DEVICE, BLOCK_DEVICE, false)]
    #[cfg(unix)]
    #[case(BLOCK_DEVICE, FIFO, false)]
    #[cfg(unix)]
    #[case(BLOCK_DEVICE, SOCKET, false)]
    #[cfg(unix)]
    #[case(BLOCK_DEVICE, CHAR_DEVICE, false)]
    #[cfg(unix)]
    #[case(BLOCK_DEVICE, BLOCK_DEVICE, true)]

    fn test_rhai_file_type_equals(
        #[case] lhs: EntryType,
        #[case] rhs: EntryType,
        #[case] expected: bool,
    ) {
        assert_eq!(dir_entry_type_mod::eq(&mut lhs.clone(), rhs), expected);
    }

    /// Given: two RhaiFileTypes
    /// When: they are compared using the not equals "!=" operator
    /// Then: the correct result is returned
    #[rstest]
    // Basic types compared with each other
    #[case(FILE, FILE, false)]
    #[case(FILE, DIR, true)]
    #[case(FILE, SYMLINK, true)]
    #[case(FILE, UNKNOWN, true)]
    #[case(DIR, FILE, true)]
    #[case(DIR, DIR, false)]
    #[case(DIR, SYMLINK, true)]
    #[case(DIR, UNKNOWN, true)]
    #[case(SYMLINK, FILE, true)]
    #[case(SYMLINK, DIR, true)]
    #[case(SYMLINK, SYMLINK, false)]
    #[case(SYMLINK, UNKNOWN, true)]
    #[case(UNKNOWN, FILE, true)]
    #[case(UNKNOWN, DIR, true)]
    #[case(UNKNOWN, SYMLINK, true)]
    #[case(UNKNOWN, UNKNOWN, false)]
    // Basic types compared with Ext types (using Fifo as representative)
    #[cfg(unix)]
    #[case(FILE, FIFO, true)]
    #[cfg(unix)]
    #[case(DIR, FIFO, true)]
    #[cfg(unix)]
    #[case(SYMLINK, FIFO, true)]
    #[cfg(unix)]
    #[case(UNKNOWN, FIFO, true)]
    #[cfg(unix)]
    #[case(FIFO, FILE, true)]
    #[cfg(unix)]
    #[case(FIFO, DIR, true)]
    #[cfg(unix)]
    #[case(FIFO, SYMLINK, true)]
    #[cfg(unix)]
    #[case(FIFO, UNKNOWN, true)]
    // Ext types compared with each other
    #[cfg(unix)]
    #[case(FIFO, FIFO, false)]
    #[cfg(unix)]
    #[case(FIFO, SOCKET, true)]
    #[cfg(unix)]
    #[case(FIFO, CHAR_DEVICE, true)]
    #[cfg(unix)]
    #[case(FIFO, BLOCK_DEVICE, true)]
    #[cfg(unix)]
    #[case(SOCKET, FIFO, true)]
    #[cfg(unix)]
    #[case(SOCKET, SOCKET, false)]
    #[cfg(unix)]
    #[case(SOCKET, CHAR_DEVICE, true)]
    #[cfg(unix)]
    #[case(SOCKET, BLOCK_DEVICE, true)]
    #[cfg(unix)]
    #[case(CHAR_DEVICE, FIFO, true)]
    #[cfg(unix)]
    #[case(CHAR_DEVICE, SOCKET, true)]
    #[cfg(unix)]
    #[case(CHAR_DEVICE, CHAR_DEVICE, false)]
    #[cfg(unix)]
    #[case(CHAR_DEVICE, BLOCK_DEVICE, true)]
    #[cfg(unix)]
    #[case(BLOCK_DEVICE, FIFO, true)]
    #[cfg(unix)]
    #[case(BLOCK_DEVICE, SOCKET, true)]
    #[cfg(unix)]
    #[case(BLOCK_DEVICE, CHAR_DEVICE, true)]
    #[cfg(unix)]
    #[case(BLOCK_DEVICE, BLOCK_DEVICE, false)]

    fn test_rhai_file_type_not_equals(
        #[case] lhs: EntryType,
        #[case] rhs: EntryType,
        #[case] expected: bool,
    ) {
        assert_eq!(dir_entry_type_mod::neq(&mut lhs.clone(), rhs), expected);
    }
}
