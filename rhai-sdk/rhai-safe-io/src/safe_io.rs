#![deny(missing_docs)]
//! The functions used here are declared in the rust-safe-io crate.
#![allow(
    unused_variables,
    unreachable_code,
    unreachable_pub,
    clippy::unreachable,
    unused_mut,
    clippy::needless_pass_by_value,
    dead_code
)]
use rhai::{Array, Dynamic, EvalAltResult};
#[cfg(target_os = "linux")]
use rust_safe_io::RcSymlinkHandle;
#[cfg(unix)]
use rust_safe_io::options::ChmodDirOptions;
#[cfg(target_os = "linux")]
use rust_safe_io::options::DiskAllocationOptions as FallocateOptions;
use rust_safe_io::options::{
    CopyFileOptions, CreateSymlinkOptions, DiskUsageOptions, FindOptions, MoveOptions,
    OpenDirOptions, OpenFileOptions, ReadLinesOptions, ReadPageOptions, ReplacementOptions,
    WriteOptions,
};
use rust_safe_io::options::{DeleteDirOptions, DeleteFileOptions};
#[cfg(not(target_vendor = "apple"))]
#[cfg(unix)]
use rust_safe_io::options::{ExtractArchiveOptions, SetOwnershipOptions, SetXAttrOptions};
use rust_safe_io::{
    DiskUsageEntry, DiskUsageResult, Match, Metadata, Ownership, RcDirHandle, RcFileHandle,
    WordCount,
};

/// Directory configuration and entry point for filesystem operations.
/// This struct represents [`rust_safe_io::DirConfig`] in a format that is compatible with expected Rhai
/// function signature.
#[derive(Debug, Clone, Copy)]
pub struct DirConfig;

/// A handle to a directory for listing, searching, and managing its contents.
/// This struct represents [`RcDirHandle`] in a format that is compatible with expected Rhai
/// function signature.
#[derive(Debug, Clone, Copy)]
pub struct DirHandle;

/// A handle to a file for reading, writing, searching, and managing file content.
/// This struct represents [`RcFileHandle`] in a format that is compatible with expected Rhai
/// function signature.
#[derive(Debug, Clone, Copy)]
pub struct FileHandle;

impl DirConfig {
    /// Opens a directory using the provided [`rust_safe_io::DirConfig`] configuration.
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource | Condition |
    /// |--------|----------|-----------|
    /// | `file_system::Action::"open"` | [`file_system::Dir::"<absolute_path>"`](cedar_auth::fs::entities::DirEntity) | Always |
    /// | `file_system::Action::"create"` | [`file_system::Dir::"<absolute_path>"`](cedar_auth::fs::entities::DirEntity) | When `create(true)` is set |
    ///
    /// NB: When `follow_symlinks(true)` is set,
    /// the resolved target directory is also checked for `open` permission.
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// #     &mut scope,
    /// #     r#"
    /// let dir = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build()
    ///     .open(OpenDirOptions().create(true).build());
    /// #     "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[doc(alias = "cd")]
    #[doc(alias = "mkdir")]
    pub fn open(
        &mut self,
        open_dir_options: OpenDirOptions,
    ) -> Result<RcDirHandle, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }
}

impl DirHandle {
    /// Deletes a directory using the provided [`rust_safe_io::DirConfigBuilder`] configuration.
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"delete"` | [`file_system::Dir::"<absolute_path>"`](cedar_auth::fs::entities::DirEntity) |
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let dir_config = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build();
    /// let dir_handle = dir_config.open(OpenDirOptions().create(true).recursive(true).build());
    /// dir_handle.delete(DeleteDirOptions().force(true).recursive(true).build());
    /// # "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[doc(alias = "rmdir")]
    pub fn delete(
        &mut self,
        delete_dir_options: DeleteDirOptions,
    ) -> Result<(), Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Gets the user and group names of a directory using the provided [`rust_safe_io::DirConfigBuilder`] configuration.
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"stat"` | [`file_system::Dir::"<absolute_path>"`](cedar_auth::fs::entities::DirEntity) |
    ///
    /// # Example
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let dir_config = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build();
    /// let dir_handle = dir_config.open(OpenDirOptions().create(true).build());
    /// let ownership = dir_handle.get_ownership();
    /// let owner = ownership.user;
    /// let group = ownership.group;
    /// print("Directory owner: " + owner + ", group: " + group);
    /// # "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[cfg(unix)]
    pub fn get_ownership(&mut self) -> Result<Ownership, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Opens a file using the provided configuration.
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource | Condition |
    /// |--------|----------|-----------|
    /// | `file_system::Action::"open"` | [`file_system::File::"<absolute_path>"`](cedar_auth::fs::entities::FileEntity) | Always |
    /// | `file_system::Action::"create"` | [`file_system::File::"<absolute_path>"`](cedar_auth::fs::entities::FileEntity) | When `create(true)` is set |
    ///
    /// NB: When `follow_symlinks(true)` is set,
    /// the resolved target file is also checked for `open` permission.
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let dir_config = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build();
    /// let dir_handle = dir_config.open(OpenDirOptions().create(true).recursive(true).build());
    /// let file_handle = dir_handle.open_file("file.txt", OpenFileOptions().create(true).build());
    /// # "#);
    ///
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// # let result = engine.eval_with_scope::<()>(
    /// #    &mut scope,
    /// #    "dir_handle.delete(DeleteDirOptions().force(true).recursive(true).build());"
    /// # );
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[doc(alias = "touch")]
    pub fn open_file(&self, file_name: &str, open_file_options: OpenFileOptions) -> RcFileHandle {
        unreachable!("This method exists only for documentation.")
    }

    /// Resolves a symlink within the directory and returns a the target path as a string.
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"read"` | [`file_system::Dir::"<absolute_path>"`](cedar_auth::fs::entities::DirEntity) |
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let dir_config = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build();
    /// let dir_handle = dir_config.open(OpenDirOptions().create(true).build());
    /// // Assuming a symlink "valid_link" exists and points to a valid file
    /// let target_path = dir_handle.read_link_target("valid_link");
    /// info("Symlink resolved to a path");
    /// # "#);
    /// ```
    #[doc(alias = "readlink")]
    pub fn read_link_target(&mut self, symlink_name: &str) -> Result<String, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Unix-specific: Changes the permissions of a directory specified in [`RcDirHandle`] using [`RcDirHandle::safe_chmod`].
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"chmod"` | [`file_system::Dir::"<absolute_path>"`](cedar_auth::fs::entities::DirEntity) |
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let dir_config = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build();
    /// let dir_handle = dir_config.open(OpenDirOptions().create(true).build());
    /// dir_handle.chmod(ChmodDirOptions().permissions(0o755).build());
    /// # "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[cfg(unix)]
    pub fn chmod(&mut self, chmod_dir_options: ChmodDirOptions) -> Result<(), Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Unix-specific: Changes the ownership of a directory specified in [`RcDirHandle`] using [`RcDirHandle::set_ownership`].
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"chown"` | [`file_system::Dir::"<absolute_path>"`](cedar_auth::fs::entities::DirEntity) |
    ///
    /// # Example
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # use rex_test_utils::rhai::common::get_current_user_and_group;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let (username, groupname) = get_current_user_and_group();
    /// # scope.push_constant("username", username);
    /// # scope.push_constant("groupname", groupname);
    /// #
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let dir_config = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build();
    /// let dir_handle = dir_config.open(OpenDirOptions().create(true).build());
    /// dir_handle.set_ownership(SetOwnershipOptions().user(username).group(groupname).build());
    /// # "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[cfg(unix)]
    #[cfg(not(target_vendor = "apple"))]
    #[doc(alias = "chown")]
    pub fn set_ownership(
        &mut self,
        set_ownership_options: SetOwnershipOptions,
    ) -> Result<(), Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Get the list of directory entries within this directory as [`DirEntry`](crate::dir_entry::DirEntry) objects.
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"read"` | [`file_system::Dir::"<absolute_path>"`](cedar_auth::fs::entities::DirEntity) |
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let dir_config = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build();
    /// let dir_handle = dir_config.open(OpenDirOptions().create(true).recursive(true).build());
    /// let entries = dir_handle.list_entries();
    /// for path in entries.keys() {
    ///     print(path);
    /// }
    ///
    /// // Open entries and read the content
    /// for dir_entry in entries.values() {
    ///     if dir_entry.type() == EntryType::FILE {
    ///         let file_handle = dir_entry.open_as_file(OpenFileOptions().read(true).build());
    ///         let contents = file_handle.read();
    ///         print(dir_entry.name() + ": " + contents);
    ///     }
    /// }
    /// # "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());    
    /// ```
    #[doc(alias = "ls")]
    pub fn list_entries(&mut self) -> Result<rhai::Map, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Find files and directories with filter then execute a callback function on each matching entry.
    ///
    /// This method maintains TOCTOU safety by keeping file descriptors open during traversal
    /// and calling the callback with the actual opened handles. The callback receives
    /// `WalkEntry` data converted to a Rhai-compatible format for processing. File descriptors
    /// are automatically closed when they go out of scope.
    ///
    /// # Cedar Permissions
    ///
    /// Authorization is checked per subdirectory during traversal:
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"open"` | [`file_system::Dir::"<absolute_path>"`](cedar_auth::fs::entities::DirEntity) |
    /// | `file_system::Action::"read"` | [`file_system::Dir::"<absolute_path>"`](cedar_auth::fs::entities::DirEntity) |
    ///
    /// # Warning
    /// This function uses pre-order traversal - we visit each entry before visiting its children,
    /// executing the callback on matching entries. Callbacks that modify directory structure
    /// during traversal (i.e. create, delete, or move) may cause incomplete traversal or errors.
    ///
    /// # Regex Pattern Note
    ///
    /// This function uses the Rust `regex` crate, which does not support PCRE's `\K` (keep) assertion.
    /// To achieve the same effect, remove `\K` and wrap the text you want to capture in parentheses `()`.
    ///
    /// Example:
    /// ```text
    /// # PCRE pattern with \K (not supported)
    /// "execfn: '\K[^']+"
    ///
    /// # Equivalent Rust regex pattern
    /// "execfn: '([^']+)"
    /// ```
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let dir_config = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build();
    /// let dir_handle = dir_config.open(OpenDirOptions().create(true).build());
    /// let size_range = SizeRange::max_only(1000, SizeUnit::BYTES);
    /// let min_creation_time = DateTime(2024, 10, 20, 12, 30, 30, 0);
    /// let max_modification_time = from_epoch_seconds(1735689600);
    /// let find_options = FindOptions()
    ///     .name("*.txt")
    ///     .size_range(size_range)
    ///     .min_creation_time(min_creation_time)
    ///     .max_modification_time(max_modification_time)
    ///     .build();
    ///
    /// dir_handle.find(find_options, |entry| {
    ///     if entry.type() == EntryType::FILE {
    ///         let file_handle = entry.open_as_file(OpenFileOptions().read(true).build());
    ///         let contents = file_handle.read();
    ///     }
    ///     return ();
    /// });
    /// # "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    pub fn find<F>(
        &mut self,
        find_options: &FindOptions,
        mut callback_executor: F,
    ) -> Result<(), Box<EvalAltResult>>
    where
        F: FnMut(Dynamic) -> Result<(), Box<EvalAltResult>>,
    {
        unreachable!("This method exists only for documentation.")
    }

    /// Get the metadata for this directory. See [`Metadata`] for the list of returned fields.
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"stat"` | [`file_system::Dir::"<absolute_path>"`](cedar_auth::fs::entities::DirEntity) |
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let dir_config = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build();
    /// let dir_handle = dir_config.open(OpenDirOptions().create(true).recursive(true).build());
    /// let metadata = dir_handle.metadata();
    /// # "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[doc(alias = "stat")]
    pub fn metadata(&mut self) -> Result<Metadata, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Moves a directory from one location to another, which can be either within the same parent directory or to a different parent directory.
    ///
    /// This operation is atomic when performed within the same filesystem. The method performs authorization checks
    /// to ensure the principal has permission to read from the source and write to the destination.
    ///
    /// For cross filesystem moves in which a directory contains a symlink inside, the operation is not TOCTOU-safe as it is required to
    /// open the symlink after creating it to obtain the FD to set ownership and timestamps on the symlink.
    /// This is done because the sys calls to create a symlink does not return a FD to it.
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"move"` | [`file_system::Dir::"<absolute_path>"`](cedar_auth::fs::entities::DirEntity) |
    /// | `file_system::Action::"create"` | [`file_system::Dir::"<absolute_path>"`](cedar_auth::fs::entities::DirEntity) |
    /// | `file_system::Action::"read"` | [`file_system::Dir::"<absolute_path>"`](cedar_auth::fs::entities::DirEntity) |
    ///
    /// NB: `move` is checked on the source directory, `create` on the destination directory,
    /// and `read` on subdirectories during cross-filesystem moves.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let src_parent_dir = DirConfig()
    ///     .path(temp_dir_path + "/source")
    ///     .build()
    ///     .open(OpenDirOptions().create(true).recursive(true).build());
    ///
    /// let test_dir = DirConfig()
    ///     .path(temp_dir_path + "/source/test_dir")
    ///     .build()
    ///     .open(OpenDirOptions().create(true).build());
    ///
    /// let dest_parent_dir = DirConfig()
    ///     .path(temp_dir_path + "/dest")
    ///     .build()
    ///     .open(OpenDirOptions().create(true).recursive(true).build());
    ///
    ///     let move_options = MoveOptions().build();
    ///     
    ///     let moved_dir = src_parent_dir.move(test_dir, dest_parent_dir, "test_dir_moved", move_options);
    /// "#);
    ///
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err())
    /// ```
    #[doc(alias = "mv")]
    pub fn move_dir(
        &mut self,
        src_dir: RcDirHandle,
        dest_parent_dir: RcDirHandle,
        dest_dirname: &str,
        move_options: &MoveOptions,
    ) -> Result<RcDirHandle, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Creates a symbolic link within the directory.
    ///
    /// This method creates a symbolic link at `link_name` that points to `target_path`.
    /// The target can be either an absolute path or a relative path.
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource | Condition |
    /// |--------|----------|-----------|
    /// | `file_system::Action::"create"` | [`file_system::File::"<absolute_path>"`](cedar_auth::fs::entities::FileEntity) | Always |
    /// | `file_system::Action::"delete"` | [`file_system::File::"<absolute_path>"`](cedar_auth::fs::entities::FileEntity) | When `force(true)` is set |
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let dir_config = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build();
    /// let dir_handle = dir_config.open(OpenDirOptions().create(true).build());
    /// let symlink_options = CreateSymlinkOptions().force(true).build();
    /// dir_handle.create_symlink("/path/to/target", "my_symlink", symlink_options);
    /// # "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[cfg(unix)]
    #[doc(alias = "ln")]
    pub fn create_symlink(
        &mut self,
        target_path: &str,
        link_name: &str,
        create_symlink_options: CreateSymlinkOptions,
    ) -> Result<(), Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Calculates disk usage for a directory and its contents
    ///
    /// # Cedar Permissions
    ///
    /// Authorization is checked per subdirectory during traversal:
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"open"` | [`file_system::Dir::"<absolute_path>"`](cedar_auth::fs::entities::DirEntity) |
    /// | `file_system::Action::"read"` | [`file_system::Dir::"<absolute_path>"`](cedar_auth::fs::entities::DirEntity) |
    ///
    /// NB: Checked for each subdirectory encountered during recursive traversal.
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let dir_config = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build();
    /// let dir_handle = dir_config.open(OpenDirOptions().create(true).build());
    ///
    /// // Basic disk usage
    /// let options = DiskUsageOptions().build();
    /// let results = dir_handle.disk_usage(options);
    ///
    /// for entry in results.entries{
    ///     let path = entry.path;
    ///     let size_bytes = entry.size_bytes;
    ///     let inode_count = entry.inode_count;
    ///     print(`${path}: ${size_bytes} bytes, ${inode_count} inodes`);
    /// }
    ///
    /// // Find largest sub direcotry
    /// let options = DiskUsageOptions().track_largest_subdir(true).build();
    /// let results = dir_handle.disk_usage(options);
    ///
    /// if results.largest_subdir_handle != () {
    ///     let largest_subdir_handle = results.largest_subdir_handle;
    ///     let metadata = largest_subdir_handle.metadata();
    /// }
    /// # "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[cfg(unix)]
    #[doc(alias = "du")]
    pub fn disk_usage(
        &mut self,
        disk_usage_options: DiskUsageOptions,
    ) -> Result<DiskUsageResult, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Opens a symlink (without following it) and returns a handle to the symlink itself.
    ///
    /// The symlink is opened with `O_PATH | O_NOFOLLOW` flags for metadata operations only,
    /// ensuring the symlink itself is opened, **not** its target file.
    /// You **cannot** use this handle to open, read, or write (I/O) the file that the symlink points to.
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"open"` | [`file_system::File::"<absolute_path>"`](cedar_auth::fs::entities::FileEntity) |
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env_with_symlink;
    /// # let (mut scope, engine, _temp_dir, symlink_name) = create_temp_test_env_with_symlink();
    /// # scope.push_constant("symlink_name", symlink_name);
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let dir_config = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build();
    /// let dir_handle = dir_config.open(OpenDirOptions().build());
    /// let symlink_handle = dir_handle.open_symlink(symlink_name);
    /// # "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[cfg(target_os = "linux")]
    pub fn open_symlink(
        &mut self,
        symlink_name: &str,
    ) -> Result<RcSymlinkHandle, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }
}

/// A handle to a symbolic link.
/// This struct represents [`RcSymlinkHandle`] in a format that is compatible with expected Rhai
/// function signature.
#[derive(Debug, Clone, Copy)]
pub struct SymlinkHandle;

impl SymlinkHandle {
    /// Retrieves metadata for the symlink itself (not its target).
    ///
    /// This method fetches metadata information about the symlink, including size, permissions,
    /// modification times, other attributes, and the target path of the symlink itself.
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"stat"` | [`file_system::File::"<absolute_path>"`](cedar_auth::fs::entities::FileEntity) |
    /// | `file_system::Action::"read"` | [`file_system::Dir::"<absolute_path>"`](cedar_auth::fs::entities::DirEntity) |
    ///
    /// # Example
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env_with_symlink;
    /// # let (mut scope, engine, _temp_dir, symlink_name) = create_temp_test_env_with_symlink();
    /// # scope.push_constant("symlink_name", symlink_name);
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let dir_config = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build();
    /// let dir_handle = dir_config.open(OpenDirOptions().build());
    /// let symlink_handle = dir_handle.open_symlink(symlink_name);
    /// let metadata = symlink_handle.metadata();
    /// print("Symlink permissions: " + metadata.permissions());
    /// print("Symlink target: " + metadata.symlink_target());
    /// # "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[cfg(target_os = "linux")]
    #[doc(alias = "stat")]
    #[doc(alias = "readlink")]
    pub fn metadata(&mut self) -> Result<Metadata, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Changes the ownership of a symlink itself (without following it).
    ///
    /// This is equivalent to using `chown -h`.
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"chown"` | [`file_system::File::"<absolute_path>"`](cedar_auth::fs::entities::FileEntity) |
    ///
    /// # Linux Capabilities
    ///
    /// | Capability | Required |
    /// |------------|----------|
    /// | `CAP_CHOWN` | Always |
    ///
    /// Only supported on Linux-based platforms.
    ///
    /// # Example
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env_with_symlink;
    /// # use rex_test_utils::rhai::common::get_current_user_and_group;
    /// # let (username, groupname) = get_current_user_and_group();
    /// # let (mut scope, engine, _temp_dir, symlink_name) = create_temp_test_env_with_symlink();
    /// # scope.push_constant("username", username);
    /// # scope.push_constant("groupname", groupname);
    /// # scope.push_constant("symlink_name", symlink_name);
    ///
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let dir_config = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build();
    /// let dir_handle = dir_config.open(OpenDirOptions().build());
    /// let symlink_handle = dir_handle.open_symlink(symlink_name);
    /// symlink_handle.set_ownership(SetOwnershipOptions().user(username).group(groupname).build());
    /// # "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[cfg(target_os = "linux")]
    #[doc(alias = "chown")]
    pub fn set_ownership(
        &mut self,
        set_ownership_options: SetOwnershipOptions,
    ) -> Result<(), Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }
}

impl FileHandle {
    /// Writes to a file specified in [`RcFileHandle`] using [`RcFileHandle::safe_write`]
    ///
    /// The file is written atomically via a temp file and rename. By default,
    /// the write attempts to preserve the original file's ownership (uid/gid).
    /// This requires `CAP_CHOWN` when the file is owned by a different user. To disable
    /// this and let the file be owned by the current user and group, pass
    /// [`WriteOptions`] with [`preserve_ownership(false)`](WriteOptions::preserve_ownership).
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"write"` | [`file_system::File::"<absolute_path>"`](cedar_auth::fs::entities::FileEntity) |
    ///
    /// # Linux Capabilities
    ///
    /// | Capability | Condition |
    /// |------------|-----------|
    /// | `CAP_CHOWN` | By default, when file is owned by a different user. Disable with [`preserve_ownership(false)`](WriteOptions::preserve_ownership) |
    /// | `CAP_DAC_OVERRIDE` | When the file's parent directory is owned by a different user (existing behavior) |
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let dir_config = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build();
    /// let dir_handle = dir_config.open(OpenDirOptions().create(true).recursive(true).build());
    /// let file_handle = dir_handle.open_file("file.txt", OpenFileOptions().create(true).build());
    ///
    /// // Simple write
    /// file_handle = file_handle.write("Hello World");
    ///
    /// // Write without ownership preservation
    /// let write_opts = WriteOptions().preserve_ownership(false).build();
    /// file_handle = file_handle.write("Hello World", write_opts);
    /// # "#);
    /// #
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// # let result = engine.eval_with_scope::<()>(
    /// #   &mut scope,
    /// #   "dir_handle.delete(DeleteDirOptions().force(true).recursive(true).build());"
    /// # );
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    pub fn write(
        &mut self,
        content: &str,
        write_options: WriteOptions,
    ) -> Result<FileHandle, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Unix-specific: Writes to a file specified in [`RcFileHandle`] using [`RcFileHandle::safe_write_in_place`]
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"write"` | [`file_system::File::"<absolute_path>"`](cedar_auth::fs::entities::FileEntity) |
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let dir_config = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build();
    /// let dir_handle = dir_config.open(OpenDirOptions().create(true).recursive(true).build());
    /// let file_handle = dir_handle.open_file("file.txt", OpenFileOptions().write(true).create(true).build());
    /// file_handle.write_in_place("Hello World");
    /// # "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[cfg(unix)]
    pub fn write_in_place(&mut self, content: &str) -> Result<(), Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Reads a file specified in [`RcFileHandle`] using [`RcFileHandle::safe_read`].
    ///
    /// # Cedar Permissions
    ///
    /// One of the following is required:
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"read"` | [`file_system::File::"<absolute_path>"`](cedar_auth::fs::entities::FileEntity) |
    ///
    /// OR
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"redacted_read"` | [`file_system::File::"<absolute_path>"`](cedar_auth::fs::entities::FileEntity) |
    ///
    /// NB: When `read` is granted, full content is returned.
    /// When only `redacted_read` is granted, content is returned with sensitive data redacted
    /// using patterns from the redaction dictionary (`/etc/opt/rex/rex_redaction.config`).
    /// The `redacted_read` mode also requires `open` on Dir `/etc/opt/rex` and
    /// `open`+`read` on the redaction config file.
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let dir_config = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build();
    /// let dir_handle = dir_config.open(OpenDirOptions().create(true).recursive(true).build());
    /// let file_handle = dir_handle.open_file("test.txt", OpenFileOptions().create(true).build());
    ///
    /// let file_handle = dir_handle.open_file("test.txt", OpenFileOptions().read(true).build());
    /// let content = file_handle.read();
    /// # "#);
    /// #
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// # let result = engine.eval_with_scope::<()>(
    /// #   &mut scope,
    /// #   "dir_handle.delete(DeleteDirOptions().force(true).recursive(true).build());"
    /// # );
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[doc(alias = "cat")]
    pub fn read(&mut self) -> Result<String, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Reads the first N lines from a file specified in [`RcFileHandle`] using [`RcFileHandle::safe_read_lines`]
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"read"` | [`file_system::File::"<absolute_path>"`](cedar_auth::fs::entities::FileEntity) |
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let dir_config = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build();
    /// let dir_handle = dir_config.open(OpenDirOptions().create(true).recursive(true).build());
    /// let file_handle = dir_handle.open_file("file.txt", OpenFileOptions().read(true).create(true).build());
    /// let lines = file_handle.read_lines(ReadLinesOptions().count(10).build());
    /// # "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// # let result = engine.eval_with_scope::<()>(
    /// #   &mut scope,
    /// #   "dir_handle.delete(DeleteDirOptions().force(true).recursive(true).build());"
    /// # );
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[doc(alias = "head")]
    #[doc(alias = "tail")]
    pub fn read_lines(
        &mut self,
        options: ReadLinesOptions,
    ) -> Result<Vec<String>, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Reads a file in paginated chunks using [`RcFileHandle::safe_read_page`]
    ///
    /// This method enables reading large files incrementally without loading the entire file into memory.
    /// It maintains state between calls, allowing you to iterate through the file page by page.
    /// When the end of file is reached, an empty array is returned.
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"read"` | [`file_system::File::"<absolute_path>"`](cedar_auth::fs::entities::FileEntity) |
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let dir_config = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build();
    /// let dir_handle = dir_config.open(OpenDirOptions().create(true).recursive(true).build());
    /// let file_handle = dir_handle.open_file("large_file.txt", OpenFileOptions().read(true).create(true).build());
    ///
    /// // Read file in pages of 5 lines each
    /// let all_lines = [];
    /// loop {
    ///     let page = file_handle.read_page(ReadPageOptions().num_lines(5).build());
    ///     if page.len() == 0 {
    ///         break;  // EOF reached
    ///     }
    ///     all_lines += page;
    /// }
    ///
    /// // Iterate over all accumulated lines
    /// for line in all_lines {
    ///     print(line);
    /// }
    /// # "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// # let result = engine.eval_with_scope::<()>(
    /// #   &mut scope,
    /// #   "dir_handle.delete(DeleteDirOptions().force(true).recursive(true).build());"
    /// # );
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    pub fn read_page(
        &mut self,
        options: ReadPageOptions,
    ) -> Result<Vec<String>, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Deletes a file specified in [`RcFileHandle`] using [`RcFileHandle::safe_delete`].
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"delete"` | [`file_system::File::"<absolute_path>"`](cedar_auth::fs::entities::FileEntity) |
    ///
    /// # Errors
    ///
    /// Authz check failed
    ///
    /// If directory cannot be opened (e.g., due to symlinks) or does not exist with `force`, an error [`std::io::ErrorKind`] is thrown by `create_dir_obj`.
    ///
    /// If the file type [`std::fs::DirEntry::file_type`] cannot be removed by `remove_file` [`std::fs::remove_file`] then an error [`std::io::ErrorKind`] will be returned.
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let dir_config = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build();
    /// let dir_handle = dir_config.open(OpenDirOptions().create(true).recursive(true).build());
    /// let file_handle = dir_handle.open_file("file.txt", OpenFileOptions().create(true).build());
    /// file_handle.delete(DeleteFileOptions().force(true).build());
    /// # "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[doc(alias = "rm")]
    pub fn delete(
        &mut self,
        delete_file_options: DeleteFileOptions,
    ) -> Result<(), Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    ///  Unix-specific: Changes the permissions of a file specified in [`RcFileHandle`] using [`RcFileHandle::safe_chmod`].
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"chmod"` | [`file_system::File::"<absolute_path>"`](cedar_auth::fs::entities::FileEntity) |
    ///
    /// # Arguments
    ///
    /// * `permissions` - The new permissions to set (as an i64 octal value for Rhai compatibility)
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let dir_config = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build();
    /// let dir_handle = dir_config.open(OpenDirOptions().create(true).recursive(true).build());
    /// let file_handle = dir_handle.open_file("file.txt", OpenFileOptions().create(true).build());
    /// file_handle.chmod(0o600);
    /// # "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[cfg(unix)]
    pub fn chmod(&mut self, permissions: i64) -> Result<(), Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Gets the last modified time of a file specified in [`RcFileHandle`] using [`RcFileHandle::safe_get_last_modified_time`].
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"stat"` | [`file_system::File::"<absolute_path>"`](cedar_auth::fs::entities::FileEntity) |
    ///
    /// # Returns
    /// * `Result<i64>` - The last modified time as nanoseconds since Unix epoch (January 1, 1970 UTC)
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let dir_config = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build();
    /// let dir_handle = dir_config.open(OpenDirOptions().create(true).recursive(true).build());
    /// let file_handle = dir_handle.open_file("test.txt", OpenFileOptions().create(true).build());
    /// file_handle = file_handle.write("Hello World");
    ///
    /// let modified_time = file_handle.get_last_modified_time();
    /// # "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[cfg(unix)]
    #[doc(alias = "stat")]
    pub fn get_last_modified_time(&mut self) -> Result<i64, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Gets the user and group names of a file. Only supported for unix based platforms.
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"stat"` | [`file_system::File::"<absolute_path>"`](cedar_auth::fs::entities::FileEntity) |
    ///
    /// # Example
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let dir_config = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build();
    /// let dir_handle = dir_config.open(OpenDirOptions().create(true).build());
    /// let file_handle = dir_handle.open_file("file.txt", OpenFileOptions().create(true).build());
    /// let ownership = file_handle.get_ownership();
    /// let owner = ownership.user;
    /// let group = ownership.group;
    /// print("File owner: " + owner + ", group: " + group);
    /// # "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[cfg(unix)]
    pub fn get_ownership(&mut self) -> Result<Ownership, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Searches for regex patterns in the file content using [`RcFileHandle::safe_search`].
    ///
    /// This method performs line-by-line regex searching and returns an array of matches.
    /// Each match contains the line number and content for grep-like behavior.
    ///
    /// # Cedar Permissions
    ///
    /// One of the following is required:
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"read"` | [`file_system::File::"<absolute_path>"`](cedar_auth::fs::entities::FileEntity) |
    ///
    /// OR
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"redacted_read"` | [`file_system::File::"<absolute_path>"`](cedar_auth::fs::entities::FileEntity) |
    ///
    /// NB: When `read` is granted, full match content is returned.
    /// When only `redacted_read` is granted, match content is returned with sensitive data redacted
    /// using patterns from the redaction dictionary (`/etc/opt/rex/rex_redaction.config`).
    /// The `redacted_read` mode also requires `open` on Dir `/etc/opt/rex` and
    /// `open`+`read` on the redaction config file.
    ///
    /// # Regex Syntax
    /// Uses Rust's [`regex`](https://docs.rs/regex/1.11.1/regex/) crate (v1.11.1).
    /// See full syntax documentation: <https://docs.rs/regex/1.11.1/regex/#syntax>
    ///
    /// **Important**: This is **NOT** PCRE or JavaScript regex syntax.
    ///
    /// # Regex Pattern Note
    ///
    /// This function uses the Rust `regex` crate, which does not support PCRE's `\K` (keep) assertion.
    /// To achieve the same effect, remove `\K` and wrap the text you want to capture in parentheses `()`.
    ///
    /// Example:
    /// ```text
    /// # PCRE pattern with \K (not supported)
    /// "execfn: '\K[^']+"
    ///
    /// # Equivalent Rust regex pattern
    /// "execfn: '([^']+)"
    /// ```
    ///
    /// # Arguments
    /// * `pattern` - Regex pattern to search for in the file content
    ///
    /// # Returns
    /// * `Result<Array>` - Array of [`rust_safe_io::Match`] objects
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let dir_config = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build();
    /// let dir_handle = dir_config.open(OpenDirOptions().create(true).build());
    /// let file_handle = dir_handle.open_file("test.log", OpenFileOptions().create(true).read(true).build());
    ///
    /// let matches = file_handle.search("ERROR");
    ///
    /// for m in matches {
    ///     print(`Line ${m.line_number}: ${m.line_content}`);
    /// }
    /// # "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[doc(alias = "grep")]
    pub fn search(&mut self, pattern: &str) -> Result<Vec<Match>, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Changes the ownership of a file specified in [`RcFileHandle`] using [`RcFileHandle::set_ownership`].  Only supported for unix based platforms.
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"chown"` | [`file_system::File::"<absolute_path>"`](cedar_auth::fs::entities::FileEntity) |
    ///
    /// # Example
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # use rex_test_utils::rhai::common::get_current_user_and_group;
    /// # let (username, groupname) = get_current_user_and_group();
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # scope.push_constant("username", username);
    /// # scope.push_constant("groupname", groupname);
    ///
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let dir_config = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build();
    /// let dir_handle = dir_config.open(OpenDirOptions().create(true).recursive(true).build());
    /// let file_handle = dir_handle.open_file("file.txt", OpenFileOptions().create(true).build());
    /// file_handle.set_ownership(SetOwnershipOptions().user(username).group(groupname).build());
    /// # "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[cfg(unix)]
    #[cfg(not(target_vendor = "apple"))]
    #[doc(alias = "chown")]
    pub fn set_ownership(
        &mut self,
        set_ownership_options: SetOwnershipOptions,
    ) -> Result<(), Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Copies a file to a destination file specified in [`RcFileHandle`] using [`RcFileHandle::safe_copy`]
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"read"` | [`file_system::File::"<absolute_path>"`](cedar_auth::fs::entities::FileEntity) |
    /// | `file_system::Action::"write"` | [`file_system::File::"<absolute_path>"`](cedar_auth::fs::entities::FileEntity) |
    ///
    /// NB: `read` is checked on the source file, `write` on the destination file.
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let dir_config = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build();
    /// let dir_handle = dir_config.open(OpenDirOptions().create(true).recursive(true).build());
    ///
    /// let src_file = dir_handle.open_file("source.txt", OpenFileOptions().read(true).write(true).create(true).build());
    /// src_file = src_file.write("Hello World");
    ///
    /// let dest_file = dir_handle.open_file("dest.txt", OpenFileOptions().create(true).build());
    ///
    /// // Copy source to destination
    /// let copy_file_options = CopyFileOptions()
    ///     .force(true)
    ///     .preserve(true)
    ///     .build();
    ///
    /// let copied_file = src_file.copy(dest_file, copy_file_options);
    /// # "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[doc(alias = "cp")]
    pub fn copy(
        &mut self,
        destination: RcFileHandle,
        copy_file_options: CopyFileOptions,
    ) -> Result<RcFileHandle, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Get the metadata for this file. See [`Metadata`] for the list of returned fields.
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"stat"` | [`file_system::File::"<absolute_path>"`](cedar_auth::fs::entities::FileEntity) |
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let dir_config = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build();
    /// let dir_handle = dir_config.open(OpenDirOptions().create(true).recursive(true).build());
    /// let metadata = dir_handle.metadata();
    /// # "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[doc(alias = "stat")]
    pub fn metadata(&mut self) -> Result<Metadata, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Extracts a tar/tar.gz archive to a destination directory using [`RcFileHandle::safe_extract_archive`].
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource | Condition |
    /// |--------|----------|-----------|
    /// | `file_system::Action::"read"` | [`file_system::File::"<absolute_path>"`](cedar_auth::fs::entities::FileEntity) | Always (source archive) |
    /// | `file_system::Action::"create"` | [`file_system::File::"<absolute_path>"`](cedar_auth::fs::entities::FileEntity) | Per extracted entry |
    /// | `file_system::Action::"write"` | [`file_system::File::"<absolute_path>"`](cedar_auth::fs::entities::FileEntity) | Per extracted entry |
    /// | `file_system::Action::"chmod"` | [`file_system::File::"<absolute_path>"`](cedar_auth::fs::entities::FileEntity) | When `preserve_permissions(true)` is set |
    /// | `file_system::Action::"chown"` | [`file_system::File::"<absolute_path>"`](cedar_auth::fs::entities::FileEntity) | When `preserve_ownership(true)` is set |
    ///
    /// NB: `read` is checked on the source archive, all other actions on each extracted entry
    /// in the destination directory.
    ///
    /// # Example
    /// ```no_run
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let dir_config = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build();
    /// let dir_handle = dir_config.open(OpenDirOptions().build());
    /// let archive_file = dir_handle.open_file("archive.tar.gz", OpenFileOptions().read(true).build());
    ///
    /// let extract_dir = DirConfig()
    ///     .path(temp_dir_path + "/extract")
    ///     .build()
    ///     .open(OpenDirOptions().create(true).recursive(true).build());
    ///
    /// let extract_options = ExtractArchiveOptions()
    ///     .preserve_permissions(true)
    ///     .preserve_timestamps(true)
    ///     .build();
    ///
    /// archive_file.extract_archive(extract_dir, extract_options);
    /// # "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[cfg(unix)]
    #[cfg(not(target_vendor = "apple"))]
    #[doc(alias = "tar")]
    pub fn extract_archive(
        &mut self,
        dest_dir: DirHandle,
        extract_options: ExtractArchiveOptions,
    ) -> Result<(), Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Counts lines, words, and bytes in a file using [`RcFileHandle::counts`].
    ///
    /// This method performs a word count operation similar to the Unix `wc` command.
    /// It counts lines, words, and bytes in the file.
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"read"` | [`file_system::File::"<absolute_path>"`](cedar_auth::fs::entities::FileEntity) |
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let dir_config = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build();
    /// let dir_handle = dir_config.open(OpenDirOptions().create(true).build());
    /// let file_handle = dir_handle.open_file("test.txt", OpenFileOptions().read(true).create(true).build());
    /// let counts = file_handle.counts();
    /// let lines = counts.line_count;
    /// let words = counts.word_count;
    /// let bytes = counts.byte_count;
    /// # "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[cfg(unix)]
    #[doc(alias = "wc")]
    pub fn counts(&mut self) -> Result<WordCount, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Extracts printable strings from a file.
    ///
    /// This method reads the file and extracts sequences of printable ASCII characters
    /// that are at least 4 characters long.
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"read"` | [`file_system::File::"<absolute_path>"`](cedar_auth::fs::entities::FileEntity) |
    ///
    /// # Returns
    /// * `Result<Array, Box<EvalAltResult>>` - Array containing the extracted strings
    ///
    /// # Errors
    /// * The caller was not authorized to open the file
    /// * The file was not opened with read permissions
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let dir_config = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build();
    /// let dir_handle = dir_config.open(OpenDirOptions().create(true).recursive(true).build());
    /// let file_handle = dir_handle.open_file("file.txt", OpenFileOptions().read(true).create(true).build());
    /// let strings = file_handle.extract_strings();
    /// # "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[doc(alias = "strings")]
    pub fn extract_strings(&mut self) -> Result<Vec<String>, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Moves a file from one location to another, which can be either within the same directory or to a different directory.
    ///
    /// This operation is atomic when performed within the same filesystem. The method performs authorization checks
    /// to ensure the principal has permission to read from the source and write to the destination.
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"move"` | [`file_system::File::"<absolute_path>"`](cedar_auth::fs::entities::FileEntity) |
    /// | `file_system::Action::"create"` | [`file_system::File::"<absolute_path>"`](cedar_auth::fs::entities::FileEntity) |
    ///
    /// NB: `move` is checked on the source file, `create` on the destination file.
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let src_dir = DirConfig()
    ///     .path(temp_dir_path + "/source")
    ///     .build()
    ///     .open(OpenDirOptions().create(true).recursive(true).build());
    ///
    /// let dest_dir = DirConfig()
    ///     .path(temp_dir_path + "/dest")
    ///     .build()
    ///     .open(OpenDirOptions().create(true).recursive(true).build());
    ///
    /// let src_file = src_dir.open_file("test.txt", OpenFileOptions().create(true).read(true).write(true).build());
    /// src_file = src_file.write("Hello World");
    ///
    /// let move_options = MoveOptions().backup(true).build();
    /// let moved_file = src_file.move(dest_dir, "test_moved.txt", move_options);
    /// # "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[doc(alias = "mv")]
    pub fn move_file(
        &mut self,
        dest_dir: DirHandle,
        dest_filename: &str,
        move_options: MoveOptions,
    ) -> Result<RcFileHandle, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Calculates disk usage for a file
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"stat"` | [`file_system::File::"<absolute_path>"`](cedar_auth::fs::entities::FileEntity) |
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let dir_config = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build();
    /// let dir_handle = dir_config.open(OpenDirOptions().create(true).build());
    /// let file_handle = dir_handle.open_file("test.txt", OpenFileOptions().create(true).read(true).build());
    ///
    /// // Get actual disk usage
    /// let options = DiskUsageOptions().build();
    /// let entry = file_handle.disk_usage(options);
    /// print(`Disk usage: ${entry.size_bytes} bytes, ${entry.inode_count} inodes`);
    ///
    /// // Get apparent size
    /// let options_apparent = DiskUsageOptions().apparent_size(true).build();
    /// let entry_apparent = file_handle.disk_usage(options_apparent);
    /// print(`File size: ${entry_apparent.size_bytes} bytes`);
    /// # "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[cfg(unix)]
    #[doc(alias = "du")]
    pub fn disk_usage(
        &mut self,
        disk_usage_options: DiskUsageOptions,
    ) -> Result<DiskUsageEntry, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Preallocates disk space for a file.
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"write"` | [`file_system::File::"<absolute_path>"`](cedar_auth::fs::entities::FileEntity) |
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let dir_config = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build();
    /// let dir_handle = dir_config.open(OpenDirOptions().create(true).build());
    /// let file_handle = dir_handle.open_file("swapfile", OpenFileOptions().write(true).create(true).build());
    ///
    /// // Allocate 1 MiB for a swap file
    /// file_handle.fallocate(FallocateOptions().length(1).format(SizeUnit::MEBIBYTES).build());
    ///
    /// // Allocate 1 MB using default format (Bytes)
    /// file_handle.fallocate(FallocateOptions().length(1048576).build());
    /// # "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[cfg(target_os = "linux")]
    pub fn fallocate(
        &mut self,
        fallocate_options: FallocateOptions,
    ) -> Result<(), Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Verifies this server certificate against a certificate chain with intermediate CAs.
    ///
    /// This replicates the behavior of:
    /// ```bash
    /// openssl verify -CAfile root.pem -untrusted intermediate.pem server.pem
    /// ```
    ///
    /// # Cedar Permissions
    ///
    /// No additional Cedar permissions required beyond those checked at file open time.
    ///
    /// For certificates directly signed by a root CA (no intermediate), use [`RcFileHandle::verify_cert`] instead.
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env_with_cert_fixtures;
    /// # let (mut scope, engine, _temp_dir) = create_temp_test_env_with_cert_fixtures();
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let dir = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build()
    ///     .open(OpenDirOptions().build());
    ///
    /// let server_cert = dir.open_file("server.pem", OpenFileOptions().read(true).build());
    /// let root_ca = dir.open_file("root-ca.pem", OpenFileOptions().read(true).build());
    /// let intermediate_ca = dir.open_file("intermediate-ca.pem", OpenFileOptions().read(true).build());
    ///
    /// // Verify the certificate chain (3-tier: root -> intermediate -> server)
    /// server_cert.verify_cert_chain(root_ca, [intermediate_ca]);
    /// # "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[doc(alias = "openssl")]
    pub fn verify_cert_chain(
        &mut self,
        root_ca: RcFileHandle,
        intermediate_cas: Array,
    ) -> Result<(), Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Verifies this server certificate directly against a root CA (no intermediate).
    ///
    /// This replicates the behavior of:
    /// ```bash
    /// openssl verify -CAfile root.pem server.pem
    /// ```
    ///
    /// # Cedar Permissions
    ///
    /// No additional Cedar permissions required beyond those checked at file open time.
    ///
    /// Use this when the server certificate is directly signed by the root CA.
    /// For certificates with an intermediate CA, use [`RcFileHandle::verify_cert_chain`] instead.
    ///
    /// # Example
    ///
    /// ```
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env_with_cert_fixtures;
    /// # let (mut scope, engine, _temp_dir) = create_temp_test_env_with_cert_fixtures();
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let dir = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build()
    ///     .open(OpenDirOptions().build());
    ///
    /// let server_cert = dir.open_file("server-direct.pem", OpenFileOptions().read(true).build());
    /// let root_ca = dir.open_file("root-ca.pem", OpenFileOptions().read(true).build());
    ///
    /// // Verify the certificate (2-tier: root -> server)
    /// server_cert.verify_cert(root_ca);
    /// # "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[doc(alias = "openssl")]
    pub fn verify_cert(&mut self, root_ca: RcFileHandle) -> Result<(), Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }

    /// Linux-specific: Sets an extended attribute on a file using [`RcFileHandle::safe_set_xattr`].
    ///
    /// Extended attributes allow storing additional metadata with files on supported filesystems.
    /// Currently only supports the `security.selinux` extended attribute for modifying `SELinux` contexts.
    ///
    /// # Example
    /// ```no_run
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let dir_config = DirConfig()
    ///     .path(temp_dir_path)
    ///     .build();
    /// let dir_handle = dir_config.open(OpenDirOptions().create(true).build());
    /// let file_handle = dir_handle.open_file("example.txt", OpenFileOptions().create(true).build());
    /// file_handle.set_extended_attr(SetXAttrOptions().name("security.selinux").selinux_type("unconfined_t").build());
    /// # "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[cfg(target_os = "linux")]
    #[doc(alias = "chcon")]
    pub fn set_extended_attr(
        &mut self,
        set_xattr_options: SetXAttrOptions,
    ) -> Result<(), Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }
}

/// Replaces text using either string matching or [rust regex patterns](https://docs.rs/regex/latest/regex/)
///
/// # Cedar Permissions
///
/// No Cedar permissions required. This is a pure string operation.
///
/// # Arguments
/// * `text` - The input text to search and replace in
/// * `old_string` - The pattern to search for (string or regex)
/// * `new_string` - The replacement text
/// * `replacement_options` - Options controlling the replacement behavior
///
/// # Returns
/// * `Result<String, Box<EvalAltResult>>` - The text with replacements applied
///
/// # Regex Pattern Notes
///
/// This function uses the Rust `regex` crate, which has different syntax from PCRE:
///
/// 1. **`\K` (keep) assertion is not supported**. To achieve the same effect, remove `\K` and wrap
///    the text you want to capture in parentheses `()`.
///
///    Example:
///    ```text
///    # PCRE pattern with \K (not supported)
///    "execfn: '\K[^']+"
///
///    # Equivalent Rust regex pattern
///    "execfn: '([^']+)"
///    ```
///
/// 2. **Replacement syntax uses `$1` instead of `\1`** for capture group references.
///
///    Example:
///    ```rhai
///    let text = "execfn: 'myapp'";
///    let options = ReplacementOptions().is_regex(true).build();
///    let result = replace_text(text, "execfn: '([^']+)'", "$1", options);
///    print(result);  // Prints "myapp"
///    ```
///
/// # Example
///
/// ```
/// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
/// # let (mut scope, engine) = create_temp_test_env();
/// # let result = engine.eval_with_scope::<()>(
/// # &mut scope,
/// # r#"
/// let options = ReplacementOptions().is_regex(true).replace_all(true).build();
/// let result = replace_text("Hello world", "world", "Rhai", options);
/// print(result);  // Prints "Hello Rhai"
/// # "#);
/// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
/// ```
#[doc(alias = "sed")]
pub fn replace_text(
    text: &str,
    old_string: &str,
    new_string: &str,
    replacement_options: ReplacementOptions,
) -> Result<String, Box<EvalAltResult>> {
    unreachable!("This method exists only for documentation.")
}
/// Returns the system hostname.
///
/// # Example
///
/// ```rhai
/// let name = hostname();
/// print(`Host: ${name}`);
/// ```
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn hostname() -> Result<String, Box<EvalAltResult>> {
    unreachable!("This method exists only for documentation.")
}

/// Returns memory and swap usage as a map.
///
/// Keys: total, free, available, used, `swap_total`, `swap_free`, `swap_used`
///
/// # Example
///
/// ```rhai
/// let mem = free();
/// print(`Memory: ${mem.total} total, ${mem.available} available`);
/// ```
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn free() -> Result<rhai::Map, Box<EvalAltResult>> {
    unreachable!("This method exists only for documentation.")
}

/// Returns filesystem disk space usage as an array of Filesystem structs.
///
/// Each entry exposes: `fs_device`, `fs_kind`, `mounted_on`, `kb_blocks`, `mb_blocks`,
/// `block_used`, `block_available`, `block_use_percent`, `inodes`, `iused`, `ifree`,
/// `iuse_percent`, `raw_size`, `mount_options`
///
/// # Example
///
/// ```rhai
/// let filesystems = df();
/// for fs in filesystems {
///     print(`${fs.mounted_on}: ${fs.block_use_percent}% used`);
/// }
/// ```
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn df() -> Result<Array, Box<EvalAltResult>> {
    unreachable!("This method exists only for documentation.")
}

/// Returns the number of logical CPUs.
///
/// # Example
///
/// ```rhai
/// let cpus = nproc();
/// print(`CPUs: ${cpus}`);
/// ```
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn nproc() -> Result<i64, Box<EvalAltResult>> {
    unreachable!("This method exists only for documentation.")
}

/// Copies a file from source to destination.
///
/// Supports flags: `cp::force` (`cp::f`), `cp::preserve` (`cp::p`)
///
/// # Example
///
/// ```rhai
/// cp("/path/to/source.txt", "/path/to/dest.txt");
/// cp([cp::force, cp::preserve], "/src.txt", "/dst.txt");
/// ```
pub(crate) fn cp(src: &str, dst: &str) -> Result<(), Box<EvalAltResult>> {
    unreachable!("This method exists only for documentation.")
}

/// Moves or renames a file.
///
/// # Example
///
/// ```rhai
/// mv("/path/to/old.txt", "/path/to/new.txt");
/// ```
pub(crate) fn mv(src: &str, dst: &str) -> Result<(), Box<EvalAltResult>> {
    unreachable!("This method exists only for documentation.")
}

/// Creates directories recursively (like `mkdir -p`).
///
/// # Example
///
/// ```rhai
/// mkdir("/tmp/parent/child/grandchild");
/// ```
pub(crate) fn mkdir(path: &str) -> Result<(), Box<EvalAltResult>> {
    unreachable!("This method exists only for documentation.")
}

/// Returns system information as a map (Linux only).
///
/// Keys: `kernel_name`, nodename, `kernel_release`, `kernel_version`, machine,
/// processor, `hardware_platform`, `operating_system`
///
/// # Example
///
/// ```rhai
/// let info = uname();
/// print(`${info.kernel_name} ${info.nodename} ${info.kernel_release}`);
/// ```
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn uname() -> Result<rhai::Map, Box<EvalAltResult>> {
    unreachable!("This method exists only for documentation.")
}

/// Returns kernel ring buffer messages as an array of maps (Linux only).
///
/// Each map contains: timestamp, message
///
/// # Example
///
/// ```rhai
/// let entries = dmesg();
/// for entry in entries {
///     print(`[${entry.timestamp}] ${entry.message}`);
/// }
/// ```
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn dmesg() -> Result<Array, Box<EvalAltResult>> {
    unreachable!("This method exists only for documentation.")
}

/// Returns I/O statistics as a map with cpu and devices keys.
///
/// # Example
///
/// ```rhai
/// let stats = iostat();
/// print(`CPU idle: ${stats.cpu.idle_percent}%`);
/// for dev in stats.devices {
///     print(`${dev.device_name}: ${dev.util_percent}% util`);
/// }
/// ```
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn iostat() -> Result<rhai::Map, Box<EvalAltResult>> {
    unreachable!("This method exists only for documentation.")
}

/// Returns network interfaces and their IP addresses.
///
/// Each map contains: name, addresses (array of strings)
///
/// # Example
///
/// ```rhai
/// let interfaces = ip_addr();
/// for iface in interfaces {
///     print(`${iface.name}: ${iface.addresses}`);
/// }
/// ```
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn ip_addr() -> Result<Array, Box<EvalAltResult>> {
    unreachable!("This method exists only for documentation.")
}

/// Returns disk usage for a directory as a map (Unix only).
///
/// Keys: entries (array of {path, `size_bytes`, `inode_count`}), `total_size_bytes`, `total_inode_count`
///
/// # Example
///
/// ```rhai
/// let usage = du("/path/to/dir");
/// print(`Total: ${usage.total_size_bytes} bytes`);
/// ```
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn du(path: &str) -> Result<rhai::Map, Box<EvalAltResult>> {
    unreachable!("This method exists only for documentation.")
}

/// Returns network connection statistics as a map (Linux only).
///
/// Keys: internet (array of connection maps), unix (array of socket maps)
///
/// # Example
///
/// ```rhai
/// let stats = netstat();
/// for conn in stats.internet {
///     print(`${conn.protocol} ${conn.local_address} -> ${conn.remote_address}`);
/// }
/// ```
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn netstat() -> Result<rhai::Map, Box<EvalAltResult>> {
    unreachable!("This method exists only for documentation.")
}

/// Performs an HTTP GET request and returns status + body.
///
/// Returns a map with: status (i64), text (String)
///
/// # Example
///
/// ```rhai
/// let response = curl("https://example.com");
/// print(`Status: ${response.status}`);
/// print(response.text);
/// ```
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn curl(url: &str) -> Result<rhai::Map, Box<EvalAltResult>> {
    unreachable!("This method exists only for documentation.")
}

/// Reads a kernel parameter value (Linux only).
///
/// # Example
///
/// ```rhai
/// let val = sysctl_read("kernel.hostname");
/// print(val);
/// ```
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn sysctl_read(key: &str) -> Result<String, Box<EvalAltResult>> {
    unreachable!("This method exists only for documentation.")
}

/// Finds kernel parameters matching a regex pattern (Linux only).
///
/// Returns an array of maps with: key, value
///
/// # Example
///
/// ```rhai
/// let entries = sysctl_find("net.ipv4");
/// for e in entries { print(`${e.key} = ${e.value}`); }
/// ```
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn sysctl_find(pattern: &str) -> Result<Array, Box<EvalAltResult>> {
    unreachable!("This method exists only for documentation.")
}

/// Writes a kernel parameter value (Linux only).
///
/// # Example
///
/// ```rhai
/// sysctl_write("net.ipv4.ip_forward", "1");
/// ```
pub(crate) fn sysctl_write(key: &str, value: &str) -> Result<(), Box<EvalAltResult>> {
    unreachable!("This method exists only for documentation.")
}

/// Resolves a hostname to IP addresses.
///
/// Returns an array of IP address strings.
///
/// # Example
///
/// ```rhai
/// let ips = resolve("example.com");
/// for ip in ips { print(ip); }
/// ```
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn resolve(hostname: &str) -> Result<Array, Box<EvalAltResult>> {
    unreachable!("This method exists only for documentation.")
}

/// Creates an empty file or opens an existing one at the given path.
///
/// # Example
///
/// ```rhai
/// touch("/tmp/newfile.txt");
/// ```
pub(crate) fn touch(path: &str) -> Result<(), Box<EvalAltResult>> {
    unreachable!("This method exists only for documentation.")
}

/// Writes content to a file. Defaults to append mode.
/// Use `[write::replace]` flag to overwrite instead.
///
/// # Example
///
/// ```rhai
/// // Append (default)
/// write("/tmp/report.txt", "Another line\n");
///
/// // Overwrite
/// write([write::replace], "/tmp/report.txt", "Hello World\n");
///
/// // Explicit append
/// write([write::append], "/tmp/report.txt", "More content\n");
/// ```
pub(crate) fn write(path: &str, content: &str) -> Result<(), Box<EvalAltResult>> {
    unreachable!("This method exists only for documentation.")
}
