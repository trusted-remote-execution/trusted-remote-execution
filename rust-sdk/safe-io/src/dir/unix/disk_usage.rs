use derive_getters::Getters;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_logger::{RUNNER_TARGET, warn};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use crate::constants::BLOCK_SIZE_BYTES;
use crate::dir_entry::Metadata;
use crate::errors::RustSafeIoError;
use crate::options::{DirWalkOptions, DiskUsageOptions};
use crate::{DirWalk, RcDirHandle, WalkEntry};

/// Type alias for directory size tracking (bytes, `inode_count`)
type DirectorySizes = HashMap<String, (u64, u64)>;

/// Type alias for tracking seen (device, inode) pairs
type SeenInodes = HashSet<(u64, u64)>;

/// Represents a single disk usage entry (file or directory)
#[derive(Clone, Debug, Getters, Serialize)]
pub struct DiskUsageEntry {
    /// Full path to the file or directory
    path: String,

    /// Size in bytes (raw value for user to format as needed)
    size_bytes: u64,

    /// Number of inodes (file/directory count)
    inode_count: u64,
}

/// Result of disk usage calculation, optionally including the largest directory handle
#[derive(Clone, Debug, Getters)]
pub struct DiskUsageResult {
    /// List of disk usage entries
    entries: Vec<DiskUsageEntry>,

    /// Optional handle to the largest directory (by size) for TOCTOU operations
    largest_subdir_handle: Option<RcDirHandle>,
}

impl DiskUsageEntry {
    pub(crate) fn new(path: String, size_bytes: u64, inode_count: u64) -> Self {
        Self {
            path,
            size_bytes,
            inode_count,
        }
    }
}

impl RcDirHandle {
    /// Calculates disk usage for a directory and its contents
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rust_safe_io::DirConfigBuilder;
    /// # use rust_safe_io::options::{OpenDirOptionsBuilder, DiskUsageOptionsBuilder};
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
    ///     .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap()).unwrap();
    ///
    /// let options = DiskUsageOptionsBuilder::default().build().unwrap();
    /// let results = dir_handle.safe_disk_usage(&cedar_auth, options).unwrap();
    /// ```
    #[allow(clippy::too_many_lines)]
    pub fn safe_disk_usage(
        &self,
        cedar_auth: &CedarAuth,
        options: DiskUsageOptions,
    ) -> Result<DiskUsageResult, RustSafeIoError> {
        let root_metadata = self.metadata(cedar_auth)?;
        let root_path = &self.dir_handle.dir_config.path;

        let mut seen_inodes = SeenInodes::new();
        let mut results = Vec::new();
        let mut directory_sizes = DirectorySizes::new();
        let mut largest_subdir_handle: Option<RcDirHandle> = None;
        let mut largest_dir_size: u64 = 0;

        let root_device_id = options.one_file_system.then(|| root_metadata.device());

        // DirWalk yields DirPre (entering dir), Entry (file/dir), DirPost (exiting dir)
        // We maintain a path_stack to track current directory context as we traverse
        // DirPre pushes paths, DirPost pops them for proper parent child accumulation
        let mut path_stack = Vec::<String>::new();
        let root_depth = root_path.matches('/').count();

        for entry in DirWalk::new(self, cedar_auth, &DirWalkOptions::default()) {
            match entry? {
                WalkEntry::DirPre(dir_handle) => {
                    let dir_path = dir_handle.dir_handle.dir_config.path.clone();
                    path_stack.push(dir_path.clone());
                    directory_sizes.insert(dir_path, (0, 0));
                }

                WalkEntry::Entry(mut dir_entry) => {
                    let metadata = match dir_entry.metadata(cedar_auth) {
                        Ok(metadata) => metadata,
                        Err(e) => {
                            warn!(
                                RUNNER_TARGET,
                                "du: cannot access '{}': {}",
                                dir_entry.name(),
                                e
                            );
                            continue;
                        }
                    };

                    let entry_inode = *dir_entry.inode();
                    let entry_device = metadata.device();

                    if !should_count_entry(entry_device, entry_inode, &mut seen_inodes, &options) {
                        continue;
                    }

                    if options.one_file_system
                        && !should_traverse_directory(&metadata, root_device_id)
                    {
                        continue;
                    }

                    let size = calculate_entry_size(&metadata, &options)?;

                    if dir_entry.is_file()
                        && let Some(current_dir_path) = path_stack.last()
                    {
                        add_to_parent_size(&mut directory_sizes, current_dir_path, size, 1);
                    }

                    if options.all_files && !dir_entry.is_dir() {
                        let current_dir_path = path_stack.last().unwrap_or(root_path);
                        let entry_path = build_file_path(current_dir_path, dir_entry.name());

                        if should_include_in_results(&entry_path, root_path, root_depth, &options) {
                            results.push(DiskUsageEntry::new(entry_path, size, 1));
                        }
                    }
                }

                WalkEntry::DirPost(dir_handle) => {
                    let dir_path = &dir_handle.dir_handle.dir_config.path;

                    path_stack.pop();

                    let dir_metadata = match dir_handle.metadata(cedar_auth) {
                        Ok(metadata) => metadata,
                        Err(e) => {
                            warn!(RUNNER_TARGET, "du: cannot access '{}': {}", dir_path, e);
                            continue;
                        }
                    };
                    let dir_metadata_size = calculate_entry_size(&dir_metadata, &options)?;

                    add_to_parent_size(&mut directory_sizes, dir_path, dir_metadata_size, 1);

                    let (total_size, total_inodes) =
                        *directory_sizes.get(dir_path).unwrap_or(&(0, 0));

                    if should_include_in_results(dir_path, root_path, root_depth, &options) {
                        results.push(DiskUsageEntry::new(
                            dir_path.clone(),
                            total_size,
                            total_inodes,
                        ));

                        if options.track_largest_subdir
                            && dir_path != root_path
                            && total_size > largest_dir_size
                        {
                            largest_dir_size = total_size;
                            largest_subdir_handle = Some(dir_handle.clone());
                        }
                    }

                    if let Some(parent_path) = path_stack.last() {
                        add_to_parent_size(
                            &mut directory_sizes,
                            parent_path,
                            total_size,
                            total_inodes,
                        );
                    }
                }

                WalkEntry::File(_) => {}
            }
        }

        Ok(DiskUsageResult {
            entries: results,
            largest_subdir_handle: if options.track_largest_subdir {
                largest_subdir_handle
            } else {
                None
            },
        })
    }
}

fn calculate_entry_size(
    metadata: &Metadata,
    options: &DiskUsageOptions,
) -> Result<u64, RustSafeIoError> {
    if options.apparent_size {
        let size = metadata.file_size()?;
        Ok(u64::try_from(size)?)
    } else {
        let blocks = metadata.blocks()?;
        Ok(u64::try_from(blocks * BLOCK_SIZE_BYTES)?)
    }
}

#[inline]
fn build_file_path(parent_path: &str, filename: &str) -> String {
    let mut path = PathBuf::from(parent_path);
    path.push(filename);
    path.to_string_lossy().into_owned()
}

/// Calculate depth of a path relative to root
#[inline]
fn calculate_depth(path: &str, root_depth: usize) -> usize {
    path.matches('/').count() - root_depth
}

/// Check if entry should be counted based on hard link tracking
/// Uses (dev, ino) pairs to correctly handle files across filesystems
fn should_count_entry(
    entry_device: u64,
    entry_inode: u64,
    seen_inodes: &mut SeenInodes,
    options: &DiskUsageOptions,
) -> bool {
    if options.count_hard_links {
        return true;
    }

    let dev_ino_pair = (entry_device, entry_inode);
    seen_inodes.insert(dev_ino_pair)
}

/// Check if we should cross into this directory (filesystem boundary detection)
fn should_traverse_directory(dir_metadata: &Metadata, root_device_id: Option<u64>) -> bool {
    root_device_id.is_none_or(|root_dev| dir_metadata.device() == root_dev)
}

/// Add size and inode count to parent directory's accumulated totals
#[inline]
fn add_to_parent_size(
    directory_sizes: &mut DirectorySizes,
    parent_path: &str,
    size: u64,
    inode_count: u64,
) {
    let parent_entry = directory_sizes
        .entry(parent_path.to_string())
        .or_insert((0, 0));
    parent_entry.0 += size;
    parent_entry.1 += inode_count;
}

/// Check if path should be included in results based on options
#[inline]
fn should_include_in_results(
    path: &str,
    root_path: &str,
    root_depth: usize,
    options: &DiskUsageOptions,
) -> bool {
    let depth = calculate_depth(path, root_depth);
    let should_print = !options.summarize || path == root_path;
    let within_depth = i64::try_from(depth).unwrap_or(i64::MAX) <= options.max_depth;
    should_print && within_depth
}
