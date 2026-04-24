use crate::dir_entry::{EntryType, Metadata};
use crate::errors::RustSafeIoError;
use crate::options::{DirWalkOptions, OpenDirOptionsBuilder};
use crate::{DirEntry, RcDirHandle, RcFileHandle};
use std::collections::HashMap;
use std::collections::hash_map::Entry;

use rex_cedar_auth::cedar_auth::CedarAuth;

use rex_logger::warn;

/// A directory tree walker that provides depth-first traversal
#[derive(Debug)]
pub struct DirWalk<'a> {
    root: RcDirHandle,
    cedar_auth: &'a CedarAuth,
    min_depth: usize,
    max_depth: usize,
    follow_symlinks: bool,
    skip_visited_inodes: bool,
}

/// Represents an entry during directory traversal
///
/// * `DirPre` - Directory entry before its contents are processed
/// * `Entry` - A directory or file entry that can be processed for content operations
/// * `File` - A regular file entry
/// * `DirPost` - Directory entry after its contents are processed
#[derive(Debug, Clone)]
#[non_exhaustive]
#[allow(dead_code)]
pub enum WalkEntry {
    DirPre(RcDirHandle),
    Entry(DirEntry),
    File(RcFileHandle),
    DirPost(RcDirHandle),
}

/// Iterator that walks directory tree with cached entries
#[derive(Debug)]
pub struct DirWalkIter<'a> {
    stack: Vec<DirState>,
    cedar_auth: &'a CedarAuth,
    min_depth: usize,
    max_depth: usize,
    follow_symlinks: bool,
    skip_visited_inodes: bool,
    visited_inodes: HashMap<(u64, u64), usize>, // (device, inode): depth
}

/// State for each directory level in the traversal
#[derive(Debug)]
struct DirState {
    dir_handle: RcDirHandle,
    processing_state: ProcessingState,
    cached_entries: std::vec::IntoIter<DirEntry>,
    current_depth: usize,
}

/// State for tracking directory traversal phases
///
/// Represents the different phases of processing a directory:
/// * `Pre` - Before processing directory contents
/// * `Contents` - While processing directory contents  
/// * `Post` - After processing directory contents
#[derive(Debug, Clone, Copy)]
enum ProcessingState {
    Pre,
    Contents,
    Post,
}

impl<'a> DirWalk<'a> {
    /// Creates a new directory walker for the given root directory
    ///
    /// # Authorization
    ///
    /// Each directory and file access is checked against Cedar policies. If authorization
    /// fails for any entry, that entry is skipped and logged, but traversal continues.
    ///
    /// # Traversal Order
    ///
    /// The iterator follows depth-first traversal with three types of entries:
    /// - `WalkEntry::DirPre` - Emitted when first entering a directory
    /// - `WalkEntry::Entry` - Emitted for each directory or file entry that can be processed
    /// - `WalkEntry::File` - Emitted for each file in the directory
    /// - `WalkEntry::DirPost` - Emitted after all contents of a directory have been processed
    ///
    /// # Errors
    /// Logged as warnings but doesn't stop iteration of sibling directories.
    /// The walker continues with a "best effort" approach to traverse as much as possible.
    ///
    /// # Example
    /// See `RcDirHandle::chmod_recursive_impl` for an example usage.
    pub fn new(root: &RcDirHandle, cedar_auth: &'a CedarAuth, options: &DirWalkOptions) -> Self {
        Self {
            root: root.clone(),
            cedar_auth,
            min_depth: options.min_depth,
            max_depth: options.max_depth,
            follow_symlinks: options.follow_symlinks,
            skip_visited_inodes: options.skip_visited_inodes,
        }
    }
}

impl<'a> IntoIterator for DirWalk<'a> {
    type Item = Result<WalkEntry, RustSafeIoError>;
    type IntoIter = DirWalkIter<'a>;

    fn into_iter(self) -> DirWalkIter<'a> {
        let root_entries = match self.root.safe_list_dir(self.cedar_auth) {
            Ok(entries) => entries,
            Err(e) => {
                warn!(
                    "Failed to list contents of root directory '{}': {}",
                    self.root.dir_handle.dir_config.path, e
                );
                Vec::new()
            }
        };

        let mut initial_visited_inodes = HashMap::new();
        if self.follow_symlinks
            && let Ok(metadata) = self.root.metadata(self.cedar_auth)
        {
            let dev = metadata.device();
            let ino = metadata.ino();
            initial_visited_inodes.insert((dev, ino), 0);
        }

        DirWalkIter {
            stack: vec![DirState {
                dir_handle: self.root,
                processing_state: ProcessingState::Pre,
                cached_entries: root_entries.into_iter(),
                current_depth: 1,
            }],
            cedar_auth: self.cedar_auth,
            min_depth: self.min_depth,
            max_depth: self.max_depth,
            follow_symlinks: self.follow_symlinks,
            skip_visited_inodes: self.skip_visited_inodes,
            visited_inodes: initial_visited_inodes,
        }
    }
}

impl Iterator for DirWalkIter<'_> {
    type Item = Result<WalkEntry, RustSafeIoError>;

    /// RAII FD Management: Uses `RcDirHandle` for reference-counted directory handles and
    /// stack-based traversal where the Min/max depth of the traversal can be specified.
    /// FDs are automatically closed when directories are popped from stack. `safe_list_dir`
    /// collects entries immediately to ensure immediate FD closure. DO NOT refactor to avoid stack
    /// operations or use lazy iterators - this will cause FD leaks. `DirPre` and `DirPost` variants
    /// are used purely for traversal control and should not be used for content operations - all
    /// content processing should be performed on `Entry` variants. Note that the root directory
    /// itself is never emitted as an `Entry` and must be processed separately by the caller.
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let current_state = self.stack.last_mut()?;

            match current_state.processing_state {
                ProcessingState::Pre => {
                    current_state.processing_state = ProcessingState::Contents;
                    return Some(Ok(WalkEntry::DirPre(current_state.dir_handle.clone())));
                }

                ProcessingState::Contents => {
                    if let Some(mut entry) = current_state.cached_entries.next() {
                        let current_depth = current_state.current_depth;

                        // Handle symlinks if follow_symlinks is enabled
                        if self.follow_symlinks && entry.is_symlink() {
                            if current_depth < self.min_depth {
                                continue;
                            }

                            match self
                                .is_entry_visited_through_shortest_path(&mut entry, current_depth)
                            {
                                // Only process the symlink if target has not been visited or was previously visited through a longer path
                                Ok((false, Some(target_metadata))) => {
                                    match self.process_symlink_entry(
                                        entry,
                                        current_depth,
                                        &target_metadata,
                                    ) {
                                        Ok(Some(processed_entry)) => {
                                            return Some(Ok(WalkEntry::Entry(processed_entry)));
                                        }

                                        Err(e) => {
                                            warn!("{e}");
                                            continue;
                                        }

                                        _ => continue,
                                    }
                                }
                                Err(e) => {
                                    warn!("{e}");
                                    continue;
                                }
                                _ => continue,
                            }
                        }

                        if self.skip_visited_inodes {
                            match self
                                .is_entry_visited_through_shortest_path(&mut entry, current_depth)
                            {
                                Ok((true, _)) => continue,
                                Ok((false, _)) => {}
                                Err(e) => {
                                    warn!("Failed to get metadata for '{}': {}", entry.name(), e);
                                    continue;
                                }
                            }
                        }

                        if entry.is_dir() {
                            match self.process_directory_for_traversal(&mut entry, current_depth) {
                                Ok(true) => {}

                                Err(e) => {
                                    warn!("{e}");
                                    continue;
                                }

                                _ => continue,
                            }
                        }

                        if current_depth >= self.min_depth {
                            return Some(Ok(WalkEntry::Entry(entry)));
                        }
                        continue;
                    }
                    current_state.processing_state = ProcessingState::Post;
                }

                ProcessingState::Post => {
                    // Post state always follows Pre state which pushes to stack
                    #[allow(clippy::unwrap_used)]
                    let dir_state = self.stack.pop().unwrap();
                    return Some(Ok(WalkEntry::DirPost(dir_state.dir_handle)));
                }
            }
        }
    }
}

impl DirWalkIter<'_> {
    /// Check if entry's inode was visited
    /// Returns (visited, `target_metadata`) for symlinks only and (visited, None) for regular entries
    fn is_entry_visited_through_shortest_path(
        &mut self,
        entry: &mut DirEntry,
        current_depth: usize,
    ) -> Result<(bool, Option<Metadata>), RustSafeIoError> {
        let metadata_unchecked = if entry.is_symlink() {
            // Open target, cache the file descriptor, get target metadata
            entry.symlink_target_metadata(self.cedar_auth)
        } else {
            entry.metadata(self.cedar_auth)
        };

        let metadata = match metadata_unchecked {
            Ok(metadata) => metadata,
            Err(e) => {
                return Err(e);
            }
        };

        let inode_pair = (metadata.device(), metadata.ino());

        let visited = match metadata.entry_type() {
            EntryType::Dir => match self.visited_inodes.get(&inode_pair) {
                Some(&previous_depth) if current_depth >= previous_depth => true,
                _ => {
                    self.visited_inodes.insert(inode_pair, current_depth);
                    false
                }
            },
            _ => match self.visited_inodes.entry(inode_pair) {
                Entry::Vacant(e) => {
                    e.insert(current_depth);
                    false
                }
                Entry::Occupied(_) => true,
            },
        };

        if entry.is_symlink() {
            Ok((visited, Some(metadata)))
        } else {
            Ok((visited, None))
        }
    }

    /// Processes a symlink entry when `follow_symlinks` is enabled.
    fn process_symlink_entry(
        &mut self,
        mut entry: DirEntry,
        current_depth: usize,
        target_metadata: &Metadata,
    ) -> Result<Option<DirEntry>, RustSafeIoError> {
        let target_file_type = target_metadata.file_type();

        entry = entry.convert_to_resolved_symlink_entry(target_file_type);

        // If target is a directory, add it to traversal stack
        if target_file_type.is_dir() {
            self.process_directory_for_traversal(&mut entry, current_depth)?;
        }
        Ok(Some(entry))
    }

    /// Opens a directory and adds it to traversal stack if within depth limits.
    fn process_directory_for_traversal(
        &mut self,
        entry: &mut DirEntry,
        current_depth: usize,
    ) -> Result<bool, RustSafeIoError> {
        let open_dir_options = if self.follow_symlinks {
            OpenDirOptionsBuilder::default()
                .follow_symlinks(true)
                .build()
        } else {
            OpenDirOptionsBuilder::default().build()
        };

        match entry.open_as_dir(self.cedar_auth, open_dir_options?) {
            Ok(subdir_handle) => {
                if current_depth < self.max_depth {
                    let subdir_entries = match subdir_handle.safe_list_dir(self.cedar_auth) {
                        Ok(entries) => entries,
                        Err(e) => {
                            warn!(
                                "Failed to list contents of directory '{}': {}",
                                subdir_handle.dir_handle.dir_config.path, e
                            );
                            if current_depth >= self.min_depth {
                                return Ok(true); // Return entry on list error
                            }
                            return Ok(false);
                        }
                    };

                    let subdir_state = DirState {
                        dir_handle: subdir_handle,
                        processing_state: ProcessingState::Pre,
                        cached_entries: subdir_entries.into_iter(),
                        current_depth: current_depth + 1,
                    };
                    self.stack.push(subdir_state);
                }
                Ok(true)
            }
            Err(e) => {
                warn!("Failed to open subdirectory '{}': {}", entry.name(), e);
                Ok(false) // Continue processing even if open failed
            }
        }
    }
}
