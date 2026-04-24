use cap_std::fs::File;
use std::rc::Rc;

use crate::DirHandle;

/// Represents a symlink handle containing a file descriptor to the symlink itself (not its target).
#[derive(Debug)]
pub struct SymlinkHandle {
    pub(crate) fd: File,
    pub(crate) symlink_name: String,
    pub(crate) dir_handle: Rc<DirHandle>,
}

/// A wrapper around [`Rc<SymlinkHandle>`].
///
/// By wrapping [`Rc<SymlinkHandle>`], we can define methods that
/// operate on the reference-counted [`SymlinkHandle`] directly.
#[derive(Clone, Debug)]
pub struct RcSymlinkHandle {
    pub(crate) symlink_handle: Rc<SymlinkHandle>,
}

impl PartialEq for RcSymlinkHandle {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.symlink_handle, &other.symlink_handle)
    }
}
