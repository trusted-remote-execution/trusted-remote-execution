use crate::random::get_rand_string;
use anyhow::Result;
use assert_fs::{TempDir, fixture::ChildPath, prelude::FileWriteStr};
use flate2::{Compression, write::GzEncoder};
use std::fs::{self, File, read};
use std::io::Write;
use std::path::{Path, PathBuf};
use tar::{Builder, Header};

/// Sets the TMPDIR environment variable to the canonicalized system temp directory on macOS.
///
/// This is used to avoid symlink issues with the default temp directory on macOS.
/// The default temporary directory is in `/var/folders/...` which is actually a symlink
/// to `/private/var/folders/...`. This can cause path traversal checks to fail in [`RustSafeIO`]
/// because the canonical path is different from the original path.
///
/// Instead of redirecting to the current working directory (which pollutes the source tree
/// with `.tmp*` directories), we resolve the canonical path of the system temp dir so that
/// temp files stay in the proper OS temp location.
#[cfg(target_os = "macos")]
fn set_tmpdir_to_canonical() -> Result<()> {
    use std::env;
    let tmp = env::temp_dir();
    let canonical_tmp = tmp.canonicalize()?;

    #[allow(unsafe_code)]
    unsafe {
        env::set_var("TMPDIR", &canonical_tmp);
    }

    Ok(())
}

/// Creates a temporary directory with `assert_fs`.
///
/// # Returns
/// - `(TempDir, String)`: A tuple where:
///   - First element is the [`TempDir`] object corresponding to temporary directory created
///   - Second element is the full String path to the temporary directory
///
/// # Example
/// ```
/// use anyhow::Result;
/// use rex_test_utils::io::create_temp_dir_and_path;
/// use std::path::Path;
///
/// fn main() -> Result<()> {
/// let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
/// assert!(Path::new(&temp_dir_path).exists());
///
/// temp_dir.close()?;
/// Ok(())
/// }
/// ```
pub fn create_temp_dir_and_path() -> Result<(TempDir, String)> {
    #[cfg(target_os = "macos")]
    set_tmpdir_to_canonical()?;

    let temp_dir = TempDir::new()?;
    let temp_dir_path = temp_dir.path().to_string_lossy().to_string();

    Ok((temp_dir, temp_dir_path))
}

/// Creates a new random file path within the specified temporary directory.
///
/// # Arguments
/// * `temp_dir` - Reference to a temporary directory created by [`TempDir`]
///
/// # Returns
/// - `(PathBuf, String)`: A tuple where:
///   - First element is the complete `PathBuf` to the new file location
///   - Second element is the generated name of the file created
///
/// # Example
/// ```
/// use assert_fs::TempDir;
/// use std::path::PathBuf;
/// use rex_test_utils::io::create_new_file_path;
///
/// let temp_dir = TempDir::new().unwrap();
/// let (file_path, file_name) = create_new_file_path(&temp_dir);
///
/// assert_eq!(file_path.file_name().unwrap().to_string_lossy(), file_name);
/// ```
pub fn create_new_file_path<P: AsRef<Path>>(path: &P) -> (PathBuf, String) {
    let temp_file_name = get_rand_string();

    (path.as_ref().join(&temp_file_name), temp_file_name)
}

/// Creates a temporary file with random content in the specified temporary directory.
///
/// # Arguments
/// * `temp` - Reference to a temporary directory created by [`TempDir`]
///
/// # Returns
/// * `String` - The full path to the temporary directory containing the created file
///
/// # Example
/// ```
/// use anyhow::Result;
/// use assert_fs::TempDir;
/// use rex_test_utils::io::create_and_write_to_test_file;
/// use std::path::Path;
///
/// fn main() -> Result<()> {
/// let temp_dir = TempDir::new()?;
/// let test_file = "test_file.txt";
/// let dir_path = create_and_write_to_test_file(&temp_dir, &test_file)?;
/// assert!(Path::new(&dir_path).exists());
///
/// temp_dir.close()?;
/// Ok(())
/// }
/// ```
pub fn create_and_write_to_test_file<P: AsRef<Path>>(path: &P, test_file: &str) -> Result<String> {
    let (path, _) = writer_helper(path, test_file, None)?;
    Ok(path)
}

/// Creates a temporary file with random content in the specified temporary directory and returns the path and content written.
///
/// # Arguments
/// * `temp` - Reference to a temporary directory created by [`TempDir`]
///
/// # Returns
/// * `String` - The full path to the temporary directory containing the created file
/// * `String` - The contents that were written
///
/// # Example
/// ```
/// use anyhow::Result;
/// use assert_fs::TempDir;
/// use rex_test_utils::io::create_write_return_test_file;
/// use std::path::Path;
///
/// fn main() -> Result<()> {
///     let temp_dir = TempDir::new()?;
///     let test_file = "test_file.txt";
///     let (dir_path, file_contents) = create_write_return_test_file(&temp_dir, &test_file)?;
///     assert!(Path::new(&dir_path).exists());
///
///     temp_dir.close()?;
///     Ok(())
/// }
/// ```
pub fn create_write_return_test_file<P: AsRef<Path>>(
    path: &P,
    test_file: &str,
) -> Result<(String, String)> {
    writer_helper(path, test_file, None)
}

/// Creates a temporary file with specific content in temporary directory and returns the path
///
/// # Arguments
/// * `temp` - Reference to a temporary directory created by [`TempDir`]
/// * `test_file` - The name of file to be created
/// * `content` - The content to be written to the file
///
/// # Returns
/// * `String` - The full path to the temporary directory containing the created file
///
/// # Example
/// ```
/// use anyhow::Result;
/// use assert_fs::TempDir;
/// use rex_test_utils::io::create_file_with_content;
/// use std::path::Path;
/// use std::fs;
///
/// fn main() -> Result<()> {
///     let temp_dir = TempDir::new()?;
///     let test_file = "test_file.txt";
///     let content = "Hello, this is specific content!";
///
///     let dir_path = create_file_with_content(&temp_dir, test_file, content)?;
///
///     let file_path = Path::new(&dir_path).join(test_file);
///     assert!(file_path.exists(), "File should exist");
///     let content = fs::read_to_string(&file_path)?;
///     assert!(content.eq(r#"Hello, this is specific content!"#));
///
///     temp_dir.close()?;
///     Ok(())
/// }
/// ```
pub fn create_file_with_content<P: AsRef<Path>>(
    path: &P,
    test_file: &str,
    content: &str,
) -> Result<String> {
    let (temp_dir, _) = writer_helper(path, test_file, Some(content))?;
    Ok(temp_dir)
}

/// Helper function for writing content to a file in a temporary directory.
///
/// This function handles the common logic for creating and writing to temporary files,
/// supporting both random and specified content.
///
/// # Arguments
/// * `temp` - Reference to a temporary directory created by [`TempDir`]
/// * `test_file` - The name of the file
/// * `content` - Optional content to write to the file. If None, random content will be generated
///
/// # Returns
/// - `Result<(String, String)>`: A tuple where:
///   - First element is the full path to the temporary directory containing the file
///   - Second element is the content that was written to the file
fn writer_helper<P: AsRef<Path>>(
    path: &P,
    test_file: &str,
    content: Option<&str>,
) -> Result<(String, String)> {
    let temp_dir_path: String = path.as_ref().to_string_lossy().to_string();

    let random_content = get_rand_string();
    let content_to_write = content.unwrap_or(&random_content);

    let cp = ChildPath::new(path.as_ref().join(test_file));
    cp.write_str(content_to_write)?;

    Ok((temp_dir_path, content_to_write.to_string()))
}

/// Creates a temporary file with some content.
///
/// # Arguments
/// * `dir` - Reference to the path of the directory where the file will be created
/// * `name` - Reference to the name of the file to be created
/// * `content` - The content to be written to the file
///
///
/// # Example
/// ```
/// use anyhow::Result;
/// use assert_fs::TempDir;
/// use rex_test_utils::io::create_test_file;
/// use std::path::Path;
///
/// fn main() -> Result<()> {
///     let temp_dir = TempDir::new()?;
///     let test_file = "test_file.txt";
///     let test_content = "Hello, world!";
///     create_test_file(&temp_dir, &test_file, test_content.as_bytes())?;
///     Ok(())
/// }
/// ```
pub fn create_test_file<P: AsRef<Path>>(path: &P, name: &str, content: &[u8]) -> Result<()> {
    let file_path = path.as_ref().join(name);
    let mut file = File::create(file_path)?;
    file.write_all(content)?;
    Ok(())
}

/// Reads a file with some content.
///
/// # Arguments
/// * `file_name` - Reference to the name of the file to be read
///
///
/// # Example
/// ```
/// use anyhow::Result;
/// use assert_fs::TempDir;
/// use rex_test_utils::io::{create_test_file, read_test_file};
/// use std::path::Path;
///
/// fn main() -> Result<()> {
///     let temp_dir = TempDir::new()?;
///     let test_file = "test_file.txt";
///     let test_content = "Hello, world!";
///     create_test_file(&temp_dir, &test_file, test_content.as_bytes())?;
///     let content = read_test_file(&temp_dir.join(&test_file));
///     Ok(())
/// }
/// ```
pub fn read_test_file<P: AsRef<Path>>(path: &P) -> Result<String> {
    let content = read(path.as_ref())?;
    let content = String::from_utf8(content)?;

    Ok(content)
}

/// Creates a temporary directory with `assert_fs` and returns just the [`TempDir`].
///
/// This is a convenience wrapper around `create_temp_dir_and_path` for when
/// only the [`TempDir`] is needed.
///
/// # Returns
/// - [`TempDir`]: The temporary directory object
///
/// # Example
/// ```
/// use anyhow::Result;
/// use rex_test_utils::io::create_temp_dir;
/// use std::path::Path;
///
/// fn main() -> Result<()> {
///     let temp_dir = create_temp_dir()?;
///     assert!(temp_dir.path().exists());
///
///     temp_dir.close()?;
///     Ok(())
/// }
/// ```
pub fn create_temp_dir() -> Result<TempDir> {
    let (temp_dir, _) = create_temp_dir_and_path()?;
    Ok(temp_dir)
}

/// Builder for creating tar archive entries with flexible configuration options.
///
/// This struct provides a fluent API for constructing tar archive entries with various
/// attributes like permissions, ownership, timestamps, and entry types. It supports
/// both files and directories, as well as special file types like symlinks.
///
/// # Example
/// ```
/// use rex_test_utils::io::ArchiveEntry;
/// use assert_fs::TempDir;
/// use anyhow::Result;
///
/// fn main() -> Result<()> {
///     let temp_dir = TempDir::new()?;
///     
///     // Create a simple file entry
///     let file_entry = ArchiveEntry::file("test.txt", "content");
///     
///     // Create a directory with custom permissions
///     let dir_entry = ArchiveEntry::directory("test_dir/").with_mode(0o755);
///     
///     // Create a file with ownership and timestamps
///     let complex_entry = ArchiveEntry::file("complex.txt", "data")
///         .with_mode(0o644)
///         .with_ownership(1000, 1000)
///         .with_usernames("user", "group")
///         .with_mtime(1609459200);
///     
///     Ok(())
/// }
/// ```
#[derive(Debug)]
pub struct ArchiveEntry {
    path: String,
    content: String,
    entry_type: tar::EntryType,
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
    username: Option<String>,
    groupname: Option<String>,
    mtime: Option<u64>,
}

impl ArchiveEntry {
    /// Creates a new regular file entry.
    ///
    /// # Arguments
    /// * `path` - The path of the file within the archive
    /// * `content` - The content to be written to the file
    ///
    /// # Example
    /// ```
    /// use rex_test_utils::io::ArchiveEntry;
    ///
    /// let entry = ArchiveEntry::file("example.txt", "Hello, world!");
    /// ```
    #[must_use]
    pub fn file(path: &str, content: &str) -> Self {
        Self {
            path: path.to_string(),
            content: content.to_string(),
            entry_type: tar::EntryType::Regular,
            mode: None,
            uid: None,
            gid: None,
            username: None,
            groupname: None,
            mtime: None,
        }
    }

    /// Creates a new directory entry.
    ///
    /// # Arguments
    /// * `path` - The path of the directory within the archive (should end with '/')
    ///
    /// # Example
    /// ```
    /// use rex_test_utils::io::ArchiveEntry;
    ///
    /// let entry = ArchiveEntry::directory("my_dir/");
    /// ```
    #[must_use]
    pub fn directory(path: &str) -> Self {
        Self {
            path: path.to_string(),
            content: String::new(),
            entry_type: tar::EntryType::Directory,
            mode: None,
            uid: None,
            gid: None,
            username: None,
            groupname: None,
            mtime: None,
        }
    }

    /// Sets the file mode (permissions) for this entry.
    ///
    /// # Arguments
    /// * `mode` - The file mode in octal format (e.g., 0o755 for rwxr-xr-x)
    ///
    /// # Example
    /// ```
    /// use rex_test_utils::io::ArchiveEntry;
    ///
    /// let entry = ArchiveEntry::file("script.sh", "#!/bin/bash\necho hello")
    ///     .with_mode(0o755);
    /// ```
    #[must_use]
    pub const fn with_mode(mut self, mode: u32) -> Self {
        self.mode = Some(mode);
        self
    }

    /// Sets the numeric user ID and group ID for this entry.
    ///
    /// # Arguments
    /// * `uid` - The numeric user ID
    /// * `gid` - The numeric group ID
    ///
    /// # Example
    /// ```
    /// use rex_test_utils::io::ArchiveEntry;
    ///
    /// let entry = ArchiveEntry::file("owned_file.txt", "content")
    ///     .with_ownership(1000, 1000);
    /// ```
    #[must_use]
    pub const fn with_ownership(mut self, uid: u32, gid: u32) -> Self {
        self.uid = Some(uid);
        self.gid = Some(gid);
        self
    }

    /// Sets the username and groupname strings for this entry.
    ///
    /// # Arguments
    /// * `username` - The username string
    /// * `groupname` - The groupname string
    ///
    /// # Example
    /// ```
    /// use rex_test_utils::io::ArchiveEntry;
    ///
    /// let entry = ArchiveEntry::file("user_file.txt", "content")
    ///     .with_usernames("alice", "users");
    /// ```
    #[must_use]
    pub fn with_usernames(mut self, username: &str, groupname: &str) -> Self {
        self.username = Some(username.to_string());
        self.groupname = Some(groupname.to_string());
        self
    }

    /// Sets the modification time for this entry.
    ///
    /// # Arguments
    /// * `mtime` - The modification time as seconds since Unix epoch
    ///
    /// # Example
    /// ```
    /// use rex_test_utils::io::ArchiveEntry;
    ///
    /// let entry = ArchiveEntry::file("timestamped.txt", "content")
    ///     .with_mtime(1609459200); // 2021-01-01 00:00:00 UTC
    /// ```
    #[must_use]
    pub const fn with_mtime(mut self, mtime: u64) -> Self {
        self.mtime = Some(mtime);
        self
    }

    /// Creates a special file entry (symlink, device, etc.).
    ///
    /// # Arguments
    /// * `path` - The path of the special file within the archive
    /// * `entry_type` - The type of special file (e.g., `tar::EntryType::Symlink`)
    ///
    /// # Example
    /// ```
    /// use rex_test_utils::io::ArchiveEntry;
    /// use tar::EntryType;
    ///
    /// let entry = ArchiveEntry::special_file("my_symlink", EntryType::Symlink);
    /// ```
    #[must_use]
    pub fn special_file(path: &str, entry_type: tar::EntryType) -> Self {
        Self {
            path: path.to_string(),
            content: String::new(),
            entry_type,
            mode: None,
            uid: None,
            gid: None,
            username: None,
            groupname: None,
            mtime: None,
        }
    }
}

/// Creates a test tar.gz archive with flexible entry configuration.
///
/// This function provides a unified interface for creating tar.gz archives with
/// various types of entries (files, directories, special files) and their associated
/// metadata (permissions, ownership, timestamps).
///
/// # Arguments
/// * `temp_dir` - Reference to a temporary directory created by [`TempDir`]
/// * `archive_name` - The name of the archive file to create (e.g., "test.tar.gz")
/// * `entries` - Vector of [`ArchiveEntry`] objects defining the archive contents
///
/// # Example
/// ```
/// use anyhow::Result;
/// use assert_fs::TempDir;
/// use rex_test_utils::io::{create_test_archive, ArchiveEntry};
/// use tar::EntryType;
///
/// fn main() -> Result<()> {
///     let temp_dir = TempDir::new()?;
///     
///     create_test_archive(&temp_dir, "test.tar.gz", vec![
///         ArchiveEntry::file("readme.txt", "Hello, world!"),
///         ArchiveEntry::directory("docs/"),
///         ArchiveEntry::file("docs/guide.txt", "Documentation content"),
///         ArchiveEntry::file("script.sh", "#!/bin/bash\necho test").with_mode(0o755),
///         ArchiveEntry::special_file("link", EntryType::Symlink),
///     ])?;
///     
///     temp_dir.close()?;
///     Ok(())
/// }
/// ```
pub fn create_test_archive(
    temp_dir: &TempDir,
    archive_name: &str,
    entries: Vec<ArchiveEntry>,
) -> Result<()> {
    let archive_path = temp_dir.path().join(archive_name);
    let tar_gz = File::create(&archive_path)?;
    let enc = GzEncoder::new(tar_gz, Compression::default());
    let mut tar = Builder::new(enc);

    for entry in entries {
        let mut header = Header::new_gnu();
        header.set_path(&entry.path)?;
        header.set_size(entry.content.len() as u64);
        header.set_mode(
            entry
                .mode
                .unwrap_or(if entry.entry_type == tar::EntryType::Directory {
                    0o755
                } else {
                    0o644
                }),
        );
        header.set_entry_type(entry.entry_type);

        if let Some(uid) = entry.uid {
            header.set_uid(u64::from(uid));
        }
        if let Some(gid) = entry.gid {
            header.set_gid(u64::from(gid));
        }
        if let Some(username) = &entry.username {
            header.set_username(username)?;
        }
        if let Some(groupname) = &entry.groupname {
            header.set_groupname(groupname)?;
        }
        if let Some(mtime) = entry.mtime {
            header.set_mtime(mtime);
        }

        header.set_cksum();
        tar.append(&header, entry.content.as_bytes())?;
    }

    tar.finish()?;
    Ok(())
}

/// Detects if the current environment is running inside a container.
///
/// Useful for not running a test in the build fleet.
#[cfg(unix)]
pub fn is_container() -> bool {
    Path::new("/.dockerenv").exists()
        || Path::new("/run/.containerenv").exists()
        || fs::read_to_string("/proc/1/cgroup")
            .map(|s| s.contains("docker") || s.contains("lxc"))
            .unwrap_or(false)
}
