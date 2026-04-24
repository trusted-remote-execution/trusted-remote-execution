pub mod error_constants {
    pub const DIR_DNE_ERR: &str = "a path led to nonexistent location";
    pub const FILE_DNE_ERR: &str = "No such file or directory";
    pub const DIR_NED_ERR: &str = "A path led to a non-empty directory location. To include contents of this directory, use the recursive flag";
    pub const FILE_NON_UTF_8: &str = "stream did not contain valid UTF-8";
    pub const PATH_TRAVERSAL: &str = "Path traversal detected";
    pub const PATH_LED_OUTSIDE_FILESYSTEM: &str = "a path led outside of the filesystem";
    pub const FILE_PATH_INVALID: &str = "file path must contain only a filename";
    pub const NOT_A_FILE: &str = "argument is not a file";
    pub const NOT_A_SYMLINK: &str = "argument is not a symlink";
    pub const TOO_MANY_SYMLINKS: &str = "Too many levels of symbolic links";
    pub const FAILED_OPEN_DIR: &str = "failed to open directory";
    pub const FAILED_OPEN_FILE: &str = "Failed to open file";
    pub const FAILED_OPEN_PARENT: &str = "failed to open parent";
    pub const FAILED_CREATE_DIR: &str = "failed to create directory";
    pub const PATH_TRAVERSAL_DETECTED: &str = "path traversal detected";
    pub const NOT_A_DIR: &str = "Not a directory";
    pub const CURRENT_DIR_NOT_ALLOWED: &str = "Current directory reference is not allowed";
    pub const INVALID_PATH: &str = "Invalid path";
    pub const PATH_NOT_ABSOLUTE: &str = "Path is not absolute";
    pub const NO_USER_MAPPING_ERR: &str = "No user mapping found for uid";
    pub const NO_GROUP_MAPPING_ERR: &str = "No group mapping found for gid";
    pub const INVALID_OPEN_FILE_OPTIONS: &str =
        "Invalid open file options: at least one of read, write or create flags must be true";
    pub const WRITE_FILE_FLAG_ERR: &str =
        "Attempted to write a file without opening it with the write option.";
    pub const SPECIAL_FILE_ATOMIC_WRITE_ERR: &str =
        "special_file option is only valid for safe_write_in_place, not atomic writes";
    pub const SPECIAL_FILE_REQUIRES_WRITE_ERR: &str = "special_file option requires write=true";
    pub const READ_FILE_FLAG_ERR: &str =
        "Attempted to read a file without opening it with the read option.";
    pub const READ_ONLY_FILE_FLAG_ERR: &str = "Attempted to execute a file opened with write permissions. Files must be opened read-only for execution.";
    pub const INVALID_PERMISSIONS_ERR: &str =
        "Invalid permissions. Permissions must be in the range 0-777 octal";
    pub const INVALID_START_LINE_ERR: &str =
        "Invalid line to start reading from: must be a positive integer greater than 1 (>= 1)";
    pub const INVALID_READ_LINES_PAGINATION_COUNT_ERR: &str =
        "Read page options require the num_lines option to be set and greater than zero";
    pub const NO_READ_LINE_MODE_SPECIFIED_ERR: &str = "No read line mode specified";
    pub const INVALID_REGEX_PATTERN_ERR: &str = "Invalid regex pattern";
    pub const INVALID_GLOB_PATTERN_ERR: &str = "Invalid glob pattern";
    pub const DEST_FILE_NOT_EMPTY_ERR: &str = "Destination file not empty";
    pub const DIR_ENTRY_NOT_A_FILE: &str = "DirEntry does not represent a file";
    pub const DIR_ENTRY_NOT_A_DIR: &str = "DirEntry does not represent a dir";
    pub const DIR_ENTRY_UNKNOWN_TYPE_FOR_OPEN: &str = "Attempted to open unknown file type";
    pub const INVALID_SIZE: &str = "Size must be greater than or equal to 0";
    pub const INVALID_LENGTH: &str = "Length must be greater than 0";
    pub const PARENT_PATH_INVALID: &str = "parent path invalid";
    pub const LEAF_PATH_INVALID: &str = "leaf path invalid";
    pub const FAILED_OPEN_LEAF: &str = "failed to open leaf";
    pub const PATH_COMPONENT_NOT_UTF8: &str = "path component not utf-8";
    pub const DISK_USAGE_SUMMARIZE_ALL_FILES_ERR: &str =
        "cannot both summarize and show all entries";
    pub const CHOWN_CAP_REQUIRED_ERR: &str = "Failed to change ownership. CAP_CHOWN capability is required when changing ownership to a different user.";
}
pub const CHUNK_SIZE: usize = 8 * 1024; // 8KB, same chunk size used in GNU coreutils implementation of tail
pub const BLOCK_SIZE_BYTES: i64 = 512;
pub const REDACTION_DICTIONARY: &str = "/etc/opt/rex/rex_redaction.config";

/// Timeout in seconds for child process graceful shutdown after SIGTERM
pub const SIGTERM_TIMEOUT_SECONDS: i64 = 5;
pub const EXECUTE_API_CHILD_MONITORING_INTERNVAL_MSEC: u64 = 100;
