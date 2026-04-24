use rex_cedar_auth::cedar_auth::CedarAuth;

use glob::{MatchOptions, Pattern};
use regex::Regex;

use crate::RcDirHandle;
use crate::error_constants::INVALID_GLOB_PATTERN_ERR;
use crate::errors::RustSafeIoError;
use crate::options::{DirWalkOptions, FindOptions};
use crate::recursive::{DirWalk, WalkEntry};
use rust_sdk_common_utils::types::datetime::DateTime;

impl RcDirHandle {
    /// Traverses a directory tree and executes a callback function on each entry with Cedar authorization.
    ///
    /// This function performs a recursive directory traversal, calling the provided callback function
    /// for each file and directory encountered. The traversal respects Cedar authorization policies
    /// for directory access and uses memoization to optimize performance when accessing the same
    /// directories multiple times.
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
    /// ```no_run
    /// // PCRE pattern with \K (not supported)
    /// // "execfn: '\K[^']+"
    ///
    /// // Equivalent Rust regex pattern
    /// // "execfn: '([^']+)"
    /// ```
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_safe_io::{DirConfigBuilder, WalkEntry};
    /// use rust_safe_io::options::{OpenDirOptionsBuilder, OpenFileOptionsBuilder, FindOptionsBuilder};
    /// use rust_safe_io::errors::RustSafeIoError;
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
    ///     .path("/tmp/search_dir".to_string())
    ///     .build().unwrap()
    ///     .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap())
    ///     .unwrap();
    ///
    /// let mut found_files = Vec::<(String, String)>::new();
    /// let callback = |entry: &WalkEntry| -> Result<(), RustSafeIoError> {
    ///     match entry {
    ///         WalkEntry::Entry(dir_entry) => {
    ///             if dir_entry.is_file() {
    ///                 let mut owned_entry = dir_entry.clone();
    ///                 let file_handle = owned_entry.open_as_file(
    ///                     &cedar_auth,
    ///                     OpenFileOptionsBuilder::default()
    ///                         .read(true)
    ///                         .build()
    ///                         .unwrap(),
    ///                 )?;
    ///
    ///                 let content = file_handle.safe_read(&cedar_auth)?;
    ///                 let file_name = dir_entry.name().to_string();
    ///                 found_files.push((file_name, content));
    ///             }
    ///             Ok(())
    ///         }
    ///         _ => Ok(()),
    ///     }
    /// };
    ///
    /// let find_options = FindOptionsBuilder::default().build().unwrap();
    /// dir_handle.safe_find(&cedar_auth, find_options, callback).unwrap();
    /// ```
    #[allow(clippy::cast_possible_wrap)]
    #[allow(clippy::needless_pass_by_value)]
    pub fn safe_find<F>(
        &self,
        cedar_auth: &CedarAuth,
        find_options: FindOptions,
        mut callback: F,
    ) -> Result<(), RustSafeIoError>
    where
        F: FnMut(&WalkEntry) -> Result<(), RustSafeIoError>,
    {
        let glob_pattern = find_options
            .name
            .as_ref()
            .or(find_options.iname.as_ref())
            .map(|pattern| Pattern::new(pattern))
            .transpose()
            .map_err(|e| RustSafeIoError::ValidationError {
                reason: format!("{INVALID_GLOB_PATTERN_ERR}: - {e}"),
            })?;

        let regex_pattern = if let Some(regex) = &find_options.regex {
            Some(Regex::new(regex).map_err(|e| RustSafeIoError::invalid_regex_err(regex, &e))?)
        } else {
            None
        };

        let dir_walk_options = &DirWalkOptions {
            min_depth: usize::try_from(find_options.min_depth)?,
            max_depth: usize::try_from(find_options.max_depth)?,
            follow_symlinks: find_options.follow_symlinks,
            skip_visited_inodes: find_options.follow_symlinks,
        };

        for entry in DirWalk::new(self, cedar_auth, dir_walk_options) {
            match entry? {
                WalkEntry::Entry(mut dir_entry) => {
                    let name_or_regex_match = does_pattern_match(
                        glob_pattern.as_ref(),
                        regex_pattern.as_ref(),
                        &find_options,
                        dir_entry.name(),
                        dir_entry.full_path().as_str(),
                    );

                    let mut size_is_match = true;
                    let mut creation_time_match = true;
                    let mut modification_time_match = true;

                    let stat_required = find_options.size_range.is_some()
                        || find_options.min_creation_time.is_some()
                        || find_options.max_creation_time.is_some()
                        || find_options.min_modification_time.is_some()
                        || find_options.max_modification_time.is_some();

                    if stat_required {
                        let metadata = dir_entry.metadata(cedar_auth)?;
                        let mtime = metadata.mtime();
                        let ctime = metadata.ctime();

                        let file_size = metadata.file_size()?;
                        size_is_match = does_size_filter_match(&find_options, file_size);

                        creation_time_match = does_creation_time_match(&find_options, ctime)?;
                        modification_time_match =
                            does_modification_time_match(&find_options, mtime)?;
                    }

                    let matches = name_or_regex_match
                        && size_is_match
                        && creation_time_match
                        && modification_time_match;
                    if matches && let Err(e) = callback(&WalkEntry::Entry(dir_entry)) {
                        return Err(RustSafeIoError::CallbackError {
                            reason: format!("{e}"),
                            source: Box::new(e),
                        });
                    }
                }
                WalkEntry::DirPre(_) | WalkEntry::DirPost(_) | WalkEntry::File(_) => {}
            }
        }
        Ok(())
    }
}

fn does_pattern_match(
    glob_pattern: Option<&Pattern>,
    regex_pattern: Option<&Regex>,
    find_options: &FindOptions,
    entry_name: &str,
    entry_full_path: &str,
) -> bool {
    glob_pattern.map_or_else(
        || regex_pattern.is_none_or(|pattern| pattern.is_match(entry_full_path)),
        |pattern| {
            let base_match = if find_options.name.is_some() {
                pattern.matches(entry_name)
            } else {
                pattern.matches_with(entry_name, MatchOptions::default())
            };
            base_match ^ find_options.negate_name
        },
    )
}

fn does_size_filter_match(options: &FindOptions, file_size: i64) -> bool {
    let mut matches = true;

    if let Some(size_range) = &options.size_range
        && !size_range.matches(file_size)
    {
        matches = false;
    }

    matches
}

fn does_creation_time_match(
    find_options: &FindOptions,
    ctime: i64,
) -> Result<bool, RustSafeIoError> {
    let dt_ctime = DateTime::from_epoch_seconds(ctime)?;

    if let Some(min_time) = &find_options.min_creation_time
        && dt_ctime < *min_time
    {
        return Ok(false);
    }

    if let Some(max_time) = &find_options.max_creation_time
        && dt_ctime > *max_time
    {
        return Ok(false);
    }

    Ok(true)
}

fn does_modification_time_match(
    find_options: &FindOptions,
    mtime: i64,
) -> Result<bool, RustSafeIoError> {
    let dt_mtime = DateTime::from_epoch_seconds(mtime)?;

    if let Some(min_time) = &find_options.min_modification_time
        && dt_mtime < *min_time
    {
        return Ok(false);
    }

    if let Some(max_time) = &find_options.max_modification_time
        && dt_mtime > *max_time
    {
        return Ok(false);
    }

    Ok(true)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::options::FindOptionsBuilder;
    use crate::options::{SizeRange, SizeUnit};

    /// Given: A find options with size range [100, 200]
    /// When: Checking a file with size within bounds
    /// Then: Should return true indicating the file matches the criteria
    #[test]
    fn test_match_size_filter_success() {
        let size_range = SizeRange::between(10, 30, SizeUnit::Bytes);
        let options = FindOptionsBuilder::default()
            .size_range(size_range)
            .build()
            .unwrap();

        let result = does_size_filter_match(&options, 20);
        assert!(result, "Expected match");
    }

    /// Given: A find options with creation time range [100, 300]
    /// When: Checking a file with creation time within bounds
    /// Then: Should return true indicating the file matches the criter
    #[test]
    fn test_match_creation_time_success() -> Result<(), RustSafeIoError> {
        let min_time = DateTime::from_epoch_seconds(100)?;
        let max_time = DateTime::from_epoch_seconds(300)?;

        let find_options = FindOptionsBuilder::default()
            .min_creation_time(min_time)
            .max_creation_time(max_time)
            .build()?;

        let file_ctime = 200;
        let result = does_creation_time_match(&find_options, file_ctime)?;

        assert!(
            result,
            "Expected file with ctime 200 to match range [100, 300]"
        );
        Ok(())
    }

    /// Given: A find options with creation time range [100, 300]
    /// When: Checking a file with creation time outside bounds
    /// Then: Should return false indicating the file does not match the criteria
    #[test]
    fn test_match_creation_time_failure() -> Result<(), RustSafeIoError> {
        let min_time = DateTime::from_epoch_seconds(100)?;
        let max_time = DateTime::from_epoch_seconds(300)?;

        let find_options = FindOptionsBuilder::default()
            .min_creation_time(min_time)
            .max_creation_time(max_time)
            .build()?;

        let ctime_too_low = 0;
        let result_low = does_creation_time_match(&find_options, ctime_too_low)?;

        let ctime_too_high = 400;
        let result_high = does_creation_time_match(&find_options, ctime_too_high)?;

        assert!(
            !result_low,
            "Expected file with ctime 0 to NOT match range [100, 300]"
        );

        assert!(
            !result_high,
            "Expected file with ctime 400 to NOT match range [100, 300]"
        );

        Ok(())
    }

    /// Given: A find options with modification time range [500, 800]
    /// When: Checking a file with modification time within bounds
    /// Then: Should return true indicating the file matches the criteria
    #[test]
    fn test_match_modification_time_success() -> Result<(), RustSafeIoError> {
        let min_time = DateTime::from_epoch_seconds(500)?;
        let max_time = DateTime::from_epoch_seconds(800)?;

        let find_options = FindOptionsBuilder::default()
            .min_modification_time(min_time)
            .max_modification_time(max_time)
            .build()?;

        let file_mtime = 650;
        let result = does_modification_time_match(&find_options, file_mtime)?;

        assert!(
            result,
            "Expected file with mtime 650 to match range [500, 800]"
        );
        Ok(())
    }

    /// Given: A find options with modification time range [500, 800]
    /// When: Checking a file with modification time outside bounds
    /// Then: Should return false indicating the file does not match the criteria
    #[test]
    fn test_match_modification_time_failure() -> Result<(), RustSafeIoError> {
        let min_time = DateTime::from_epoch_seconds(500)?;
        let max_time = DateTime::from_epoch_seconds(800)?;

        let find_options = FindOptionsBuilder::default()
            .min_modification_time(min_time)
            .max_modification_time(max_time)
            .build()?;

        let mtime_too_low = 200;
        let result_low = does_modification_time_match(&find_options, mtime_too_low)?;

        let mtime_too_high = 900;
        let result_high = does_modification_time_match(&find_options, mtime_too_high)?;

        assert!(
            !result_low,
            "Expected file with mtime 200 to NOT match range [500, 800]"
        );

        assert!(
            !result_high,
            "Expected file with mtime 900 to NOT match range [500, 800]"
        );
        Ok(())
    }
}
