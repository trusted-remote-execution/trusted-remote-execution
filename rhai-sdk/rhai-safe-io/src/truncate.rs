use rex_cedar_auth::cedar_auth::CedarAuth;
use rhai::EvalAltResult;
use rust_safe_io::truncate::TruncateOptions;

use crate::safe_io::FileHandle;

impl FileHandle {
    /// Truncates a file specified in [`FileHandle`] to a specified size
    /// and format from [`TruncateOptions`]
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
    /// let file_handle = dir_handle.open_file("file.txt", OpenFileOptions().read(true).create(true).build());
    /// file_handle.truncate(TruncateOptions().size(10).build());
    ///
    /// file_handle.truncate(TruncateOptions().format(SizeUnit::BYTES).build());
    /// # "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[allow(unused_variables, unreachable_code, clippy::unreachable)]
    pub fn truncate(
        &mut self,
        cedar_auth: &CedarAuth,
        options: &TruncateOptions,
    ) -> Result<(), Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }
}
