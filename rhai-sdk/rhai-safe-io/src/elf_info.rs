#![deny(missing_docs)]
//! The functions used here are declared in the rust-safe-io crate.
#![allow(
    unused_variables,
    unreachable_code,
    clippy::unreachable,
    clippy::needless_pass_by_value
)]
use rhai::EvalAltResult;
use rust_safe_io::ElfInfo;

use crate::safe_io::FileHandle;

impl FileHandle {
    /// Provides [`ElfInfo`] about binaries matching output from the UNIX `file` command.
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
    /// # let fixture_dir = format!("{}/tests/fixtures/elf_info", env!("CARGO_MANIFEST_DIR"));
    /// # scope.push_constant("fixture_dir", fixture_dir);
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    /// let dir_config = DirConfig()
    ///     .path(fixture_dir)
    ///     .build();
    /// let dir_handle = dir_config.open(OpenDirOptions().build());
    /// let file_handle = dir_handle.open_file("core.3922", OpenFileOptions().read(true).build());
    ///
    /// let elf_info = file_handle.elf_info();
    ///
    /// // execfn if it exists
    /// if elf_info.execfn != () {
    ///     print(elf_info.execfn);
    /// }
    ///
    /// // platform if it exists
    /// if elf_info.platform != () {
    ///     print(elf_info.platform);
    /// }
    ///
    /// // interpreter if it exists
    /// if elf_info.interpreter != () {
    ///     print(elf_info.interpreter);
    /// }
    ///
    /// // is_64bit
    /// if elf_info.is_64bit == true {{
    ///     print(elf_info.is_64bit);
    /// }
    /// }
    /// # "#);
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[doc(alias = "file")]
    pub fn elf_info(&self) -> Result<ElfInfo, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }
}
