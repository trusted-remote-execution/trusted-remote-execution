#![deny(missing_docs)]
//! The function used here is declared in the rust-safe-io crate.
#![allow(
    unused_variables,
    unreachable_code,
    clippy::unreachable,
    unused_mut,
    clippy::needless_pass_by_value
)]

use crate::safe_io::FileHandle;
use rhai::EvalAltResult;
use rust_safe_io::execute::{ExecuteOptions, ExecuteResult};

impl FileHandle {
    /// Executes a command using the file handle.
    ///
    /// Only supported for Linux-based platforms.
    ///
    /// # Cedar Permissions
    ///
    /// | Action | Resource |
    /// |--------|----------|
    /// | `file_system::Action::"execute"` | [`file_system::File::"<absolute_path>"`](cedar_auth::fs::entities::FileEntity) |
    ///
    /// Authorization is checked with context entities including
    /// [`Arguments`](cedar_auth::fs::entities::ArgumentsEntity) and
    /// [`Environment`](cedar_auth::fs::entities::EnvironmentEntity).
    /// Cedar policies can use these to restrict which flags, args, and env vars are permitted.
    ///
    /// # Linux Capabilities
    ///
    /// | Capability | Condition |
    /// |------------|-----------|
    /// | `CAP_SETUID` | Required when `user` option is set |
    /// | `CAP_SETGID` | Required when `group` option is set |
    /// | `CAP_SYS_ADMIN` | Required when `namespace` option is set |
    /// | `CAP_SYS_PTRACE` | Required when namespace target PID has a different UID/GID than the caller |
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use rex_test_utils::rhai::safe_io::create_temp_test_env;
    /// # let (mut scope, engine) = create_temp_test_env();
    /// # let result = engine.eval_with_scope::<()>(
    /// # &mut scope,
    /// # r#"
    ///     let dir_config = DirConfig()
    ///         .path("/usr/bin")
    ///         .build();
    ///     let dir_handle = dir_config.open(OpenDirOptions().build());
    ///     let file_handle = dir_handle.open_file("ls", OpenFileOptions().read(true).build());
    ///
    ///     let args = [
    ///         "-l",                    // Flag
    ///         ["--sort", "time"],      // Key-value pair
    ///         "/tmp"                   // Positional argument
    ///     ];
    ///     
    ///     let env = #{
    ///         "LANG": "en_US.UTF-8",
    ///         "PATH": "/usr/bin:/bin"
    ///     };
    ///     
    ///     let capabilities = ["CAP_DAC_OVERRIDE"];
    ///          
    ///     let namespace_options = ChildNamespaceOptions()
    ///         .target_process(1234)
    ///         .build();
    ///     
    ///     let options = ExecuteOptions()
    ///         .args(args)
    ///         .env(env)
    ///         .capabilities(capabilities)
    ///         .user("nobody")
    ///         .group("nobody")
    ///         .namespace(namespace_options)
    ///         .build();
    ///
    ///     
    ///     let result = file_handle.execute(options);
    ///     print("Exit code: " + result.exit_code);
    ///     print("Output: " + result.stdout);
    ///     if result.stderr != "" {
    ///         print("Errors: " + result.stderr);
    ///     }
    /// # "#);
    ///
    /// # assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
    /// ```
    #[cfg(target_os = "linux")]
    #[doc(alias = "iptables")]
    #[doc(alias = "ip6tables")]
    #[doc(alias = "vgs")]
    #[doc(alias = "vgrename")]
    #[doc(alias = "matchpathcon")]
    #[doc(alias = "perl")]
    #[doc(alias = "python")]
    #[doc(alias = "python3")]
    #[doc(alias = "tcpdump")]
    #[doc(alias = "bash")]
    #[doc(alias = "sh")]
    #[doc(alias = "db2trc")]
    #[doc(alias = "drbdadm")]
    #[doc(alias = "drbdsetup")]
    #[doc(alias = "klist")]
    #[doc(alias = "numactl")]
    #[doc(alias = "pip3")]
    #[doc(alias = "swapon")]
    #[doc(alias = "tbstack")]
    pub fn execute(
        &mut self,
        options: ExecuteOptions,
    ) -> Result<ExecuteResult, Box<EvalAltResult>> {
        unreachable!("This method exists only for documentation.")
    }
}
