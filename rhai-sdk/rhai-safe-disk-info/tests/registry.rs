#![cfg(target_os = "linux")]
use rex_test_utils::rhai::common::create_test_engine_and_register;
use rhai::{EvalAltResult, Scope};
use rstest::rstest;

/// Given: A new Rhai engine is created
/// When: Safe diskinfo functions are registered
/// Then: All expected safe diskinfo functions are available in the engine
#[rstest]
#[case::standard_operations(None)]
fn test_diskinfo_function_registration(
    #[case] force: Option<bool>,
) -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let mut scope = Scope::new();

    match force {
        None => {
            // Test FilesystemOptions builder methods
            assert!(
                engine
                    .eval_with_scope::<()>(
                        &mut scope,
                        r#"let fs_opts = FilesystemOptions().local(true).build();"#
                    )
                    .is_ok(),
                "FilesystemOptions().local() is not properly registered"
            );

            assert!(
                engine
                    .eval_with_scope::<()>(
                        &mut scope,
                        r#" let target_paths = ["/", "/tmp"];
                    let fs_opts = FilesystemOptions().targets(target_paths).build();
                "#
                    )
                    .is_ok(),
                "FilesystemOptions().targets() is not properly registered"
            );

            assert!(
                engine
                    .eval_with_scope::<()>(
                        &mut scope,
                        r#"
                    let fs_opts = FilesystemOptions()
                        .local(true)
                        .targets([""])
                        .build();
                "#
                    )
                    .is_ok(),
                "FilesystemOptions() method chaining is not properly registered"
            );

            // Test Filesystems creation and filesystems() method
            assert!(
                engine
                    .eval_with_scope::<()>(
                        &mut scope,
                        r#"
                    let fs_opts = FilesystemOptions()
                        .local(true)
                        .build();
                    let filesystems = Filesystems(fs_opts).filesystems();
                "#
                    )
                    .is_ok(),
                "Filesystems::filesystems() is not properly registered"
            );

            let result = engine.eval_with_scope::<()>(
                &mut scope,
                r#"
                    let fs_opts = FilesystemOptions()
                        .targets(["/"])  // Target root filesystem which is guaranteed to exist
                        .build();
                    let filesystems = Filesystems(fs_opts).filesystems();
                    
                    // Skip test if no filesystems are returned
                    if filesystems.len() > 0 {
                        let fs = filesystems[0];
                        
                        // Test basic properties
                        let device = fs.fs_device;
                        let kind = fs.fs_kind;
                        let mount = fs.mounted_on;
                        
                        // Test size properties
                        let size = fs.size;
                        let size_kb = fs.kb_blocks;
                        let size_mb = fs.mb_blocks;
                        let used = fs.block_used;
                        let avail = fs.block_available;
                        let percent = fs.block_use_percent;

                        
                        // Test inode properties
                        let inodes = fs.inodes;
                        let inodes_used = fs.iused;
                        let inodes_free = fs.ifree;
                        let inode_percent = fs.iuse_percent;

                        let kb_result = format_bytes(size_kb, Unit::KILOBYTES);
                        let mb_result = format_bytes(size_mb, Unit::MEGABYTES);
                        let byte_result = format_bytes(size_mb, Unit::BYTES);
                    }
                "#,
            );
            // Test accessing filesystem properties
            assert!(
                result.is_ok(),
                "Filesystem property getters are not properly registered: {:?}",
                result
            );
        }
        // The force option is not applicable for the sysinfo module as it doesn't have delete operations
        // This branch is kept for compatibility with the test structure
        Some(_force) => {
            // No operations to test with force flag in sysinfo module
            println!("Force option not applicable for sysinfo operations");
        }
    }

    Ok(())
}
