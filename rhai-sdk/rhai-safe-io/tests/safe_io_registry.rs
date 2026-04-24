use rex_test_utils::io::create_and_write_to_test_file;
use rex_test_utils::io::create_temp_dir_and_path;
use rex_test_utils::random::get_rand_string;
use rex_test_utils::rhai::common::{create_test_engine_and_register, to_eval_error};
use rhai::{EvalAltResult, Scope};
use rstest::rstest;
use rust_safe_io::DirConfigBuilder;

/// Given: A new Rhai engine is created
/// When: Safe I/O functions are registered
/// Then: All expected safe I/O functions are available in the engine
#[rstest]
#[case::standard_operations(None)]
#[case::delete_no_force(Some(false))]
#[case::delete_force(Some(true))]
fn test_standard_io_operations(#[case] force: Option<bool>) -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;
    let temp_dir_name = get_rand_string();
    let temp_file_name = get_rand_string();
    let file_name = "example_file.txt";

    create_and_write_to_test_file(&temp_dir, file_name).expect("Failed to create test file");

    let mut scope = Scope::new();
    scope.push("directory_path", temp_dir_path.clone());
    scope.push("file_name", file_name);

    match force {
        None => {
            scope.push("content", "test");
            scope.push_constant("temp_dir_path", temp_dir_path);
            scope.push_constant("temp_dir_name", temp_dir_name);
            scope.push_constant("temp_file_name", temp_file_name);

            assert!(
                engine
                    .eval_with_scope::<DirConfigBuilder>(
                        &mut scope,
                        r#"
                            DirConfig()
                                .path(`${directory_path}/${temp_dir_name}`)
                        "#,
                    )
                    .is_ok(),
                "DirConfigBuilder is not properly registered"
            );

            assert!(
                engine
                    .eval_with_scope::<()>(
                        &mut scope,
                        r#"
                            let dir_handle = DirConfig()
                                .path(directory_path)
                                .build().open(OpenDirOptions().build());
                            let file_handle = dir_handle.open_file(file_name, OpenFileOptions().read(true).build());
                        "#
                    )
                    .is_ok(),
                "open_file is not properly registered"
            );

            assert!(
                engine
                    .eval_with_scope::<()>(
                        &mut scope,
                        r#"
                            let dir_handle = DirConfig()
                                .path(directory_path)
                                .build().open(OpenDirOptions().build());
                            let file_handle = dir_handle.open_file(file_name, OpenFileOptions().read(true).build());
                            let content = file_handle.read();
                        "#
                    )
                    .is_ok(),
                "read is not properly registered"
            );

            assert!(
                engine
                    .eval_with_scope::<()>(
                        &mut scope,
                        r#"
                            let dir_handle = DirConfig()
                                .path(directory_path)
                                .build().open(OpenDirOptions().build());
                            let file_handle = dir_handle.open_file(file_name, OpenFileOptions().write(true).build());
                            file_handle = file_handle.write(content);
                        "#
                    )
                    .is_ok(),
                "write is not properly registered"
            );

            // Validate unix-specific safe IO operations
            #[cfg(unix)]
            {
                assert!(
                    engine
                        .eval_with_scope::<()>(
                            &mut scope,
                            r#"
                                let dir_handle = DirConfig()
                                    .path(directory_path)
                                    .build().open(OpenDirOptions().build());
                                let file_handle = dir_handle.open_file(file_name, OpenFileOptions().write(true).build());
                                file_handle.write_in_place(content);
                            "#
                        )
                        .is_ok(),
                    "write_in_place is not properly registered"
                );

                assert!(
                    engine
                        .eval_with_scope::<()>(
                            &mut scope,
                            r#"
                                let dir_handle = DirConfig()
                                    .path(directory_path)
                                    .build().open(OpenDirOptions().build());
                                let file_handle = dir_handle.open_file(file_name, OpenFileOptions().read(true).build());
                                let modified_time = file_handle.get_last_modified_time();
                            "#
                        )
                        .is_ok(),
                    "get_last_modified_time is not properly registered"
                );
            }

            assert!(
                engine
                    .eval_with_scope::<()>(
                        &mut scope,
                        r#"
                            let dir_handle = DirConfig()
                                .path(directory_path)
                                .build().open(OpenDirOptions().build());
                            let file_handle = dir_handle.open_file(temp_file_name, OpenFileOptions().create(true).build());
                            file_handle = file_handle.write(content);
                        "#
                    )
                    .is_ok(),
                "create_file is not properly registered"
            );

            assert!(
                engine
                    .eval_with_scope::<()>(
                        &mut scope,
                        r#"
                            let dir_handle = DirConfig()
                                .path(directory_path)
                                .build().open(OpenDirOptions().build());
                            let file_handle = dir_handle.open_file(file_name, OpenFileOptions().read(true).build());
                            let matches = file_handle.search("test");
                        "#
                    )
                    .is_ok(),
                "search is not properly registered"
            );

            #[cfg(target_os = "linux")]
            assert!(
                engine
                    .eval_with_scope::<()>(
                        &mut scope,
                        r#"
                            let dir_handle = DirConfig()
                                .path(directory_path)
                                .build().open(OpenDirOptions().build());
                            let file_handle = dir_handle.open_file(file_name, OpenFileOptions().write(true).read(true).build());
                            file_handle.truncate(TruncateOptions().size(10).format(SizeUnit::KIBIBYTES).build());
                        "#
                    )
                    .is_ok(),
                "truncate is not properly registered"
            );
        }
        Some(force) => {
            scope.push_constant("force", force);

            assert!(
                engine
                    .eval_with_scope::<()>(
                        &mut scope,
                        r#"
                            let dir_handle = DirConfig()
                                .path(directory_path)
                                .build().open(OpenDirOptions().build());
                            let file_handle = dir_handle.open_file(file_name, OpenFileOptions().read(true).build());
                            file_handle.delete(DeleteFileOptions().build());
                        "#
                    )
                    .is_ok(),
                "delete_file is not properly registered"
            );
        }
    }

    let _ = temp_dir.close();
    Ok(())
}

/// Given: A new Rhai engine is created
/// When: delete_dir function is registered
/// Then: delete_dir function is available in the engine
#[rstest]
#[case::delete_dir_non_recursive_no_force(false, false)]
#[case::delete_dir_recursive_no_force(true, false)]
#[case::delete_dir_non_recursive_force(false, true)]
#[case::delete_dir_recursive_force(true, true)]
fn test_delete_dir(#[case] force: bool, #[case] recursive: bool) -> Result<(), Box<EvalAltResult>> {
    let engine = create_test_engine_and_register();
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path().map_err(to_eval_error)?;

    let mut scope = Scope::new();
    scope.push_constant("temp_dir_path", temp_dir_path);
    scope.push_constant("force", force);
    scope.push_constant("recursive", recursive);

    let result = engine.eval_with_scope::<()>(
        &mut scope,
        r#"
            let dir_config = DirConfig()
                .path(temp_dir_path)
                .build();

            let dir_handle = dir_config.open(OpenDirOptions().build());
            dir_handle.delete(DeleteDirOptions().force(true).recursive(true).build());
        "#,
    );

    assert!(result.is_ok());

    let _ = temp_dir.close();
    Ok(())
}
