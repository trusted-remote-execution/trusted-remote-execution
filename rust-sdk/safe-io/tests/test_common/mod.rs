use rex_cedar_auth::test_utils::DEFAULT_TEST_CEDAR_AUTH;
use rex_test_utils::io::create_temp_dir_and_path;
use rex_test_utils::random::get_rand_string;
use rust_safe_io::errors::RustSafeIoError;
use rust_safe_io::options::{OpenDirOptionsBuilder, OpenFileOptionsBuilder};
use rust_safe_io::{DirConfigBuilder, RcDirHandle, RcFileHandle};

use anyhow::Result;
use assert_fs::TempDir;
use assert_fs::fixture::ChildPath;
use assert_fs::prelude::{FileWriteStr, PathChild};
use std::process::Command;
use std::rc::Rc;
use tracing_subscriber::fmt;

pub const PERMISSION_EXTRACT_BITMASK: u32 = 0o777;

#[derive(Debug)]
pub struct TestContents {
    pub file_handle: RcFileHandle,
    pub dir_name: String,
    pub file_name: String,
    pub _tempdir: TempDir,
    pub _content: String,
}

pub struct TestMoveSetup {
    pub src_parent_handle: RcDirHandle,
    pub src_dir_handle: RcDirHandle,
    pub src_parent_dir: TempDir,
    pub src_dir: ChildPath,
    pub dst_parent_dir: TempDir,
    pub dst_parent_handle: RcDirHandle,
}

/// Open a dir using the default cedar auth and default open options.
pub fn open_test_dir_handle(temp_dir_path: &String) -> RcDirHandle {
    DirConfigBuilder::default()
        .path(temp_dir_path.clone())
        .build()
        .unwrap()
        .safe_open(
            &DEFAULT_TEST_CEDAR_AUTH,
            OpenDirOptionsBuilder::default().build().unwrap(),
        )
        .unwrap()
}

// this will create the test elements and return content
// that's written to a temp file (test_str)
pub fn open_dir_and_file() -> Result<Rc<TestContents>> {
    let test_str = get_rand_string();
    open_dir_and_file_with_contents(test_str)
}

pub fn open_dir_and_file_with_contents(contents: String) -> Result<Rc<TestContents>> {
    let (temp, temp_dir_path) = create_temp_dir_and_path()?;

    let rand_path = get_rand_string();
    temp.child(&rand_path).write_str(&contents)?;

    let dir = open_test_dir_handle(&temp_dir_path);
    let file = dir.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        &rand_path,
        OpenFileOptionsBuilder::default()
            .read(true)
            .write(true)
            .build()
            .unwrap(),
    )?;

    let test_contents = TestContents {
        file_handle: file,
        dir_name: temp_dir_path,
        file_name: rand_path,
        _tempdir: temp,
        _content: contents,
    };

    Ok(Rc::new(test_contents))
}

/// Enables code coverage for `tracing::debug` calls.
pub fn init_test_logger() {
    let _ = fmt::Subscriber::builder()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();
}

pub fn open_dir_with_follow_symlinks(
    path: String,
    follow_symlinks: bool,
) -> Result<RcDirHandle, RustSafeIoError> {
    DirConfigBuilder::default().path(path).build()?.safe_open(
        &DEFAULT_TEST_CEDAR_AUTH,
        OpenDirOptionsBuilder::default()
            .follow_symlinks(follow_symlinks)
            .build()
            .unwrap(),
    )
}

pub fn read_and_verify_file_content(
    dir_handle: &RcDirHandle,
    filename: &str,
    expected_content: &str,
) -> Result<()> {
    let file_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        filename,
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let content = file_handle.safe_read(&DEFAULT_TEST_CEDAR_AUTH)?;
    assert_eq!(content, expected_content);
    Ok(())
}

pub fn run_bash_command(command_str: &str) -> Result<String> {
    let mut command_iter = command_str.split(" ");
    let command_name = command_iter.next().unwrap();

    let mut command = Command::new(command_name);
    command_iter.for_each(|arg| {
        if !arg.is_empty() {
            command.arg(arg);
        }
    });

    let output = command.output().expect("Failed to execute command");

    Ok(String::from_utf8(output.stdout)?)
}
