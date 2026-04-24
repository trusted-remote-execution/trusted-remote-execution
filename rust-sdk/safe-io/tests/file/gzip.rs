use crate::test_common::open_test_dir_handle;
use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::io::create_temp_dir_and_path;

use anyhow::Result;
use assert_fs::TempDir;
use assert_fs::fixture::FileWriteStr;
use assert_fs::fixture::PathChild;
use rstest::rstest;
use rust_safe_io::RcFileHandle;
use rust_safe_io::error_constants::{
    INVALID_REGEX_PATTERN_ERR, READ_FILE_FLAG_ERR, WRITE_FILE_FLAG_ERR,
};
use rust_safe_io::options::{
    CompressGzipOptionsBuilder, OpenFileOptionsBuilder, SearchGzipOptionsBuilder,
};
use std::path::PathBuf;
use std::process::Command;

// ============================================================================
// Helper Functions
// ============================================================================

/// Creates a gzip file using the system gzip command.
/// This is used by search tests to isolate search functionality testing from our compression library.
fn create_gzip_with_system_command(
    temp_dir: &TempDir,
    filename: &str,
    content: &str,
) -> Result<PathBuf> {
    let source_file = temp_dir.child(filename);
    source_file.write_str(content)?;

    let source_path = temp_dir.path().join(filename);
    let gz_path = temp_dir.path().join(format!("{}.gz", filename));

    let output = Command::new("gzip").arg("-c").arg(&source_path).output()?;

    assert!(
        output.status.success(),
        "System gzip command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::write(&gz_path, &output.stdout)?;

    Ok(gz_path)
}

/// Sets up a gzip test using the system gzip command for compression.
/// Returns the temp directory and a file handle to the gzip file ready for search/read operations.
fn setup_gzip_test_with_system(content: &str) -> Result<(TempDir, PathBuf, RcFileHandle)> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let gz_path = create_gzip_with_system_command(&temp_dir, "source.txt", content)?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let gzip_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "source.txt.gz",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    Ok((temp_dir, gz_path, gzip_handle))
}

/// Sets up a test with our compression API and returns handles for both source and destination.
/// Used for tests that specifically need to test our compression functionality.
#[allow(dead_code)]
fn setup_compress_test(content: &str) -> Result<(TempDir, String, RcFileHandle, RcFileHandle)> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let source_file = temp_dir.child("source.txt");
    source_file.write_str(content)?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let source_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "source.txt",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let dest_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "source.txt.gz",
        OpenFileOptionsBuilder::default()
            .read(true)
            .create(true)
            .build()
            .unwrap(),
    )?;

    Ok((temp_dir, temp_dir_path, source_handle, dest_handle))
}

// ============================================================================
// Compression Tests
// ============================================================================

/// Given: A regular text file and a destination file
/// When: safe_compress_gzip is called with default options
/// Then: The file is compressed successfully and can be decompressed by system gzip
#[test]
fn test_safe_compress_gzip_success() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let test_content = "Hello, this is test content for gzip compression!\n";
    let source_file = temp_dir.child("source.txt");
    source_file.write_str(test_content)?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let source_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "source.txt",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let dest_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "source.txt.gz",
        OpenFileOptionsBuilder::default()
            .create(true)
            .build()
            .unwrap(),
    )?;

    let options = CompressGzipOptionsBuilder::default().build().unwrap();

    let result = source_handle.safe_compress_gzip(&DEFAULT_TEST_CEDAR_AUTH, dest_handle, options);

    assert!(result.is_ok(), "Expected Ok but got: {:?}", result);

    // Verify the compressed file exists and can be decompressed by system gzip
    let gz_path = temp_dir.path().join("source.txt.gz");
    assert!(gz_path.exists());

    // Use system gunzip to decompress and verify content matches
    let output = Command::new("gunzip").arg("-c").arg(&gz_path).output()?;

    assert!(output.status.success());
    let decompressed_content = String::from_utf8(output.stdout)?;
    assert_eq!(decompressed_content, test_content);

    Ok(())
}

/// Given: An invalid compression level
/// When: CompressGzipOptionsBuilder is called with that level
/// Then: Validation error is returned
#[rstest]
#[case(0)]
#[case(10)]
fn test_compress_gzip_options_invalid_level(#[case] level: u32) -> Result<()> {
    let result = CompressGzipOptionsBuilder::default().level(level).build();

    assert_error_contains(result, "Compression level must be between 1 and 9");

    Ok(())
}

/// Given: A source file without read permission
/// When: safe_compress_gzip is called
/// Then: An error is returned indicating missing read option
#[test]
fn test_safe_compress_gzip_source_no_read_option() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let source_file = temp_dir.child("source.txt");
    source_file.write_str("content")?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let source_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "source.txt",
        OpenFileOptionsBuilder::default()
            .write(true)
            .build()
            .unwrap(),
    )?;

    let dest_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "dest.gz",
        OpenFileOptionsBuilder::default()
            .create(true)
            .build()
            .unwrap(),
    )?;

    let options = CompressGzipOptionsBuilder::default().build().unwrap();

    let result = source_handle.safe_compress_gzip(&DEFAULT_TEST_CEDAR_AUTH, dest_handle, options);

    assert_error_contains(result, READ_FILE_FLAG_ERR);

    Ok(())
}

/// Given: A destination file without write permission
/// When: safe_compress_gzip is called
/// Then: An error is returned indicating missing write option
#[test]
fn test_safe_compress_gzip_dest_no_write_option() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let source_file = temp_dir.child("source.txt");
    source_file.write_str("content")?;

    // Create dest file first
    let dest_file = temp_dir.child("dest.gz");
    dest_file.write_str("")?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let source_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "source.txt",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let dest_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "dest.gz",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let options = CompressGzipOptionsBuilder::default().build().unwrap();

    let result = source_handle.safe_compress_gzip(&DEFAULT_TEST_CEDAR_AUTH, dest_handle, options);

    assert_error_contains(result, WRITE_FILE_FLAG_ERR);

    Ok(())
}

/// Given: A source file and unauthorized user for reading
/// When: safe_compress_gzip is called
/// Then: Access is denied for read permission
#[test]
fn test_unauthorized_safe_compress_gzip_read() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let source_file = temp_dir.child("source.txt");
    source_file.write_str("content")?;

    let principal = get_test_rex_principal();
    let source_path = format!("{}/source.txt", temp_dir_path);
    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action,
            resource
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{source_path}"
        );"#,
        FilesystemAction::Read
    );
    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let source_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "source.txt",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let dest_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "dest.gz",
        OpenFileOptionsBuilder::default()
            .create(true)
            .build()
            .unwrap(),
    )?;

    let options = CompressGzipOptionsBuilder::default().build().unwrap();

    let result = source_handle.safe_compress_gzip(&test_cedar_auth, dest_handle, options);

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Read
    );
    assert_error_contains(result, &expected_error);

    Ok(())
}

/// Given: A destination file and unauthorized user for writing
/// When: safe_compress_gzip is called
/// Then: Access is denied for write permission
#[test]
fn test_unauthorized_safe_compress_gzip_write() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let source_file = temp_dir.child("source.txt");
    source_file.write_str("content")?;

    let principal = get_test_rex_principal();
    let dest_path = format!("{}/dest.gz", temp_dir_path);
    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action,
            resource
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{dest_path}"
        );"#,
        FilesystemAction::Write
    );
    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let source_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "source.txt",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let dest_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "dest.gz",
        OpenFileOptionsBuilder::default()
            .create(true)
            .build()
            .unwrap(),
    )?;

    let options = CompressGzipOptionsBuilder::default().build().unwrap();

    let result = source_handle.safe_compress_gzip(&test_cedar_auth, dest_handle, options);

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Write
    );
    assert_error_contains(result, &expected_error);

    Ok(())
}

/// Given: The same content compressed at level 1 and level 9
/// When: Comparing output file sizes
/// Then: Level 9 should produce smaller or equal output than level 1
#[test]
fn test_compress_gzip_level_affects_output_size() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    // Create a large, compressible file (repeating text compresses well at different levels)
    let test_content = "The quick brown fox jumps over the lazy dog. ".repeat(1000);
    let source_file = temp_dir.child("source.txt");
    source_file.write_str(&test_content)?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);

    // Compress with level 1 (fastest, less compression)
    let source_handle_1 = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "source.txt",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let dest_handle_1 = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "level1.gz",
        OpenFileOptionsBuilder::default()
            .create(true)
            .build()
            .unwrap(),
    )?;

    let options_1 = CompressGzipOptionsBuilder::default()
        .level(1)
        .build()
        .unwrap();

    source_handle_1.safe_compress_gzip(&DEFAULT_TEST_CEDAR_AUTH, dest_handle_1, options_1)?;

    // Compress with level 9 (best compression)
    let source_handle_9 = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "source.txt",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let dest_handle_9 = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "level9.gz",
        OpenFileOptionsBuilder::default()
            .create(true)
            .build()
            .unwrap(),
    )?;

    let options_9 = CompressGzipOptionsBuilder::default()
        .level(9)
        .build()
        .unwrap();

    source_handle_9.safe_compress_gzip(&DEFAULT_TEST_CEDAR_AUTH, dest_handle_9, options_9)?;

    // Compare file sizes
    let level1_size = std::fs::metadata(temp_dir.path().join("level1.gz"))?.len();
    let level9_size = std::fs::metadata(temp_dir.path().join("level9.gz"))?.len();

    // Level 9 should produce smaller or equal output
    assert!(
        level9_size <= level1_size,
        "Level 9 ({} bytes) should be <= Level 1 ({} bytes)",
        level9_size,
        level1_size
    );

    // Verify both can be decompressed to original content
    let output_1 = Command::new("gunzip")
        .arg("-c")
        .arg(temp_dir.path().join("level1.gz"))
        .output()?;
    let output_9 = Command::new("gunzip")
        .arg("-c")
        .arg(temp_dir.path().join("level9.gz"))
        .output()?;

    assert!(output_1.status.success());
    assert!(output_9.status.success());
    assert_eq!(String::from_utf8(output_1.stdout)?, test_content);
    assert_eq!(String::from_utf8(output_9.stdout)?, test_content);

    Ok(())
}

/// Given: The same content compressed by our API and system gzip
/// When: Comparing output using same compression level
/// Then: Output should be similar size and both decompress to same content
#[test]
fn test_compress_gzip_matches_system_gzip() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let test_content = "Test content for comparing with system gzip output.\n".repeat(100);
    let source_file = temp_dir.child("source.txt");
    source_file.write_str(&test_content)?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);

    // Compress with our API (default level 6)
    let source_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "source.txt",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let dest_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "api.gz",
        OpenFileOptionsBuilder::default()
            .create(true)
            .build()
            .unwrap(),
    )?;

    let options = CompressGzipOptionsBuilder::default()
        .level(6)
        .build()
        .unwrap();

    source_handle.safe_compress_gzip(&DEFAULT_TEST_CEDAR_AUTH, dest_handle, options)?;

    // Compress with system gzip at same level
    let system_output = Command::new("gzip")
        .arg("-6")
        .arg("-c")
        .arg(temp_dir.path().join("source.txt"))
        .output()?;

    assert!(system_output.status.success());
    std::fs::write(temp_dir.path().join("system.gz"), &system_output.stdout)?;

    let api_size = std::fs::metadata(temp_dir.path().join("api.gz"))?.len();
    let system_size = system_output.stdout.len() as u64;

    // Sizes should be reasonably close (within 15% tolerance due to header differences)
    let diff_percent = ((api_size as f64 - system_size as f64).abs() / system_size as f64) * 100.0;
    assert!(
        diff_percent < 15.0,
        "API size ({} bytes) differs from system gzip ({} bytes) by {:.1}%",
        api_size,
        system_size,
        diff_percent
    );

    // Both should decompress to same content
    let api_output = Command::new("gunzip")
        .arg("-c")
        .arg(temp_dir.path().join("api.gz"))
        .output()?;

    assert!(api_output.status.success());
    assert_eq!(String::from_utf8(api_output.stdout)?, test_content);

    Ok(())
}

/// Given: A source file and destination file
/// When: safe_compress_gzip is called followed by safe_read on source
/// Then: safe_read returns the full original content (proving source was rewound)
#[test]
fn test_safe_compress_gzip_rewinds_source_for_subsequent_read() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let test_content = "Content to verify rewind after compression\n";
    let source_file = temp_dir.child("source.txt");
    source_file.write_str(test_content)?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let source_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "source.txt",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let dest_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "source.txt.gz",
        OpenFileOptionsBuilder::default()
            .read(true)
            .create(true)
            .build()
            .unwrap(),
    )?;

    let options = CompressGzipOptionsBuilder::default().build().unwrap();

    source_handle.safe_compress_gzip(&DEFAULT_TEST_CEDAR_AUTH, dest_handle.clone(), options)?;

    // Verify source file was rewound: safe_read should return full content from beginning
    let source_content = source_handle.safe_read(&DEFAULT_TEST_CEDAR_AUTH)?;
    assert_eq!(
        source_content, test_content,
        "Source file should be rewound after compress, allowing full content to be read again"
    );

    Ok(())
}

/// Given: A gzipped file with known content
/// When: safe_read_gzip_lines is called with count(3)
/// Then: The first 3 decompressed lines are returned
#[test]
fn test_safe_read_gzip_lines_head() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let test_content = "line1\nline2\nline3\nline4\nline5\n";
    let source_file = temp_dir.child("source.txt");
    source_file.write_str(test_content)?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);

    // Compress using our own API
    let source_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "source.txt",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let dest_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "source.txt.gz",
        OpenFileOptionsBuilder::default()
            .read(true)
            .create(true)
            .build()
            .unwrap(),
    )?;

    let compress_opts = CompressGzipOptionsBuilder::default().build().unwrap();
    source_handle.safe_compress_gzip(
        &DEFAULT_TEST_CEDAR_AUTH,
        dest_handle.clone(),
        compress_opts,
    )?;

    let options = rust_safe_io::options::ReadLinesOptionsBuilder::default()
        .count(3)
        .build()
        .unwrap();

    let lines = dest_handle.safe_read_gzip_lines(&DEFAULT_TEST_CEDAR_AUTH, options)?;

    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0], "line1");
    assert_eq!(lines[1], "line2");
    assert_eq!(lines[2], "line3");

    Ok(())
}

/// Given: A gzipped file with known content
/// When: safe_read_gzip_lines is called with count(-3)
/// Then: The last 3 decompressed lines are returned
#[test]
fn test_safe_read_gzip_lines_tail() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let test_content = "line1\nline2\nline3\nline4\nline5";
    let source_file = temp_dir.child("source.txt");
    source_file.write_str(test_content)?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);

    // Compress using our own API
    let source_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "source.txt",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let dest_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "source.txt.gz",
        OpenFileOptionsBuilder::default()
            .read(true)
            .create(true)
            .build()
            .unwrap(),
    )?;

    let compress_opts = CompressGzipOptionsBuilder::default().build().unwrap();
    source_handle.safe_compress_gzip(
        &DEFAULT_TEST_CEDAR_AUTH,
        dest_handle.clone(),
        compress_opts,
    )?;

    let options = rust_safe_io::options::ReadLinesOptionsBuilder::default()
        .count(-3)
        .build()
        .unwrap();

    let lines = dest_handle.safe_read_gzip_lines(&DEFAULT_TEST_CEDAR_AUTH, options)?;

    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0], "line3");
    assert_eq!(lines[1], "line4");
    assert_eq!(lines[2], "line5");

    Ok(())
}

/// Given: A gzipped file
/// When: safe_gzip_info is called
/// Then: The compressed and uncompressed sizes are returned correctly and match `gzip -l` output
#[test]
fn test_safe_gzip_info_success() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let test_content = "Hello, this is test content for gzip info!\n".repeat(100);
    let source_file = temp_dir.child("source.txt");
    source_file.write_str(&test_content)?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);

    // Compress using our own API
    let source_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "source.txt",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let dest_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "source.txt.gz",
        OpenFileOptionsBuilder::default()
            .read(true)
            .create(true)
            .build()
            .unwrap(),
    )?;

    let compress_opts = CompressGzipOptionsBuilder::default().build().unwrap();
    source_handle.safe_compress_gzip(
        &DEFAULT_TEST_CEDAR_AUTH,
        dest_handle.clone(),
        compress_opts,
    )?;

    let info = dest_handle.safe_gzip_info(&DEFAULT_TEST_CEDAR_AUTH)?;

    // Uncompressed size should match the original content length
    let expected_uncompressed = test_content.len() as u64;
    assert_eq!(*info.uncompressed_size_bytes(), expected_uncompressed);
    // Compressed size should be less than uncompressed
    assert!(*info.compressed_size_bytes() < expected_uncompressed);
    // Ratio should be > 1 for compressible content
    assert!(*info.compression_ratio() > 1.0);

    // Verify our compression ratio matches `gzip -l` output
    let gz_path = temp_dir.path().join("source.txt.gz");
    let gzip_l_output = Command::new("gzip").arg("-l").arg(&gz_path).output()?;
    assert!(
        gzip_l_output.status.success(),
        "gzip -l failed: {}",
        String::from_utf8_lossy(&gzip_l_output.stderr)
    );

    // Parse gzip -l output:
    // "         compressed        uncompressed  ratio uncompressed_name"
    // "                 31                   3 -66.7% foo.txt"
    let output_str = String::from_utf8(gzip_l_output.stdout)?;
    let lines: Vec<&str> = output_str.lines().collect();
    assert!(
        lines.len() >= 2,
        "Expected at least 2 lines from gzip -l, got: {}",
        output_str
    );

    let data_line = lines[1];
    let parts: Vec<&str> = data_line.split_whitespace().collect();
    assert!(
        parts.len() >= 3,
        "Expected at least 3 parts in gzip -l data line, got: {:?}",
        parts
    );

    let gzip_compressed: u64 = parts[0].parse()?;
    let gzip_uncompressed: u64 = parts[1].parse()?;

    // Verify sizes match exactly
    assert_eq!(
        *info.compressed_size_bytes(),
        gzip_compressed,
        "Compressed size mismatch: API={} vs gzip -l={}",
        info.compressed_size_bytes(),
        gzip_compressed
    );
    assert_eq!(
        *info.uncompressed_size_bytes(),
        gzip_uncompressed,
        "Uncompressed size mismatch: API={} vs gzip -l={}",
        info.uncompressed_size_bytes(),
        gzip_uncompressed
    );

    // Compute expected ratio directly from sizes (avoids rounding error from gzip's display)
    // Our ratio is uncompressed/compressed
    let expected_our_ratio = gzip_uncompressed as f64 / gzip_compressed as f64;
    let ratio_diff = (*info.compression_ratio() - expected_our_ratio).abs();
    assert!(
        ratio_diff < 0.001,
        "Compression ratio mismatch: API={:.6} vs expected={:.6}",
        info.compression_ratio(),
        expected_our_ratio
    );

    Ok(())
}

/// Given: A gzipped file with known content (compressed by system gzip)
/// When: safe_search_gzip is called with a pattern
/// Then: Matching lines are returned with line numbers
#[test]
fn test_safe_search_gzip_basic() -> Result<()> {
    let test_content = "line1 ERROR happened\nline2 info message\nline3 ERROR again\nline4 debug\n";
    let (_temp_dir, _gz_path, gzip_handle) = setup_gzip_test_with_system(test_content)?;

    let options = SearchGzipOptionsBuilder::default().build().unwrap();
    let matches = gzip_handle.safe_search_gzip(&DEFAULT_TEST_CEDAR_AUTH, "ERROR", options)?;

    assert_eq!(matches.len(), 2);
    assert_eq!(*matches[0].line_number(), 1);
    assert!(matches[0].line_content().contains("ERROR happened"));
    assert_eq!(*matches[1].line_number(), 3);
    assert!(matches[1].line_content().contains("ERROR again"));

    Ok(())
}

/// Given: A gzipped file with known content (compressed by system gzip)
/// When: safe_search_gzip is called with exclude_pattern
/// Then: Lines matching exclude pattern are filtered out
#[test]
fn test_safe_search_gzip_with_exclude() -> Result<()> {
    let test_content = "ERROR in production\nERROR in debug mode\nERROR critical\n";
    let (_temp_dir, _gz_path, gzip_handle) = setup_gzip_test_with_system(test_content)?;

    let options = SearchGzipOptionsBuilder::default()
        .exclude_pattern("debug".to_string())
        .build()
        .unwrap();
    let matches = gzip_handle.safe_search_gzip(&DEFAULT_TEST_CEDAR_AUTH, "ERROR", options)?;

    assert_eq!(matches.len(), 2);
    assert!(matches[0].line_content().contains("production"));
    assert!(matches[1].line_content().contains("critical"));

    Ok(())
}

/// Given: A gzipped file with known content (compressed by system gzip)
/// When: safe_search_gzip is called with case_insensitive
/// Then: Case-insensitive matching is applied
#[test]
fn test_safe_search_gzip_case_insensitive() -> Result<()> {
    let test_content = "ERROR message\nerror message\nError Message\n";
    let (_temp_dir, _gz_path, gzip_handle) = setup_gzip_test_with_system(test_content)?;

    let options = SearchGzipOptionsBuilder::default()
        .case_insensitive(true)
        .build()
        .unwrap();
    let matches = gzip_handle.safe_search_gzip(&DEFAULT_TEST_CEDAR_AUTH, "error", options)?;

    assert_eq!(matches.len(), 3);

    Ok(())
}

/// Given: A gzipped file with many matches (compressed by system gzip)
/// When: safe_search_gzip is called with positive max_results (head)
/// Then: Only first N matches are returned
#[test]
fn test_safe_search_gzip_max_results_head() -> Result<()> {
    let test_content = "match1\nmatch2\nmatch3\nmatch4\nmatch5\n";
    let (_temp_dir, _gz_path, gzip_handle) = setup_gzip_test_with_system(test_content)?;

    let options = SearchGzipOptionsBuilder::default()
        .max_results(2)
        .build()
        .unwrap();
    let matches = gzip_handle.safe_search_gzip(&DEFAULT_TEST_CEDAR_AUTH, "match", options)?;

    assert_eq!(matches.len(), 2);
    assert!(matches[0].line_content().contains("match1"));
    assert!(matches[1].line_content().contains("match2"));

    Ok(())
}

/// Given: A gzipped file with many matches (compressed by system gzip)
/// When: safe_search_gzip is called with negative max_results (tail)
/// Then: Only last N matches are returned
#[test]
fn test_safe_search_gzip_max_results_tail() -> Result<()> {
    let test_content = "match1\nmatch2\nmatch3\nmatch4\nmatch5";
    let (_temp_dir, _gz_path, gzip_handle) = setup_gzip_test_with_system(test_content)?;

    let options = SearchGzipOptionsBuilder::default()
        .max_results(-2)
        .build()
        .unwrap();
    let matches = gzip_handle.safe_search_gzip(&DEFAULT_TEST_CEDAR_AUTH, "match", options)?;

    assert_eq!(matches.len(), 2);
    assert!(matches[0].line_content().contains("match4"));
    assert!(matches[1].line_content().contains("match5"));

    Ok(())
}

/// Given: A gzipped file with known content (compressed by system gzip)
/// When: safe_search_gzip_exists is called with matching pattern
/// Then: true is returned
#[test]
fn test_safe_search_gzip_exists_found() -> Result<()> {
    let test_content = "info message\nERROR critical\nwarning message\n";
    let (_temp_dir, _gz_path, gzip_handle) = setup_gzip_test_with_system(test_content)?;

    let options = SearchGzipOptionsBuilder::default().build().unwrap();
    let exists = gzip_handle.safe_search_gzip_exists(&DEFAULT_TEST_CEDAR_AUTH, "ERROR", options)?;

    assert!(exists);

    Ok(())
}

/// Given: A gzipped file with known content (compressed by system gzip)
/// When: safe_search_gzip_exists is called with non-matching pattern
/// Then: false is returned
#[test]
fn test_safe_search_gzip_exists_not_found() -> Result<()> {
    let test_content = "info message\nwarning message\n";
    let (_temp_dir, _gz_path, gzip_handle) = setup_gzip_test_with_system(test_content)?;

    let options = SearchGzipOptionsBuilder::default().build().unwrap();
    let exists =
        gzip_handle.safe_search_gzip_exists(&DEFAULT_TEST_CEDAR_AUTH, "CRITICAL", options)?;

    assert!(!exists);

    Ok(())
}

/// Given: A truncated gzip file with matching lines before the truncation point
/// When: safe_search_gzip is called
/// Then: Partial results found before the error are returned (matches zgrep behavior)
#[test]
fn test_safe_search_gzip_truncated_returns_partial_results() -> Result<()> {
    let test_content = "line1 ERROR happened\nline2 info message\nline3 ERROR again\nline4 debug\n";
    let (temp_dir, gz_path, _) = setup_gzip_test_with_system(test_content)?;

    // Truncate the gzip file to simulate incomplete write
    let gz_data = std::fs::read(&gz_path)?;
    std::fs::write(&gz_path, &gz_data[..gz_data.len() - 5])?;

    let temp_dir_path = temp_dir.path().to_path_buf().to_string_lossy().to_string();
    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let gzip_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "source.txt.gz",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let options = SearchGzipOptionsBuilder::default().build().unwrap();
    let matches = gzip_handle.safe_search_gzip(&DEFAULT_TEST_CEDAR_AUTH, "ERROR", options)?;

    assert!(
        !matches.is_empty(),
        "Should return partial results from truncated gzip"
    );

    Ok(())
}

/// Given: A gzipped file (compressed by system gzip)
/// When: safe_search_gzip is called with invalid regex pattern
/// Then: Validation error is returned
#[test]
fn test_safe_search_gzip_invalid_pattern() -> Result<()> {
    let test_content = "test content\n";
    let (_temp_dir, _gz_path, gzip_handle) = setup_gzip_test_with_system(test_content)?;

    let options = SearchGzipOptionsBuilder::default().build().unwrap();
    let result = gzip_handle.safe_search_gzip(&DEFAULT_TEST_CEDAR_AUTH, "[invalid(", options);

    assert_error_contains(result, INVALID_REGEX_PATTERN_ERR);

    Ok(())
}

/// Given: A gzipped file with known content
/// When: safe_read_gzip_lines is called with start(3)
/// Then: Lines from line 3 to end are returned
#[test]
fn test_safe_read_gzip_lines_start_only() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let test_content = "line1\nline2\nline3\nline4\nline5";
    let source_file = temp_dir.child("source.txt");
    source_file.write_str(test_content)?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let source_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "source.txt",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let dest_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "source.txt.gz",
        OpenFileOptionsBuilder::default()
            .read(true)
            .create(true)
            .build()
            .unwrap(),
    )?;

    let compress_opts = CompressGzipOptionsBuilder::default().build().unwrap();
    source_handle.safe_compress_gzip(
        &DEFAULT_TEST_CEDAR_AUTH,
        dest_handle.clone(),
        compress_opts,
    )?;

    let options = rust_safe_io::options::ReadLinesOptionsBuilder::default()
        .start(3)
        .build()
        .unwrap();

    let lines = dest_handle.safe_read_gzip_lines(&DEFAULT_TEST_CEDAR_AUTH, options)?;

    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0], "line3");
    assert_eq!(lines[1], "line4");
    assert_eq!(lines[2], "line5");

    Ok(())
}

/// Given: A gzipped file with known content
/// When: safe_read_gzip_lines is called with start(2) and count(2)
/// Then: 2 lines starting from line 2 are returned
#[test]
fn test_safe_read_gzip_lines_start_with_head() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let test_content = "line1\nline2\nline3\nline4\nline5";
    let source_file = temp_dir.child("source.txt");
    source_file.write_str(test_content)?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let source_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "source.txt",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let dest_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "source.txt.gz",
        OpenFileOptionsBuilder::default()
            .read(true)
            .create(true)
            .build()
            .unwrap(),
    )?;

    let compress_opts = CompressGzipOptionsBuilder::default().build().unwrap();
    source_handle.safe_compress_gzip(
        &DEFAULT_TEST_CEDAR_AUTH,
        dest_handle.clone(),
        compress_opts,
    )?;

    let options = rust_safe_io::options::ReadLinesOptionsBuilder::default()
        .start(2)
        .count(2)
        .build()
        .unwrap();

    let lines = dest_handle.safe_read_gzip_lines(&DEFAULT_TEST_CEDAR_AUTH, options)?;

    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0], "line2");
    assert_eq!(lines[1], "line3");

    Ok(())
}

/// Given: A gzipped file with known content
/// When: safe_read_gzip_lines is called with start(4) and count(-2)
/// Then: Last 2 lines of lines 1-4 are returned (i.e., lines 3 and 4)
#[test]
fn test_safe_read_gzip_lines_start_with_tail() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let test_content = "line1\nline2\nline3\nline4\nline5";
    let source_file = temp_dir.child("source.txt");
    source_file.write_str(test_content)?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let source_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "source.txt",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let dest_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "source.txt.gz",
        OpenFileOptionsBuilder::default()
            .read(true)
            .create(true)
            .build()
            .unwrap(),
    )?;

    let compress_opts = CompressGzipOptionsBuilder::default().build().unwrap();
    source_handle.safe_compress_gzip(
        &DEFAULT_TEST_CEDAR_AUTH,
        dest_handle.clone(),
        compress_opts,
    )?;

    let options = rust_safe_io::options::ReadLinesOptionsBuilder::default()
        .start(4)
        .count(-2)
        .build()
        .unwrap();

    let lines = dest_handle.safe_read_gzip_lines(&DEFAULT_TEST_CEDAR_AUTH, options)?;

    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0], "line3");
    assert_eq!(lines[1], "line4");

    Ok(())
}

/// Given: A gzipped file with 5 lines
/// When: safe_read_gzip_lines is called with count(100)
/// Then: All 5 lines are returned (no error for exceeding count)
#[test]
fn test_safe_read_gzip_lines_count_exceeds_file() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let test_content = "line1\nline2\nline3\nline4\nline5";
    let source_file = temp_dir.child("source.txt");
    source_file.write_str(test_content)?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let source_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "source.txt",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let dest_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "source.txt.gz",
        OpenFileOptionsBuilder::default()
            .read(true)
            .create(true)
            .build()
            .unwrap(),
    )?;

    let compress_opts = CompressGzipOptionsBuilder::default().build().unwrap();
    source_handle.safe_compress_gzip(
        &DEFAULT_TEST_CEDAR_AUTH,
        dest_handle.clone(),
        compress_opts,
    )?;

    let options = rust_safe_io::options::ReadLinesOptionsBuilder::default()
        .count(100)
        .build()
        .unwrap();

    let lines = dest_handle.safe_read_gzip_lines(&DEFAULT_TEST_CEDAR_AUTH, options)?;

    assert_eq!(lines.len(), 5);
    assert_eq!(lines[0], "line1");
    assert_eq!(lines[4], "line5");

    Ok(())
}

/// Given: An empty gzipped file
/// When: safe_read_gzip_lines is called with count(10)
/// Then: Empty vector is returned
#[test]
fn test_safe_read_gzip_lines_empty_file() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let source_file = temp_dir.child("empty.txt");
    source_file.write_str("")?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let source_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "empty.txt",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let dest_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "empty.txt.gz",
        OpenFileOptionsBuilder::default()
            .read(true)
            .create(true)
            .build()
            .unwrap(),
    )?;

    let compress_opts = CompressGzipOptionsBuilder::default().build().unwrap();
    source_handle.safe_compress_gzip(
        &DEFAULT_TEST_CEDAR_AUTH,
        dest_handle.clone(),
        compress_opts,
    )?;

    let options = rust_safe_io::options::ReadLinesOptionsBuilder::default()
        .count(10)
        .build()
        .unwrap();

    let lines = dest_handle.safe_read_gzip_lines(&DEFAULT_TEST_CEDAR_AUTH, options)?;

    assert!(lines.is_empty());

    Ok(())
}

/// Given: An empty file
/// When: safe_compress_gzip is called
/// Then: The file is compressed successfully (empty gzip is valid)
#[test]
fn test_safe_compress_gzip_empty_file() -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let source_file = temp_dir.child("empty.txt");
    source_file.write_str("")?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);

    let source_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "empty.txt",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let dest_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "empty.gz",
        OpenFileOptionsBuilder::default()
            .create(true)
            .build()
            .unwrap(),
    )?;

    let options = CompressGzipOptionsBuilder::default().build().unwrap();

    let result = source_handle.safe_compress_gzip(&DEFAULT_TEST_CEDAR_AUTH, dest_handle, options);

    assert!(result.is_ok());

    // Verify with gunzip
    let gz_path = temp_dir.path().join("empty.gz");
    let output = Command::new("gunzip").arg("-c").arg(&gz_path).output()?;

    assert!(output.status.success());
    assert!(output.stdout.is_empty());

    Ok(())
}

/// Given: A gzipped file and an unauthorized user for reading
/// When: Various gzip read operations are called
/// Then: Access is denied for read permission
#[rstest]
#[case("safe_read_gzip_lines")]
#[case("safe_search_gzip")]
#[case("safe_search_gzip_exists")]
#[case("safe_gzip_info")]
fn test_unauthorized_gzip_read_operations(#[case] method: &str) -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    // Create and compress a file using system gzip
    create_gzip_with_system_command(&temp_dir, "source.txt", "test content\n")?;

    let principal = get_test_rex_principal();
    let gz_path = format!("{}/source.txt.gz", temp_dir_path);
    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action,
            resource
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource == file_system::File::"{gz_path}"
        );"#,
        FilesystemAction::Read
    );
    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let gzip_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "source.txt.gz",
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Read
    );

    match method {
        "safe_read_gzip_lines" => {
            let options = rust_safe_io::options::ReadLinesOptionsBuilder::default()
                .count(10)
                .build()
                .unwrap();
            let result = gzip_handle.safe_read_gzip_lines(&test_cedar_auth, options);
            assert_error_contains(result, &expected_error);
        }
        "safe_search_gzip" => {
            let options = SearchGzipOptionsBuilder::default().build().unwrap();
            let result = gzip_handle.safe_search_gzip(&test_cedar_auth, "test", options);
            assert_error_contains(result, &expected_error);
        }
        "safe_search_gzip_exists" => {
            let options = SearchGzipOptionsBuilder::default().build().unwrap();
            let result = gzip_handle.safe_search_gzip_exists(&test_cedar_auth, "test", options);
            assert_error_contains(result, &expected_error);
        }
        "safe_gzip_info" => {
            let result = gzip_handle.safe_gzip_info(&test_cedar_auth);
            assert_error_contains(result, &expected_error);
        }
        _ => panic!("Unknown method: {}", method),
    }

    Ok(())
}

/// Given: A gzipped file opened without read permission
/// When: Various gzip read operations are called
/// Then: An error is returned indicating missing read option
#[rstest]
#[case("safe_read_gzip_lines")]
#[case("safe_search_gzip")]
#[case("safe_search_gzip_exists")]
#[case("safe_gzip_info")]
fn test_gzip_read_operations_no_read_option(#[case] method: &str) -> Result<()> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    // Create and compress a file using system gzip
    create_gzip_with_system_command(&temp_dir, "source.txt", "test content\n")?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);

    // Open without read permission (write only)
    let gzip_handle = dir_handle.safe_open_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        "source.txt.gz",
        OpenFileOptionsBuilder::default()
            .write(true)
            .build()
            .unwrap(),
    )?;

    match method {
        "safe_read_gzip_lines" => {
            let options = rust_safe_io::options::ReadLinesOptionsBuilder::default()
                .count(10)
                .build()
                .unwrap();
            let result = gzip_handle.safe_read_gzip_lines(&DEFAULT_TEST_CEDAR_AUTH, options);
            assert_error_contains(result, READ_FILE_FLAG_ERR);
        }
        "safe_search_gzip" => {
            let options = SearchGzipOptionsBuilder::default().build().unwrap();
            let result = gzip_handle.safe_search_gzip(&DEFAULT_TEST_CEDAR_AUTH, "test", options);
            assert_error_contains(result, READ_FILE_FLAG_ERR);
        }
        "safe_search_gzip_exists" => {
            let options = SearchGzipOptionsBuilder::default().build().unwrap();
            let result =
                gzip_handle.safe_search_gzip_exists(&DEFAULT_TEST_CEDAR_AUTH, "test", options);
            assert_error_contains(result, READ_FILE_FLAG_ERR);
        }
        "safe_gzip_info" => {
            let result = gzip_handle.safe_gzip_info(&DEFAULT_TEST_CEDAR_AUTH);
            assert_error_contains(result, READ_FILE_FLAG_ERR);
        }
        _ => panic!("Unknown method: {}", method),
    }

    Ok(())
}
