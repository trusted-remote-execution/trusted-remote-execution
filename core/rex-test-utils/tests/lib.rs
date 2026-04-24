use anyhow::Result;
use assert_fs::TempDir;
#[cfg(target_os = "macos")]
use rex_test_utils::io::create_temp_dir;
use rex_test_utils::io::{
    create_and_write_to_test_file, create_file_with_content, create_new_file_path,
    create_temp_dir_and_path, create_test_file, create_write_return_test_file, read_test_file,
};
use std::fs;
use std::io::Read;
use std::path::Path;

/// Given: A function to create a temporary directory and return its path
/// When: The function is called
/// Then: It should return a valid TempDir and its corresponding path string
#[test]
fn test_create_temp_dir_and_path_success() {
    let result = create_temp_dir_and_path();
    assert!(result.is_ok());

    let (temp_dir, temp_dir_path) = result.unwrap();

    assert!(temp_dir.path().exists());
    assert_eq!(temp_dir_path, temp_dir.path().to_string_lossy().to_string());
    assert!(fs::metadata(temp_dir.path()).unwrap().is_dir());
}

/// Given: A function to create a new file path within a temporary directory
/// When: The function is called with a temporary directory
/// Then: It should return a valid file path and filename within the given directory
#[test]
fn test_create_new_file_path() {
    let temp_dir = TempDir::new().unwrap();
    let (file_path, file_name) = create_new_file_path(&temp_dir);

    assert!(file_path.starts_with(temp_dir.path()));
    assert!(!file_name.is_empty());
    assert_eq!(file_path.file_name().unwrap().to_str().unwrap(), file_name);
}

/// Given: A temporary directory and a test file name
/// When: Creating and writing to a test file
/// Then: The file should exist and contain non-empty content
#[test]
fn test_create_and_write_to_test_file() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let test_file_name = "test.txt";

    let path = create_and_write_to_test_file(&temp_dir, test_file_name)?;
    assert!(Path::new(&path).exists());

    let content = fs::read_to_string(Path::new(&path).join(test_file_name))?;
    assert!(!content.is_empty());

    Ok(())
}

/// Given: An attempt to write a file
/// When: The file is created and written
/// Then: The file is written / created and returned
#[test]
fn test_create_write_return_test_file() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let test_file_name = "test_file.txt";

    let (file_path, content) = create_write_return_test_file(&temp_dir, test_file_name)?;

    let expected_path = temp_dir.path().to_string_lossy().to_string();
    assert_eq!(file_path, expected_path);

    let full_file_path = Path::new(&file_path).join(test_file_name);
    assert!(full_file_path.exists());

    let written_content = fs::read_to_string(full_file_path)?;
    assert_eq!(written_content, content);
    assert!(!content.is_empty());

    Ok(())
}

/// Given: A temporary directory and a test file name
/// When: Creating and writing to a test file
/// Then: The file should exist with correct path and content
#[test]
fn test_create_test_file() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let test_file_name = "test_file.txt";

    let content_string = "Hello World";
    let content = content_string.as_bytes();

    let result = create_test_file(&temp_dir, &test_file_name, &content);
    assert!(result.is_ok());

    let test_file_path = temp_dir.path().join(test_file_name);
    let mut test_file_content = Vec::new();
    std::fs::File::open(test_file_path)?.read_to_end(&mut test_file_content)?;
    assert_eq!(test_file_content, content);

    Ok(())
}

/// Given: A temporary directory and a test file name with specific content
/// When: Creating a file with content using create_file_with_content
/// Then: The file should exist and contain the specified content
#[test]
fn test_create_file_with_content() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let test_file_name = "test.txt";
    let test_content = "Hello, World!";

    let path = create_file_with_content(&temp_dir, test_file_name, test_content)?;

    assert!(Path::new(&path).exists());
    let content = fs::read_to_string(Path::new(&path).join(test_file_name))?;
    assert_eq!(content, test_content);

    Ok(())
}

/// Given: A temporary directory and a test file name
/// When: Reading to a test file
/// Then: The contents of the file are returned
#[test]
fn test_read_test_file() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let test_file_name = "test.txt";
    let test_content = "Hello, World!";

    create_test_file(&temp_dir, test_file_name, test_content.as_bytes())?;

    let content = read_test_file(&temp_dir.join(&test_file_name));

    assert!(content.is_ok());
    assert_eq!(content?, test_content);

    Ok(())
}

/// Given: A function to create a temporary directory on macOS
/// When: The function is called
/// Then: It should return a valid TempDir
#[test]
#[cfg(target_os = "macos")]
fn test_create_temp_dir_on_macos() -> Result<()> {
    let result = create_temp_dir();
    assert!(result.is_ok());

    let temp_dir = result?;
    let temp_dir_path = temp_dir.path().to_string_lossy().to_string();

    assert!(temp_dir.path().exists());
    assert!(fs::metadata(temp_dir.path())?.is_dir());

    // Path should already be canonical (no symlink mismatch)
    let canonical_path = fs::canonicalize(temp_dir.path())?;
    assert_eq!(temp_dir_path, canonical_path.to_string_lossy().to_string());

    Ok(())
}
