use rex_cedar_auth::fs::actions::FilesystemAction;
use rex_cedar_auth::test_utils::{
    DEFAULT_TEST_CEDAR_AUTH, TestCedarAuthBuilder, get_test_rex_principal,
};
use rex_test_utils::assertions::assert_error_contains;
use rex_test_utils::io::{create_temp_dir_and_path, create_test_file};
use rust_safe_io::dir_entry::{EntryType, EntryTypeExt};

use assert_fs::prelude::{PathChild, PathCreateDir};
use rust_safe_io::options::{OpenDirOptionsBuilder, OpenFileOptionsBuilder};
use rust_safe_io::{DirConfigBuilder, RcDirHandle};
#[cfg(target_os = "linux")]
use std::os::linux::fs::MetadataExt as LinuxMetadataExt;
#[cfg(unix)]
use {
    cap_fs_ext::FileTypeExt,
    std::os::unix::{
        fs::{MetadataExt, symlink},
        net::UnixListener,
    },
    std::process::Command,
};

/// Open a dir using the default cedar auth and default open options.
fn open_test_dir_handle(temp_dir_path: &String) -> RcDirHandle {
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

/// Given: a Vec<DirEntry> containing some files and some directories obtained by calling RcDirHandle::safe_list_dir
/// When: the file_type method is called on each DirEntry
/// Then: the file_type is correct depending on whether the entry is a file or a directory
#[test]
fn test_dir_entry_file_type_correctness() -> Result<(), anyhow::Error> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let file_name = "test_file.txt";
    let _ = create_test_file(&temp_dir, file_name, b"test content")?;

    let subdir_name = "test_subdir";
    let subdir = temp_dir.child(subdir_name);
    subdir.create_dir_all()?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let entries = dir_handle.safe_list_dir(&DEFAULT_TEST_CEDAR_AUTH)?;

    assert!(
        entries.len() == 2,
        "Expected 2 entries, got {}",
        entries.len()
    );

    for entry in entries {
        let name = entry.name();
        if name == file_name {
            assert!(
                entry.dir_entry_type().is_file(),
                "Entry {} should be a file",
                name
            );
            assert!(entry.is_file(), "Entry {} should be a file", name);
        } else if name == subdir_name {
            assert!(
                entry.dir_entry_type().is_dir(),
                "Entry {} should be a directory",
                name
            );
            assert!(entry.is_dir(), "Entry {} s should not be a file", name);
        }
    }

    Ok(())
}

/// Given: a Vec<DirEntry> containing some files and some directories obtained by calling RcDirHandle::safe_list_dir
/// When: the inode method is called on each DirEntry
/// Then: the inode matches the actual inode number
#[test]
#[cfg(target_os = "linux")]
fn test_dir_entry_inode_correctness() -> Result<(), anyhow::Error> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let file_name = "test_file.txt";
    create_test_file(&temp_dir, file_name, b"test content")?;
    let file_path = temp_dir_path.clone() + "/" + file_name;

    let subdir_name = "test_subdir";
    let subdir = temp_dir.child(subdir_name);
    subdir.create_dir_all()?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let entries = dir_handle.safe_list_dir(&DEFAULT_TEST_CEDAR_AUTH)?;

    let file_metadata = std::fs::metadata(&file_path)?;
    let file_inode = file_metadata.ino();
    let mtime = file_metadata.mtime();
    let mtime_nsec = file_metadata.mtime_nsec();
    let ctime = file_metadata.ctime();
    let blocks = file_metadata.blocks();
    let allocated_size = blocks * 512;
    let file_size = file_metadata.size();

    let subdir_path = temp_dir.path().join(subdir_name);
    let subdir_metadata = std::fs::metadata(&subdir_path)?;
    let subdir_inode = subdir_metadata.ino();
    #[cfg(target_os = "linux")]
    let expected_hardlinks: u64 = std::fs::metadata(&file_path).unwrap().st_nlink();

    for mut entry in entries {
        let metadata = entry.metadata(&DEFAULT_TEST_CEDAR_AUTH).unwrap();
        let name = entry.name();
        if name == file_name {
            assert_eq!(
                *entry.inode(),
                file_inode,
                "File inode mismatch for {}",
                name
            );
            assert_eq!(
                metadata.file_size()?,
                file_size as i64,
                "File size mismatch for {}",
                name
            );
            #[cfg(target_os = "linux")]
            assert_eq!(
                metadata.num_hardlinks().unwrap(),
                expected_hardlinks as i64,
                "expected hardlinks mismatch for {}",
                name
            );
            assert_eq!(
                metadata.mtime(),
                mtime as i64,
                "File mtime mismatch for {}",
                name
            );
            assert_eq!(
                metadata.mtime_nsec(),
                mtime_nsec as i64,
                "File mtime_nsec mismatch for {}",
                name
            );
            assert_eq!(
                metadata.ctime(),
                ctime as i64,
                "File ctime mismatch for {}",
                name
            );
            assert_eq!(
                metadata.blocks()?,
                blocks as i64,
                "File blocks mismatch for {}",
                name
            );
            assert_eq!(
                metadata.allocated_size()?,
                allocated_size as i64,
                "File block size mismatch for {}",
                name
            );
        } else if name == subdir_name {
            assert_eq!(
                *entry.inode(),
                subdir_inode,
                "Directory inode mismatch for {}",
                name
            );
        }
    }

    Ok(())
}

/// Given: a Vec<DirEntry> containing some files and some directories obtained by calling RcDirHandle::safe_list_dir
/// When: the name method is called on each DirEntry
/// Then: the name equals the actual directory or file name
#[test]
fn test_dir_entry_name_correctness() -> Result<(), anyhow::Error> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let file_names = vec!["file1.txt", "file2.log", "test.data"];
    for file_name in &file_names {
        let _ = create_test_file(&temp_dir, file_name, b"test content")?;
    }

    let dir_names = vec!["dir1", "dir2", "test_dir"];
    for dir_name in &dir_names {
        let subdir = temp_dir.child(dir_name);
        subdir.create_dir_all()?;
    }

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let entries = dir_handle.safe_list_dir(&DEFAULT_TEST_CEDAR_AUTH)?;

    let mut found_names = Vec::new();
    for entry in entries {
        let name = entry.name();
        found_names.push(name.clone());

        let expected_names = [&file_names[..], &dir_names[..]].concat();
        assert!(
            expected_names.contains(&name.as_str()),
            "Unexpected entry name: {}",
            name
        );
    }

    for expected_name in file_names.iter().chain(dir_names.iter()) {
        assert!(
            found_names.contains(&expected_name.to_string()),
            "Expected entry name not found: {}",
            expected_name
        );
    }

    Ok(())
}

/// Given: a DirEntry corresponding to a directory obtained by calling RcDirHandle::safe_list_dir
/// When: the open_as_dir method is called twice on the DirEntry
/// Then: the same RcDirHandle is returned both times
#[test]
fn test_dir_entry_open_as_dir_memoization() -> Result<(), anyhow::Error> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let subdir_name = "test_subdir";
    let subdir = temp_dir.child(subdir_name);
    subdir.create_dir_all()?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let mut entries = dir_handle.safe_list_dir(&DEFAULT_TEST_CEDAR_AUTH)?;
    let dir_entry = entries.get_mut(0).unwrap();

    let dir_handle1 = dir_entry.open_as_dir(
        &DEFAULT_TEST_CEDAR_AUTH,
        OpenDirOptionsBuilder::default().build().unwrap(),
    )?;

    let dir_handle2 = dir_entry.open_as_dir(
        &DEFAULT_TEST_CEDAR_AUTH,
        OpenDirOptionsBuilder::default().build().unwrap(),
    )?;

    assert_eq!(
        &dir_handle1, &dir_handle2,
        "Directory handles should be the same instance"
    );

    Ok(())
}

/// Given: a DirEntry corresponding to a file obtained by calling RcDirHandle::safe_list_dir
/// When: the open_as_file method is called twice on the DirEntry
/// Then: the same RcFileHandle is returned both times
#[test]
fn test_dir_entry_open_as_file_memoization() -> Result<(), anyhow::Error> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let file_name = "test_file.txt";
    let _ = create_test_file(&temp_dir, file_name, b"test content")?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let mut entries = dir_handle.safe_list_dir(&DEFAULT_TEST_CEDAR_AUTH)?;
    let file_entry = entries.get_mut(0).unwrap();

    let file_handle1 = file_entry.open_as_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let file_handle2 = file_entry.open_as_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    assert_eq!(
        &file_handle1, &file_handle2,
        "File handles should be the same instance"
    );

    Ok(())
}

/// Given: a DirEntry obtained by calling RcDirHandle::safe_list_dir and a user unauthorized for stat
/// When: the metadata method is called on the DirEntry
/// Then: an authorization error is returned
#[test]
fn test_unauthorized_dir_entry_metadata() -> Result<(), anyhow::Error> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let file_name = "test_file.txt";
    let _ = create_test_file(&temp_dir, file_name, b"test content")?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let mut entries = dir_handle.safe_list_dir(&DEFAULT_TEST_CEDAR_AUTH)?;
    let entry = entries.get_mut(0).unwrap();

    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action == {},
            resource
        );
        
        forbid(
            principal == User::"{principal}",
            action == {},
            resource
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Stat
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()
        .unwrap()
        .create();

    let result = entry.metadata(&test_cedar_auth);
    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Stat
    );
    assert_error_contains(result, &expected_error);

    Ok(())
}

/// Given: a DirEntry corresponding to a directory obtained by calling RcDirHandle::safe_list_dir and a user authorized for stat
/// When: the metadata method is called on the DirEntry
/// Then: the ownership in the returned metadata is the same as calling ownership on the RcDirHandle itself
#[test]
#[cfg(unix)] // ownership is a Unix-specific concept
fn test_dir_entry_dir_metadata_ownership() -> Result<(), anyhow::Error> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let subdir_name = "test_subdir";
    let subdir = temp_dir.child(subdir_name);
    subdir.create_dir_all()?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let mut entries = dir_handle.safe_list_dir(&DEFAULT_TEST_CEDAR_AUTH)?;
    let dir_entry = entries.get_mut(0).unwrap();

    let subdir_handle = dir_entry.open_as_dir(
        &DEFAULT_TEST_CEDAR_AUTH,
        OpenDirOptionsBuilder::default().build().unwrap(),
    )?;

    let entry_metadata = dir_entry.metadata(&DEFAULT_TEST_CEDAR_AUTH)?;
    let entry_ownership = entry_metadata.ownership();

    let dir_ownership = subdir_handle.safe_get_ownership(&DEFAULT_TEST_CEDAR_AUTH)?;

    assert_eq!(
        entry_ownership.user(),
        dir_ownership.user(),
        "User ownership mismatch between DirEntry metadata and RcDirHandle"
    );
    assert_eq!(
        entry_ownership.group(),
        dir_ownership.group(),
        "Group ownership mismatch between DirEntry metadata and RcDirHandle"
    );

    Ok(())
}

/// Given: a DirEntry corresponding to a file obtained by calling RcDirHandle::safe_list_dir and a user authorized for stat
/// When: the metadata method is called on the DirEntry
/// Then: the ownership in the returned metadata is the same as calling ownership on the RcFileHandle itself
#[test]
#[cfg(unix)] // ownership is a Unix-specific concept
fn test_dir_entry_file_metadata_ownership() -> Result<(), anyhow::Error> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let file_name = "test_file.txt";
    let _ = create_test_file(&temp_dir, file_name, b"test content")?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let mut entries = dir_handle.safe_list_dir(&DEFAULT_TEST_CEDAR_AUTH)?;
    let file_entry = entries.get_mut(0).unwrap();

    let file_handle = file_entry.open_as_file(
        &DEFAULT_TEST_CEDAR_AUTH,
        OpenFileOptionsBuilder::default()
            .read(true)
            .build()
            .unwrap(),
    )?;

    let entry_metadata = file_entry.metadata(&DEFAULT_TEST_CEDAR_AUTH)?;
    let entry_ownership = entry_metadata.ownership();

    let file_ownership = file_handle.safe_get_ownership(&DEFAULT_TEST_CEDAR_AUTH)?;

    assert_eq!(
        entry_ownership.user(),
        file_ownership.user(),
        "User ownership mismatch between DirEntry metadata and RcFileHandle"
    );
    assert_eq!(
        entry_ownership.group(),
        file_ownership.group(),
        "Group ownership mismatch between DirEntry metadata and RcFileHandle"
    );

    Ok(())
}

/// Given: a DirEntry corresponding to a symlink and an authorized user
/// When: we open as symlink and get metadata
/// Then: the metadata is returned, ownership matches, and memoization works
#[test]
#[cfg(target_os = "linux")]
fn test_dir_entry_symlink_open_and_metadata() -> Result<(), anyhow::Error> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let target_file_name = "target_file.txt";
    let _ = create_test_file(&temp_dir, target_file_name, b"target content")?;
    let target_path = temp_dir.path().join(target_file_name);

    let symlink_name = "test_symlink";
    let symlink_path = temp_dir.path().join(symlink_name);
    symlink(&target_path, &symlink_path)?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let entries = dir_handle.safe_list_dir(&DEFAULT_TEST_CEDAR_AUTH)?;

    let mut symlink_entry = entries
        .into_iter()
        .find(|e| e.name() == symlink_name)
        .expect("Symlink entry not found");

    assert!(symlink_entry.dir_entry_type().is_symlink());
    assert_eq!(symlink_entry.entry_type(), EntryType::Symlink);

    let symlink_handle1 = symlink_entry.open_as_symlink(&DEFAULT_TEST_CEDAR_AUTH)?;
    let symlink_handle2 = symlink_entry.open_as_symlink(&DEFAULT_TEST_CEDAR_AUTH)?;
    assert_eq!(
        &symlink_handle1, &symlink_handle2,
        "Symlink handles should be memoized"
    );

    let entry_metadata = symlink_entry.metadata(&DEFAULT_TEST_CEDAR_AUTH)?;
    assert!(entry_metadata.cap_std_metadata().is_symlink());

    let symlink_target = entry_metadata.symlink_target();
    assert!(
        symlink_target.is_some(),
        "symlink_target() should not be None for a symlink DirEntry"
    );
    assert_eq!(
        symlink_target,
        Some(target_path.to_string_lossy().to_string()),
        "symlink_target() should match the actual target path"
    );

    Ok(())
}

/// Given: a DirEntry corresponding to a symlink and an unauthorized user
/// When: we get the metadata of the DirEntry
/// Then: an authorization error is returned
#[test]
#[cfg(target_os = "linux")]
fn test_dir_entry_symlink_metadata_unauthorized() -> Result<(), anyhow::Error> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let target_file_name = "target_file.txt";
    let _ = create_test_file(&temp_dir, target_file_name, b"target content")?;
    let target_path = temp_dir.path().join(target_file_name);

    let symlink_name = "test_symlink";
    let symlink_path = temp_dir.path().join(symlink_name);
    symlink(&target_path, &symlink_path)?;

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let entries = dir_handle.safe_list_dir(&DEFAULT_TEST_CEDAR_AUTH)?;

    let mut symlink_entry = None;
    for entry in entries {
        if entry.name() == symlink_name {
            symlink_entry = Some(entry);
            break;
        }
    }

    let mut symlink_entry = symlink_entry.unwrap();
    assert!(
        symlink_entry.dir_entry_type().is_symlink(),
        "Entry should be a symlink"
    );

    let principal = get_test_rex_principal();
    let test_policy = format!(
        r#"permit(
            principal == User::"{principal}",
            action == {},
            resource
        );
        forbid(
            principal == User::"{principal}",
            action == {},
            resource
        );"#,
        FilesystemAction::Open,
        FilesystemAction::Stat
    );

    let test_cedar_auth = TestCedarAuthBuilder::default()
        .policy(test_policy)
        .build()?
        .create();

    let result = symlink_entry.metadata(&test_cedar_auth);
    let expected_error = format!(
        "Permission denied: {principal} unauthorized to perform {}",
        FilesystemAction::Stat
    );
    assert_error_contains(result, &expected_error);

    Ok(())
}

/// Given: a DirEntry corresponding to a FIFO
/// When: we get the metadata of the DirEntry
/// Then: the metadata is returned
#[test]
#[cfg(unix)] // FIFOs are a Unix-specific concept
fn test_dir_entry_fifo_metadata() -> Result<(), anyhow::Error> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let fifo_name = "test_fifo";
    let fifo_path = temp_dir.path().join(fifo_name);

    Command::new("mkfifo")
        .arg(&fifo_path)
        .status()
        .expect("Failed to create FIFO");

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let entries = dir_handle.safe_list_dir(&DEFAULT_TEST_CEDAR_AUTH)?;

    let mut fifo_entry = None;
    for entry in entries {
        if entry.name() == fifo_name {
            fifo_entry = Some(entry);
            break;
        }
    }

    let mut fifo_entry = fifo_entry.unwrap();
    assert_eq!(fifo_entry.entry_type(), EntryType::Ext(EntryTypeExt::Fifo));
    let metadata = fifo_entry.metadata(&DEFAULT_TEST_CEDAR_AUTH)?;
    assert!(
        metadata.cap_std_metadata().file_type().is_fifo(),
        "Metadata should indicate a FIFO"
    );

    Ok(())
}

/// Given: a DirEntry corresponding to a socket
/// When: we get the metadata of the DirEntry
/// Then: the metadata is returned
#[test]
#[cfg(unix)] // sockets are on unix
fn test_dir_entry_socket_metadata() -> Result<(), anyhow::Error> {
    let (temp_dir, temp_dir_path) = create_temp_dir_and_path()?;

    let socket_name = "test_socket";
    let socket_path = temp_dir.path().join(socket_name);

    let _listener = UnixListener::bind(&socket_path).unwrap();

    let dir_handle = open_test_dir_handle(&temp_dir_path);
    let entries = dir_handle.safe_list_dir(&DEFAULT_TEST_CEDAR_AUTH)?;

    let mut socket_metadata = None;
    for mut entry in entries {
        if entry.name() == socket_name {
            socket_metadata = Some(entry.metadata(&DEFAULT_TEST_CEDAR_AUTH).unwrap());
            break;
        }
    }

    assert_eq!(
        socket_metadata.unwrap().entry_type(),
        EntryType::Ext(EntryTypeExt::Socket)
    );

    Ok(())
}
