use anyhow::Result;
use rex_cedar_auth::cedar_auth::CedarAuth;
use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
use rex_test_utils::io::create_temp_dir_and_path;
use rust_safe_io::DirConfigBuilder;
use rust_safe_io::options::{OpenDirOptionsBuilder, OpenFileOptionsBuilder};
use std::fs;
use std::io::Write;

/// Given: A valid ELF core dump file
/// When: The elf_info method is called
/// Then: It successfully extracts ELF information including execfn and platform
#[test]
fn test_elf_info_core_dump() -> Result<()> {
    let (cedar_auth, _) = CedarAuth::new(
        &get_default_test_rex_policy(),
        get_default_test_rex_schema(),
        "[]",
    )?;

    let (_temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let core_path = format!("{}/core.3922", temp_dir_path);
    fs::copy("tests/fixtures/core.3922", &core_path)?;

    let dir_handle = DirConfigBuilder::default()
        .path(temp_dir_path.clone())
        .build()?
        .safe_open(
            &cedar_auth,
            OpenDirOptionsBuilder::default().build().unwrap(),
        )?;

    let file_handle = dir_handle.safe_open_file(
        &cedar_auth,
        "core.3922",
        OpenFileOptionsBuilder::default().read(true).build()?,
    )?;

    let elf_info = file_handle.elf_info(&cedar_auth)?;
    assert!(elf_info.is_64bit, "Core dump should be 64-bit");
    assert_eq!(elf_info.platform.unwrap(), "x86_64");
    assert_eq!(elf_info.execfn.unwrap(), "/usr/bin/sleep");
    assert_eq!(elf_info.interpreter, None);

    Ok(())
}

/// Given: A regular ELF binary (using /bin/ls)
/// When: The elf_info method is called
/// Then: It successfully extracts the interpreter path
#[test]
fn test_elf_info_regular_binary() -> Result<()> {
    let (cedar_auth, _) = CedarAuth::new(
        &get_default_test_rex_policy(),
        get_default_test_rex_schema(),
        "[]",
    )?;

    let (_temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let binary_path = format!("{}/ls", temp_dir_path);
    fs::copy("/bin/ls", &binary_path)?;

    let dir_handle = DirConfigBuilder::default()
        .path(temp_dir_path.clone())
        .build()?
        .safe_open(
            &cedar_auth,
            OpenDirOptionsBuilder::default().build().unwrap(),
        )?;

    let file_handle = dir_handle.safe_open_file(
        &cedar_auth,
        "ls",
        OpenFileOptionsBuilder::default().read(true).build()?,
    )?;

    let elf_info = file_handle.elf_info(&cedar_auth)?;
    assert!(elf_info.interpreter.is_some());
    assert!(elf_info.platform.is_none());
    assert!(elf_info.execfn.is_none());

    Ok(())
}

/// Given: A file opened without read permissions
/// When: The elf_info method is called
/// Then: It returns an error about invalid file mode
#[test]
fn test_elf_info_requires_read_permission() -> Result<()> {
    let (cedar_auth, _) = CedarAuth::new(
        &get_default_test_rex_policy(),
        get_default_test_rex_schema(),
        "[]",
    )?;

    let (_temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let test_file = format!("{}/test.bin", temp_dir_path);
    fs::copy("tests/fixtures/core.3922", &test_file)?;

    let dir_handle = DirConfigBuilder::default()
        .path(temp_dir_path.clone())
        .build()?
        .safe_open(
            &cedar_auth,
            OpenDirOptionsBuilder::default().build().unwrap(),
        )?;

    let file_handle = dir_handle.safe_open_file(
        &cedar_auth,
        "test.bin",
        OpenFileOptionsBuilder::default()
            .write(true)
            .create(true)
            .build()?,
    )?;

    let result = file_handle.elf_info(&cedar_auth);
    assert!(result.is_err());

    Ok(())
}

/// Given: A non-ELF file
/// When: The elf_info method is called
/// Then: It returns a validation error
#[test]
fn test_elf_info_non_elf_file() -> Result<()> {
    let (cedar_auth, _) = CedarAuth::new(
        &get_default_test_rex_policy(),
        get_default_test_rex_schema(),
        "[]",
    )?;

    let (_temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let test_file = format!("{}/not_elf.txt", temp_dir_path);

    let mut file = fs::File::create(&test_file)?;
    file.write_all(b"This is not an ELF file")?;
    drop(file);

    let dir_handle = DirConfigBuilder::default()
        .path(temp_dir_path.clone())
        .build()?
        .safe_open(
            &cedar_auth,
            OpenDirOptionsBuilder::default().build().unwrap(),
        )?;

    let file_handle = dir_handle.safe_open_file(
        &cedar_auth,
        "not_elf.txt",
        OpenFileOptionsBuilder::default().read(true).build()?,
    )?;

    let result = file_handle.elf_info(&cedar_auth);
    assert!(result.is_err());

    Ok(())
}

/// Given: An empty file
/// When: The elf_info method is called
/// Then: It returns an error
#[test]
fn test_elf_info_empty_file() -> Result<()> {
    let (cedar_auth, _) = CedarAuth::new(
        &get_default_test_rex_policy(),
        get_default_test_rex_schema(),
        "[]",
    )?;

    let (_temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let test_file = format!("{}/empty.bin", temp_dir_path);
    fs::File::create(&test_file)?;

    let dir_handle = DirConfigBuilder::default()
        .path(temp_dir_path.clone())
        .build()?
        .safe_open(
            &cedar_auth,
            OpenDirOptionsBuilder::default().build().unwrap(),
        )?;

    let file_handle = dir_handle.safe_open_file(
        &cedar_auth,
        "empty.bin",
        OpenFileOptionsBuilder::default().read(true).build()?,
    )?;

    let result = file_handle.elf_info(&cedar_auth);
    assert!(result.is_err());

    Ok(())
}

/// Given: A truncated ELF file (header only)
/// When: The elf_info method is called
/// Then: It returns an error
#[test]
fn test_elf_info_truncated_file() -> Result<()> {
    let (cedar_auth, _) = CedarAuth::new(
        &get_default_test_rex_policy(),
        get_default_test_rex_schema(),
        "[]",
    )?;

    let (_temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let test_file = format!("{}/truncated.bin", temp_dir_path);

    let mut file = fs::File::create(&test_file)?;
    file.write_all(&[0x7f, b'E', b'L', b'F'])?;
    drop(file);

    let dir_handle = DirConfigBuilder::default()
        .path(temp_dir_path.clone())
        .build()?
        .safe_open(
            &cedar_auth,
            OpenDirOptionsBuilder::default().build().unwrap(),
        )?;

    let file_handle = dir_handle.safe_open_file(
        &cedar_auth,
        "truncated.bin",
        OpenFileOptionsBuilder::default().read(true).build()?,
    )?;

    let result = file_handle.elf_info(&cedar_auth);
    assert!(result.is_err());

    Ok(())
}

/// Given: An ELF file with corrupted header data (valid magic but invalid class)
/// When: The elf_info method is called
/// Then: It returns a ValidationError for "Failed to parse ELF header"
#[test]
fn test_elf_info_corrupted_header() -> Result<()> {
    let (cedar_auth, _) = CedarAuth::new(
        &get_default_test_rex_policy(),
        get_default_test_rex_schema(),
        "[]",
    )?;

    let (_temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let test_file = format!("{}/corrupted_header.bin", temp_dir_path);

    let mut file = fs::File::create(&test_file)?;
    // Create a buffer with ELF magic but invalid EI_CLASS value
    let mut header = vec![0u8; 64];
    // ELF magic
    header[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    // EI_CLASS: Invalid value (3 is not valid, only 1=32-bit or 2=64-bit)
    header[4] = 3;
    // EI_DATA: Little endian
    header[5] = 1;
    // EI_VERSION: Current
    header[6] = 1;
    file.write_all(&header)?;
    drop(file);

    let dir_handle = DirConfigBuilder::default()
        .path(temp_dir_path.clone())
        .build()?
        .safe_open(
            &cedar_auth,
            OpenDirOptionsBuilder::default().build().unwrap(),
        )?;

    let file_handle = dir_handle.safe_open_file(
        &cedar_auth,
        "corrupted_header.bin",
        OpenFileOptionsBuilder::default().read(true).build()?,
    )?;

    let result = file_handle.elf_info(&cedar_auth);
    assert!(result.is_err());
    if let Err(e) = result {
        let error_msg = format!("{:?}", e);
        assert!(
            error_msg.contains("Failed to parse ELF header")
                || error_msg.contains("ValidationError"),
            "Expected header parsing error, got: {}",
            error_msg
        );
    }

    Ok(())
}

/// Given: A 32-bit little-endian ELF binary
/// When: The elf_info method is called
/// Then: It correctly identifies the endianness and container type
#[test]
fn test_elf_info_little_endian_32bit() -> Result<()> {
    let (cedar_auth, _) = CedarAuth::new(
        &get_default_test_rex_policy(),
        get_default_test_rex_schema(),
        "[]",
    )?;

    let (_temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let test_file = format!("{}/elf32_le.bin", temp_dir_path);

    let mut file = fs::File::create(&test_file)?;
    // Create a minimal valid 32-bit little-endian ELF header
    let mut header = vec![0u8; 64];

    // ELF magic
    header[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    // EI_CLASS: 32-bit (1)
    header[4] = 1;
    // EI_DATA: Little endian (1)
    header[5] = 1;
    // EI_VERSION: Current (1)
    header[6] = 1;
    // EI_OSABI: SYSV (0)
    header[7] = 0;

    // e_type: ET_EXEC (2) - little endian
    header[16] = 2;
    header[17] = 0;
    // e_machine: EM_386 (3) - little endian
    header[18] = 3;
    header[19] = 0;
    // e_version: 1 - little endian
    header[20] = 1;
    header[21] = 0;
    header[22] = 0;
    header[23] = 0;

    // e_entry, e_phoff, e_shoff all 0 for this test

    // e_ehsize: 52 bytes for 32-bit - little endian (at offset 40)
    header[40] = 52;
    header[41] = 0;
    // e_phentsize: 32 bytes for 32-bit - little endian (at offset 42)
    header[42] = 32;
    header[43] = 0;
    // e_phnum: 0 program headers (at offset 44)
    header[44] = 0;
    header[45] = 0;
    // e_shentsize: 40 bytes for 32-bit - little endian (at offset 46)
    header[46] = 40;
    header[47] = 0;
    // e_shnum: 0 section headers (at offset 48)
    header[48] = 0;
    header[49] = 0;
    // e_shstrndx: 0 (at offset 50)
    header[50] = 0;
    header[51] = 0;

    file.write_all(&header)?;
    drop(file);

    let dir_handle = DirConfigBuilder::default()
        .path(temp_dir_path.clone())
        .build()?
        .safe_open(
            &cedar_auth,
            OpenDirOptionsBuilder::default().build().unwrap(),
        )?;

    let file_handle = dir_handle.safe_open_file(
        &cedar_auth,
        "elf32_le.bin",
        OpenFileOptionsBuilder::default().read(true).build()?,
    )?;

    let elf_info = file_handle.elf_info(&cedar_auth)?;
    assert!(!elf_info.is_64bit, "Should be identified as 32-bit");
    assert!(elf_info.interpreter.is_none());
    assert!(elf_info.platform.is_none());
    assert!(elf_info.execfn.is_none());

    Ok(())
}

/// Given: An ELF file with valid header but truncated program headers
/// When: The elf_info method is called  
/// Then: It returns an IO error when trying to read program headers
#[test]
fn test_elf_info_truncated_program_headers() -> Result<()> {
    let (cedar_auth, _) = CedarAuth::new(
        &get_default_test_rex_policy(),
        get_default_test_rex_schema(),
        "[]",
    )?;

    let (_temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let test_file = format!("{}/truncated_phdrs.bin", temp_dir_path);

    let mut file = fs::File::create(&test_file)?;
    // Create a valid 64-bit ELF header
    let mut header = vec![0u8; 64];

    // ELF magic
    header[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    // EI_CLASS: 64-bit (2)
    header[4] = 2;
    // EI_DATA: Little endian (1)
    header[5] = 1;
    // EI_VERSION: Current (1)
    header[6] = 1;

    // e_type: ET_EXEC (2) - little endian
    header[16] = 2;
    header[17] = 0;
    // e_machine: EM_X86_64 (62) - little endian
    header[18] = 62;
    header[19] = 0;
    // e_version: 1 - little endian
    header[20] = 1;
    header[21] = 0;
    header[22] = 0;
    header[23] = 0;

    // e_phoff: 64 (right after header) - little endian (at offset 32)
    header[32] = 64;
    header[33] = 0;
    header[34] = 0;
    header[35] = 0;
    header[36] = 0;
    header[37] = 0;
    header[38] = 0;
    header[39] = 0;

    // e_ehsize: 64 bytes for 64-bit - little endian (at offset 52)
    header[52] = 64;
    header[53] = 0;
    // e_phentsize: 56 bytes for 64-bit - little endian (at offset 54)
    header[54] = 56;
    header[55] = 0;
    // e_phnum: 1 program header (at offset 56)
    header[56] = 1;
    header[57] = 0;

    file.write_all(&header)?;

    // Write truncated program header data (not enough bytes)
    // This will cause an IO error during file.read_exact() before ProgramHeader::parse is called
    let corrupted_ph = vec![0u8; 20]; // Should be 56 bytes, but only write 20
    file.write_all(&corrupted_ph)?;
    drop(file);

    let dir_handle = DirConfigBuilder::default()
        .path(temp_dir_path.clone())
        .build()?
        .safe_open(
            &cedar_auth,
            OpenDirOptionsBuilder::default().build().unwrap(),
        )?;

    let file_handle = dir_handle.safe_open_file(
        &cedar_auth,
        "truncated_phdrs.bin",
        OpenFileOptionsBuilder::default().read(true).build()?,
    )?;

    let result = file_handle.elf_info(&cedar_auth);
    assert!(result.is_err());
    if let Err(e) = result {
        let error_msg = format!("{:?}", e);
        // Goblin returns a ValidationError for truncated data, not an IO error
        assert!(
            error_msg.contains("ValidationError") || error_msg.contains("Failed to parse ELF"),
            "Expected validation error for truncated program headers, got: {}",
            error_msg
        );
    }

    Ok(())
}

/// Given: An ELF file with corrupted PT_NOTE segment that causes note parsing to fail
/// When: The elf_info method is called
/// Then: It returns a ValidationError for "Failed to parse note"
#[test]
fn test_elf_info_corrupted_note_segment() -> Result<()> {
    let (cedar_auth, _) = CedarAuth::new(
        &get_default_test_rex_policy(),
        get_default_test_rex_schema(),
        "[]",
    )?;

    let (_temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let test_file = format!("{}/corrupted_note.bin", temp_dir_path);

    let mut file = fs::File::create(&test_file)?;

    // Create a valid 64-bit ELF header
    let mut header = vec![0u8; 64];
    header[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    header[4] = 2; // 64-bit
    header[5] = 1; // Little endian
    header[6] = 1; // Current version
    header[16] = 2; // ET_EXEC
    header[18] = 62; // EM_X86_64
    header[20] = 1; // e_version

    // e_phoff: 64 (at offset 32)
    header[32] = 64;
    // e_ehsize: 64 (at offset 52)
    header[52] = 64;
    // e_phentsize: 56 (at offset 54)
    header[54] = 56;
    // e_phnum: 1 (at offset 56)
    header[56] = 1;

    file.write_all(&header)?;

    // Create a PT_NOTE program header
    let mut phdr = vec![0u8; 56];
    // p_type: PT_NOTE (4) - little endian
    phdr[0] = 4;
    phdr[1] = 0;
    phdr[2] = 0;
    phdr[3] = 0;
    // p_offset: 120 (after header + phdr) - little endian (at offset 8)
    phdr[8] = 120;
    // p_filesz: 20 - little endian (at offset 32)
    phdr[32] = 20;

    file.write_all(&phdr)?;

    // Write corrupted note data (incomplete note header)
    // A valid note needs at least 12 bytes (namesz, descsz, type)
    // We'll write only 8 bytes to trigger a parsing error
    let corrupted_note = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    file.write_all(&corrupted_note)?;
    drop(file);

    let dir_handle = DirConfigBuilder::default()
        .path(temp_dir_path.clone())
        .build()?
        .safe_open(
            &cedar_auth,
            OpenDirOptionsBuilder::default().build().unwrap(),
        )?;

    let file_handle = dir_handle.safe_open_file(
        &cedar_auth,
        "corrupted_note.bin",
        OpenFileOptionsBuilder::default().read(true).build()?,
    )?;

    let result = file_handle.elf_info(&cedar_auth);
    assert!(result.is_err());
    if let Err(e) = result {
        let error_msg = format!("{:?}", e);
        assert!(
            error_msg.contains("Failed to parse note") || error_msg.contains("ValidationError"),
            "Expected note parsing error, got: {}",
            error_msg
        );
    }

    Ok(())
}

/// Given: A 32-bit ELF core dump with valid NT_AUXV containing AT_EXECFN
/// When: The elf_info method is called
/// Then: It correctly parses 32-bit auxv entries and extracts execfn
#[test]
fn test_elf_info_32bit_auxv_parsing_execfn() -> Result<()> {
    let (cedar_auth, _) = CedarAuth::new(
        &get_default_test_rex_policy(),
        get_default_test_rex_schema(),
        "[]",
    )?;

    let (_temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let test_file = format!("{}/core32_execfn.bin", temp_dir_path);

    let mut file = fs::File::create(&test_file)?;

    // Create 32-bit ELF header
    let mut header = vec![0u8; 52];
    header[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    header[4] = 1; // 32-bit
    header[5] = 1; // Little endian
    header[6] = 1; // Current version
    header[16] = 4; // ET_CORE
    header[18] = 3; // EM_386
    header[20] = 1; // e_version
    header[28] = 52; // e_phoff
    header[40] = 52; // e_ehsize
    header[42] = 32; // e_phentsize
    header[44] = 2; // e_phnum (PT_LOAD + PT_NOTE)
    file.write_all(&header)?;

    // PT_LOAD segment for string data
    let mut phdr_load = vec![0u8; 32];
    phdr_load[0] = 1; // PT_LOAD (little-endian)
    phdr_load[4] = 176; // p_offset (little-endian) - actual offset where string will be written
    phdr_load[8] = 0x10; // p_vaddr = 0x10 (little-endian)
    phdr_load[16] = 20; // p_filesz (little-endian)
    phdr_load[20] = 20; // p_memsz (little-endian)
    file.write_all(&phdr_load)?;

    // PT_NOTE segment
    let mut phdr_note = vec![0u8; 32];
    phdr_note[0] = 4; // PT_NOTE
    phdr_note[4] = 116; // p_offset
    phdr_note[16] = 60; // p_filesz
    file.write_all(&phdr_note)?;

    // Note header for NT_AUXV
    let mut note = vec![0u8; 60];
    note[0] = 5; // namesz
    note[4] = 32; // descsz (4 auxv entries * 8 bytes)
    note[8] = 6; // NT_AUXV
    note[12..17].copy_from_slice(b"CORE\0");
    // Auxv entry: AT_EXECFN (31) -> vaddr 0x10
    note[20] = 31; // type (32-bit LE)
    note[24] = 0x10; // value (32-bit LE)
    file.write_all(&note)?;

    // String data at offset 176 (immediately after note data)
    file.write_all(b"/bin/test32\0")?;
    drop(file);

    let dir_handle = DirConfigBuilder::default()
        .path(temp_dir_path.clone())
        .build()?
        .safe_open(
            &cedar_auth,
            OpenDirOptionsBuilder::default().build().unwrap(),
        )?;

    let file_handle = dir_handle.safe_open_file(
        &cedar_auth,
        "core32_execfn.bin",
        OpenFileOptionsBuilder::default().read(true).build()?,
    )?;

    let elf_info = file_handle.elf_info(&cedar_auth)?;
    assert!(!elf_info.is_64bit);
    assert_eq!(elf_info.execfn.unwrap(), "/bin/test32");

    Ok(())
}

/// Given: A 32-bit ELF core dump with valid NT_AUXV containing AT_PLATFORM
/// When: The elf_info method is called
/// Then: It correctly parses 32-bit auxv entries and extracts platform
#[test]
fn test_elf_info_32bit_auxv_parsing_platform() -> Result<()> {
    let (cedar_auth, _) = CedarAuth::new(
        &get_default_test_rex_policy(),
        get_default_test_rex_schema(),
        "[]",
    )?;

    let (_temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let test_file = format!("{}/core32_platform.bin", temp_dir_path);

    let mut file = fs::File::create(&test_file)?;

    // Create 32-bit ELF header
    let mut header = vec![0u8; 52];
    header[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    header[4] = 1; // 32-bit
    header[5] = 1; // Little endian
    header[6] = 1; // Current version
    header[16] = 4; // ET_CORE
    header[18] = 3; // EM_386
    header[20] = 1; // e_version
    header[28] = 52; // e_phoff
    header[40] = 52; // e_ehsize
    header[42] = 32; // e_phentsize
    header[44] = 2; // e_phnum
    file.write_all(&header)?;

    // PT_LOAD segment
    let mut phdr_load = vec![0u8; 32];
    phdr_load[0] = 1; // PT_LOAD (little-endian)
    phdr_load[4] = 176; // p_offset (little-endian) - actual offset where string will be written
    phdr_load[8] = 0x20; // p_vaddr = 0x20 (little-endian)
    phdr_load[16] = 10; // p_filesz (little-endian)
    phdr_load[20] = 10; // p_memsz (little-endian)
    file.write_all(&phdr_load)?;

    // PT_NOTE segment
    let mut phdr_note = vec![0u8; 32];
    phdr_note[0] = 4; // PT_NOTE
    phdr_note[4] = 116; // p_offset
    phdr_note[16] = 60; // p_filesz
    file.write_all(&phdr_note)?;

    // Note with AT_PLATFORM
    let mut note = vec![0u8; 60];
    note[0] = 5; // namesz
    note[4] = 32; // descsz
    note[8] = 6; // NT_AUXV
    note[12..17].copy_from_slice(b"CORE\0");
    // AT_PLATFORM (15) -> vaddr 0x20
    note[20] = 15; // type
    note[24] = 0x20; // value
    file.write_all(&note)?;

    // String data at offset 176 (immediately after note data)
    file.write_all(b"i686\0")?;
    drop(file);

    let dir_handle = DirConfigBuilder::default()
        .path(temp_dir_path.clone())
        .build()?
        .safe_open(
            &cedar_auth,
            OpenDirOptionsBuilder::default().build().unwrap(),
        )?;

    let file_handle = dir_handle.safe_open_file(
        &cedar_auth,
        "core32_platform.bin",
        OpenFileOptionsBuilder::default().read(true).build()?,
    )?;

    let elf_info = file_handle.elf_info(&cedar_auth)?;
    assert!(!elf_info.is_64bit);
    assert_eq!(elf_info.platform.unwrap(), "i686");

    Ok(())
}

/// Given: A 32-bit big-endian ELF core dump with valid auxv
/// When: The elf_info method is called
/// Then: It correctly parses 32-bit big-endian auxv entries
#[test]
fn test_elf_info_32bit_big_endian_auxv() -> Result<()> {
    let (cedar_auth, _) = CedarAuth::new(
        &get_default_test_rex_policy(),
        get_default_test_rex_schema(),
        "[]",
    )?;

    let (_temp_dir, temp_dir_path) = create_temp_dir_and_path()?;
    let test_file = format!("{}/core32_be.bin", temp_dir_path);

    let mut file = fs::File::create(&test_file)?;

    // Create 32-bit big-endian ELF header
    let mut header = vec![0u8; 52];
    header[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    header[4] = 1; // 32-bit
    header[5] = 2; // Big endian
    header[6] = 1; // Current version
    header[16] = 0;
    header[17] = 4; // ET_CORE (big-endian)
    header[18] = 0;
    header[19] = 20; // EM_PPC (big-endian)
    header[20] = 0;
    header[21] = 0;
    header[22] = 0;
    header[23] = 1; // e_version
    header[28] = 0;
    header[29] = 0;
    header[30] = 0;
    header[31] = 52; // e_phoff
    header[40] = 0;
    header[41] = 52; // e_ehsize
    header[42] = 0;
    header[43] = 32; // e_phentsize
    header[44] = 0;
    header[45] = 2; // e_phnum
    file.write_all(&header)?;

    // PT_LOAD segment (big-endian)
    let mut phdr_load = vec![0u8; 32];
    phdr_load[0] = 0;
    phdr_load[1] = 0;
    phdr_load[2] = 0;
    phdr_load[3] = 1; // PT_LOAD
    phdr_load[4] = 0;
    phdr_load[5] = 0;
    phdr_load[6] = 0;
    phdr_load[7] = 176; // p_offset - actual offset where string will be written
    phdr_load[8] = 0;
    phdr_load[9] = 0;
    phdr_load[10] = 0;
    phdr_load[11] = 0x30; // p_vaddr
    phdr_load[16] = 0;
    phdr_load[17] = 0;
    phdr_load[18] = 0;
    phdr_load[19] = 15; // p_filesz
    phdr_load[20] = 0;
    phdr_load[21] = 0;
    phdr_load[22] = 0;
    phdr_load[23] = 15; // p_memsz
    file.write_all(&phdr_load)?;

    // PT_NOTE segment (big-endian)
    let mut phdr_note = vec![0u8; 32];
    phdr_note[0] = 0;
    phdr_note[1] = 0;
    phdr_note[2] = 0;
    phdr_note[3] = 4; // PT_NOTE
    phdr_note[4] = 0;
    phdr_note[5] = 0;
    phdr_note[6] = 0;
    phdr_note[7] = 116; // p_offset
    phdr_note[16] = 0;
    phdr_note[17] = 0;
    phdr_note[18] = 0;
    phdr_note[19] = 60; // p_filesz
    file.write_all(&phdr_note)?;

    // Note with AT_PLATFORM (big-endian)
    let mut note = vec![0u8; 60];
    note[0] = 0;
    note[1] = 0;
    note[2] = 0;
    note[3] = 5; // namesz
    note[4] = 0;
    note[5] = 0;
    note[6] = 0;
    note[7] = 32; // descsz
    note[8] = 0;
    note[9] = 0;
    note[10] = 0;
    note[11] = 6; // NT_AUXV
    note[12..17].copy_from_slice(b"CORE\0");
    // AT_PLATFORM (15) -> vaddr 0x30 (big-endian)
    note[20] = 0;
    note[21] = 0;
    note[22] = 0;
    note[23] = 15; // type
    note[24] = 0;
    note[25] = 0;
    note[26] = 0;
    note[27] = 0x30; // value
    file.write_all(&note)?;

    // String data at offset 176 (immediately after note data)
    file.write_all(b"ppc\0")?;
    drop(file);

    let dir_handle = DirConfigBuilder::default()
        .path(temp_dir_path.clone())
        .build()?
        .safe_open(
            &cedar_auth,
            OpenDirOptionsBuilder::default().build().unwrap(),
        )?;

    let file_handle = dir_handle.safe_open_file(
        &cedar_auth,
        "core32_be.bin",
        OpenFileOptionsBuilder::default().read(true).build()?,
    )?;

    let elf_info = file_handle.elf_info(&cedar_auth)?;
    assert!(!elf_info.is_64bit);
    assert_eq!(elf_info.platform.unwrap(), "ppc");

    Ok(())
}
