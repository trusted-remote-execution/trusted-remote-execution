//! ELF file information extraction module.
//!
//! This module provides functionality to extract metadata from ELF (Executable and Linkable Format)
//! files and core dumps using memory-mapped I/O for efficient parsing.
//!
//! # Parsing Strategy
//!
//! The parsing uses memory-mapped I/O combined with goblin's ELF parser:
//! 1. Memory-map the file (virtual memory mapping, demand-paged by OS)
//! 2. Use `goblin::elf::Elf::parse()` to parse the ELF structure
//! 3. Extract interpreter from the parsed ELF structure
//! 4. Iterate through `PT_NOTE` segments to find `NT_AUXV` notes
//! 5. Parse auxiliary vector entries to extract executable filename and platform
//! 6. Resolve virtual addresses to strings using `PT_LOAD` segments
//!
//! # Memory Efficiency
//!
//! Memory mapping creates a virtual address space mapping but only loads pages
//! into physical RAM as they're accessed (demand paging). For large core dumps,
//! this means we only use memory for the parts we actually read (headers, notes).

use crate::RcFileHandle;
use crate::errors::RustSafeIoError;
use derive_getters::Getters;
use goblin::elf::{Elf, ProgramHeader};
use goblin::options::ParseOptions;
use memmap2::Mmap;
use rex_cedar_auth::cedar_auth::CedarAuth;
use scroll::Pread;
use serde::Serialize;

// ELF note types
const NT_AUXV: u32 = 6;

// Auxiliary vector entry types
const AT_EXECFN: u64 = 31;
const AT_PLATFORM: u64 = 15;

// Auxiliary vector entry sizes
const AUXV_ENTRY_SIZE_64: usize = 16;
const AUXV_ENTRY_SIZE_32: usize = 8;

// Program header types
const PT_LOAD: u32 = 1;

/// Information extracted from an ELF file
#[derive(Debug, Clone, Getters, Serialize)]
pub struct ElfInfo {
    /// The executable filename (from `AT_EXECFN` in core dumps)
    pub execfn: Option<String>,
    /// The platform string (from `AT_PLATFORM` in core dumps)
    pub platform: Option<String>,
    /// The interpreter path (from `PT_INTERP` segment)
    pub interpreter: Option<String>,
    /// Whether this is a 64-bit ELF file
    pub is_64bit: bool,
}

impl RcFileHandle {
    /// Extracts ELF information from the file.
    ///
    /// This method memory-maps the file and uses goblin's ELF parser to extract
    /// metadata about the binary, including the interpreter path, platform information,
    /// and executable filename (for core dumps).
    ///
    /// # Memory Efficiency
    ///
    /// The file is memory-mapped, which means the OS only loads pages into physical
    /// memory as they're accessed. For large core dumps, this is much more efficient
    /// than reading the entire file into memory.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_safe_io::DirConfigBuilder;
    /// use rust_safe_io::options::{OpenDirOptionsBuilder, OpenFileOptionsBuilder};
    /// # use rex_cedar_auth::test_utils::{get_default_test_rex_policy, get_default_test_rex_schema};
    /// # use rex_cedar_auth::cedar_auth::CedarAuth;
    /// #
    /// # let cedar_auth = CedarAuth::new(
    /// #     &get_default_test_rex_policy(),
    /// #     get_default_test_rex_schema(),
    /// #     "[]"
    /// # ).unwrap().0;
    ///
    /// let dir_handle = DirConfigBuilder::default()
    ///     .path("/tmp".to_string())
    ///     .build().unwrap()
    ///     .safe_open(&cedar_auth, OpenDirOptionsBuilder::default().build().unwrap())
    ///     .unwrap();
    ///
    /// let file_handle = dir_handle.safe_open_file(
    ///     &cedar_auth,
    ///     "binary",
    ///     OpenFileOptionsBuilder::default().read(true).build().unwrap()
    /// ).unwrap();
    ///
    /// let elf_info = file_handle.elf_info(&cedar_auth).unwrap();
    /// println!("64-bit: {}", elf_info.is_64bit);
    /// if let Some(interpreter) = elf_info.interpreter {
    ///     println!("Interpreter: {}", interpreter);
    /// }
    /// ```
    #[cfg(target_os = "linux")]
    #[allow(unsafe_code)]
    pub fn elf_info(&self, cedar_auth: &CedarAuth) -> Result<ElfInfo, RustSafeIoError> {
        self.validate_read_open_option(cedar_auth)?;

        // Memory-map the file for efficient parsing
        // Safety: We're creating a read-only memory map of a file we have permission to read

        let mmap = unsafe {
            Mmap::map(&self.file_handle.file).map_err(|e| RustSafeIoError::ValidationError {
                reason: format!("Failed to memory-map file: {e}"),
            })?
        };

        // Parse the ELF file using goblin
        let parse_opts = ParseOptions::strict(); // Always ensure we're using strict mode
        let elf = Elf::parse_with_opts(&mmap, &parse_opts).map_err(|e| {
            RustSafeIoError::ValidationError {
                reason: format!("Failed to parse ELF file: {e}"),
            }
        })?;

        // Extract basic information
        let interpreter = elf.interpreter.map(ToString::to_string);
        let is_64bit = elf.is_64;

        // Extract execfn and platform from PT_NOTE segments (for core dumps)
        let (execfn, platform) = extract_auxv_info(&elf, &mmap)?;

        Ok(ElfInfo {
            execfn,
            platform,
            interpreter,
            is_64bit,
        })
    }
}

/// Extracts execfn and platform from auxiliary vector in `PT_NOTE` segments.
///
/// This function iterates through all `PT_NOTE` segments, looking for `NT_AUXV` notes
/// which contain the auxiliary vector with information about the original executable.
pub(crate) fn extract_auxv_info(
    elf: &Elf,
    data: &[u8],
) -> Result<(Option<String>, Option<String>), RustSafeIoError> {
    let mut execfn = None;
    let mut platform = None;

    // Use goblin's note iterator to parse PT_NOTE segments
    if let Some(note_iter) = elf.iter_note_headers(data) {
        for note_result in note_iter {
            let note = note_result.map_err(|e| RustSafeIoError::ValidationError {
                reason: format!("Failed to parse note: {e}"),
            })?;

            // Look for NT_AUXV notes which contain the auxiliary vector
            if note.n_type == NT_AUXV {
                let (e, p) = parse_auxv(
                    note.desc,
                    elf.is_64,
                    elf.little_endian,
                    &elf.program_headers,
                    data,
                )?;

                execfn = e;
                platform = p;
                return Ok((execfn, platform));
            }
        }
    }

    Ok((execfn, platform))
}

/// Parses auxiliary vector (auxv) entries to extract execfn and platform.
///
/// The auxiliary vector is an array of key-value pairs passed to programs at startup.
/// In core dumps, it contains information about the original process.
///
/// # Auxv Entry Structure
///
/// For 64-bit ELF (16 bytes per entry):
/// ```text
/// +-------------------+
/// | type  (8 bytes)   |  Entry type (e.g., AT_EXECFN, AT_PLATFORM)
/// +-------------------+
/// | value (8 bytes)   |  Entry value (often a virtual address)
/// +-------------------+
/// ```
///
/// For 32-bit ELF (8 bytes per entry):
/// ```text
/// +-------------------+
/// | type  (4 bytes)   |  Entry type
/// +-------------------+
/// | value (4 bytes)   |  Entry value
/// +-------------------+
/// ```
pub(crate) fn parse_auxv(
    auxv_data: &[u8],
    is_64bit: bool,
    little_endian: bool,
    program_headers: &[ProgramHeader],
    file_data: &[u8],
) -> Result<(Option<String>, Option<String>), RustSafeIoError> {
    let entry_size = if is_64bit {
        AUXV_ENTRY_SIZE_64
    } else {
        AUXV_ENTRY_SIZE_32
    };

    let endian = if little_endian {
        scroll::Endian::Little
    } else {
        scroll::Endian::Big
    };

    let mut offset = 0;
    let mut execfn = None;
    let mut platform = None;

    // Iterate through all auxv entries
    while offset + entry_size <= auxv_data.len() {
        // Parse type and value fields (size depends on 32-bit vs 64-bit)
        let (auxv_type, auxv_value) = if is_64bit {
            // 64-bit: type and value are both 8 bytes
            let auxv_type: u64 =
                auxv_data
                    .pread_with(offset, endian)
                    .map_err(|e: scroll::Error| RustSafeIoError::ValidationError {
                        reason: format!("Failed to parse auxv type: {e}"),
                    })?;
            let auxv_value: u64 =
                auxv_data
                    .pread_with(offset + 8, endian)
                    .map_err(|e: scroll::Error| RustSafeIoError::ValidationError {
                        reason: format!("Failed to parse auxv value: {e}"),
                    })?;
            (auxv_type, auxv_value)
        } else {
            // 32-bit: type and value are both 4 bytes, upcast to u64
            let auxv_type: u32 =
                auxv_data
                    .pread_with(offset, endian)
                    .map_err(|e: scroll::Error| RustSafeIoError::ValidationError {
                        reason: format!("Failed to parse auxv type: {e}"),
                    })?;
            let auxv_value: u32 =
                auxv_data
                    .pread_with(offset + 4, endian)
                    .map_err(|e: scroll::Error| RustSafeIoError::ValidationError {
                        reason: format!("Failed to parse auxv value: {e}"),
                    })?;
            (u64::from(auxv_type), u64::from(auxv_value))
        };

        // Extract strings for the entries we care about
        match auxv_type {
            AT_EXECFN => {
                // Value is a virtual address pointing to the executable filename string
                execfn = read_string_at_virtual_address(auxv_value, program_headers, file_data);
            }
            AT_PLATFORM => {
                // Value is a virtual address pointing to the platform string
                platform = read_string_at_virtual_address(auxv_value, program_headers, file_data);
            }
            _ => {}
        }

        offset += entry_size;
    }

    Ok((execfn, platform))
}

/// Reads a null-terminated string at a virtual address in the ELF file.
///
/// This function resolves a virtual memory address to a file offset by finding
/// the `PT_LOAD` segment that contains the address, then reads the string from
/// the memory-mapped data at the calculated offset.
///
/// # Virtual Address Resolution
///
/// Virtual addresses in core dumps refer to the process's memory space. To read
/// the actual data, we must:
/// 1. Find the `PT_LOAD` segment containing the virtual address
/// 2. Calculate the file offset: `file_offset = (vaddr - segment_vaddr) + segment_offset`
/// 3. Read from the memory-mapped data at that offset
///
/// # Returns
/// - `Some(String)` if the string is found and valid UTF-8
/// - `None` if the address is not in any `PT_LOAD` segment or string is invalid
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn read_string_at_virtual_address(
    addr: u64,
    program_headers: &[ProgramHeader],
    data: &[u8],
) -> Option<String> {
    // Find the PT_LOAD segment containing this virtual address
    for ph in program_headers {
        if ph.p_type != PT_LOAD {
            continue;
        }

        // Check if the address falls within this segment's virtual address range
        // Use p_memsz instead of p_filesz to check the full memory range
        if addr >= ph.p_vaddr && addr < ph.p_vaddr + ph.p_memsz {
            // Calculate the file offset from the virtual address
            // Note: Truncation is acceptable here as file offsets fit in usize on target platforms
            let file_offset = (addr - ph.p_vaddr + ph.p_offset) as usize;

            // Ensure we don't read past the end of the data
            if file_offset >= data.len() {
                return None;
            }

            // Find the null terminator
            let remaining = data.get(file_offset..)?;
            if let Some(null_pos) = remaining.iter().position(|&b| b == 0) {
                // Extract and convert to UTF-8 string
                if let Ok(s) = std::str::from_utf8(remaining.get(..null_pos)?) {
                    return Some(s.to_string());
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn create_pt_load(p_vaddr: u64, p_offset: u64, p_filesz: u64, p_memsz: u64) -> ProgramHeader {
        ProgramHeader {
            p_type: PT_LOAD,
            p_flags: 0,
            p_offset,
            p_vaddr,
            p_paddr: 0,
            p_filesz,
            p_memsz,
            p_align: 0,
        }
    }

    mod read_string_tests {
        use super::*;

        /// Given: A PT_LOAD segment with a null-terminated string at a virtual address
        /// When: read_string_at_virtual_address is called with that address
        /// Then: It successfully reads and returns the string
        #[rstest]
        #[case(0x1000, 100, b"hello\0world", "hello")]
        #[case(0x2000, 200, b"test\0", "test")]
        #[case(0x3000, 300, b"a\0b\0c", "a")]
        fn test_read_string_success(
            #[case] vaddr: u64,
            #[case] offset: u64,
            #[case] data_bytes: &[u8],
            #[case] expected: &str,
        ) {
            let mut data = vec![0u8; offset as usize];
            data.extend_from_slice(data_bytes);

            let phdrs = vec![create_pt_load(vaddr, offset, 20, 20)];

            let result = read_string_at_virtual_address(vaddr, &phdrs, &data);
            assert_eq!(result, Some(expected.to_string()));
        }

        /// Given: No PT_LOAD segments in the program headers
        /// When: read_string_at_virtual_address is called
        /// Then: It returns None
        #[test]
        fn test_read_string_no_pt_load_segment() {
            let data = b"hello\0";
            let phdrs = vec![];

            let result = read_string_at_virtual_address(0x1000, &phdrs, data);
            assert_eq!(result, None);
        }

        /// Given: A virtual address that is not within any PT_LOAD segment
        /// When: read_string_at_virtual_address is called
        /// Then: It returns None
        #[test]
        fn test_read_string_address_not_in_segment() {
            let data = b"hello\0";
            let phdrs = vec![create_pt_load(0x1000, 0, 10, 10)];

            let result = read_string_at_virtual_address(0x2000, &phdrs, data);
            assert_eq!(result, None);
        }

        /// Given: A virtual address that maps to a file offset beyond the data length
        /// When: read_string_at_virtual_address is called
        /// Then: It returns None
        #[test]
        fn test_read_string_file_offset_out_of_bounds() {
            let data = vec![0u8; 50];
            let phdrs = vec![create_pt_load(0x1000, 100, 20, 20)];

            let result = read_string_at_virtual_address(0x1000, &phdrs, &data);
            assert_eq!(result, None);
        }

        /// Given: A string at a virtual address without a null terminator
        /// When: read_string_at_virtual_address is called
        /// Then: It returns None
        #[test]
        fn test_read_string_no_null_terminator() {
            let mut data = vec![0u8; 100];
            data.extend_from_slice(b"hello");

            let phdrs = vec![create_pt_load(0x1000, 100, 20, 20)];

            let result = read_string_at_virtual_address(0x1000, &phdrs, &data);
            assert_eq!(result, None);
        }

        /// Given: Invalid UTF-8 bytes at a virtual address
        /// When: read_string_at_virtual_address is called
        /// Then: It returns None
        #[test]
        fn test_read_string_invalid_utf8() {
            let mut data = vec![0u8; 100];
            data.extend_from_slice(&[0xFF, 0xFE, 0xFD, 0x00]);

            let phdrs = vec![create_pt_load(0x1000, 100, 20, 20)];

            let result = read_string_at_virtual_address(0x1000, &phdrs, &data);
            assert_eq!(result, None);
        }

        /// Given: An empty string (just null terminator) at a virtual address
        /// When: read_string_at_virtual_address is called
        /// Then: It returns an empty string
        #[test]
        fn test_read_string_empty_string() {
            let mut data = vec![0u8; 100];
            data.push(0x00);

            let phdrs = vec![create_pt_load(0x1000, 100, 20, 20)];

            let result = read_string_at_virtual_address(0x1000, &phdrs, &data);
            assert_eq!(result, Some(String::new()));
        }

        /// Given: A PT_LOAD segment where p_memsz is larger than p_filesz
        /// When: read_string_at_virtual_address is called with an address in the memory range
        /// Then: It successfully reads the string using p_memsz for range checking
        #[test]
        fn test_read_string_uses_p_memsz_not_p_filesz() {
            let mut data = vec![0u8; 100];
            data.extend_from_slice(b"test\0");

            // p_filesz is 5, but p_memsz is 20
            let phdrs = vec![create_pt_load(0x1000, 100, 5, 20)];

            // Address at offset 0 within segment (within p_memsz)
            let result = read_string_at_virtual_address(0x1000, &phdrs, &data);
            assert_eq!(result, Some("test".to_string()));
        }

        /// Given: Multiple PT_LOAD segments with strings at different virtual addresses
        /// When: read_string_at_virtual_address is called for each address
        /// Then: It correctly reads strings from their respective segments
        #[test]
        fn test_read_string_multiple_pt_load_segments() {
            let mut data = vec![0u8; 100];
            data.extend_from_slice(b"first\0");
            data.extend_from_slice(&vec![0u8; 50]);
            data.extend_from_slice(b"second\0");

            let phdrs = vec![
                create_pt_load(0x1000, 100, 10, 10),
                create_pt_load(0x2000, 156, 10, 10),
            ];

            let result1 = read_string_at_virtual_address(0x1000, &phdrs, &data);
            assert_eq!(result1, Some("first".to_string()));

            let result2 = read_string_at_virtual_address(0x2000, &phdrs, &data);
            assert_eq!(result2, Some("second".to_string()));
        }
    }

    mod parse_auxv_tests {
        use super::*;

        /// Given: Valid auxv data with AT_EXECFN or AT_PLATFORM entries
        /// When: parse_auxv is called with various bit widths and endianness
        /// Then: It successfully extracts the execfn or platform string
        #[rstest]
        #[case(true, true, 31u64, 0x1000u64, "execfn_test")]
        #[case(true, true, 15u64, 0x2000u64, "platform_test")]
        #[case(false, true, 31u64, 0x1000u64, "execfn32")]
        #[case(false, true, 15u64, 0x2000u64, "platform32")]
        fn test_parse_auxv_success(
            #[case] is_64bit: bool,
            #[case] little_endian: bool,
            #[case] auxv_type: u64,
            #[case] vaddr: u64,
            #[case] expected_str: &str,
        ) {
            let mut auxv_data = Vec::new();
            let mut file_data = vec![0u8; vaddr as usize];
            file_data.extend_from_slice(expected_str.as_bytes());
            file_data.push(0);

            if is_64bit {
                auxv_data.extend_from_slice(&auxv_type.to_le_bytes());
                auxv_data.extend_from_slice(&vaddr.to_le_bytes());
            } else {
                auxv_data.extend_from_slice(&(auxv_type as u32).to_le_bytes());
                auxv_data.extend_from_slice(&(vaddr as u32).to_le_bytes());
            }

            let phdrs = vec![create_pt_load(vaddr, vaddr, 100, 100)];

            let result = parse_auxv(&auxv_data, is_64bit, little_endian, &phdrs, &file_data);
            assert!(result.is_ok());

            let (execfn, platform) = result.unwrap();
            if auxv_type == AT_EXECFN {
                assert_eq!(execfn, Some(expected_str.to_string()));
                assert_eq!(platform, None);
            } else {
                assert_eq!(execfn, None);
                assert_eq!(platform, Some(expected_str.to_string()));
            }
        }

        /// Given: 32-bit big-endian auxv data with AT_PLATFORM
        /// When: parse_auxv is called
        /// Then: It correctly parses big-endian data and extracts the platform
        #[test]
        fn test_parse_auxv_32bit_big_endian() {
            let mut auxv_data = Vec::new();
            let vaddr = 0x1000u32;
            let auxv_type = 15u32; // AT_PLATFORM

            // Big-endian encoding
            auxv_data.extend_from_slice(&auxv_type.to_be_bytes());
            auxv_data.extend_from_slice(&vaddr.to_be_bytes());

            let mut file_data = vec![0u8; vaddr as usize];
            file_data.extend_from_slice(b"ppc\0");

            let phdrs = vec![create_pt_load(vaddr as u64, vaddr as u64, 100, 100)];

            let result = parse_auxv(&auxv_data, false, false, &phdrs, &file_data);
            assert!(result.is_ok());

            let (execfn, platform) = result.unwrap();
            assert_eq!(execfn, None);
            assert_eq!(platform, Some("ppc".to_string()));
        }

        /// Given: Truncated auxv data that is too short for a complete entry
        /// When: parse_auxv is called
        /// Then: It gracefully handles the truncation and returns None
        #[test]
        fn test_parse_auxv_truncated_data() {
            let auxv_data = vec![31, 0, 0]; // Only 3 bytes, not enough for 32-bit entry

            let phdrs = vec![];
            let file_data = vec![];

            let result = parse_auxv(&auxv_data, false, true, &phdrs, &file_data);
            assert!(result.is_ok());

            let (execfn, platform) = result.unwrap();
            assert_eq!(execfn, None);
            assert_eq!(platform, None);
        }

        /// Given: Empty auxv data
        /// When: parse_auxv is called
        /// Then: It returns None for both execfn and platform
        #[test]
        fn test_parse_auxv_empty_data() {
            let auxv_data = vec![];
            let phdrs = vec![];
            let file_data = vec![];

            let result = parse_auxv(&auxv_data, true, true, &phdrs, &file_data);
            assert!(result.is_ok());

            let (execfn, platform) = result.unwrap();
            assert_eq!(execfn, None);
            assert_eq!(platform, None);
        }

        /// Given: Auxv data with both AT_EXECFN and AT_PLATFORM entries
        /// When: parse_auxv is called
        /// Then: It successfully extracts both strings
        #[test]
        fn test_parse_auxv_multiple_entries() {
            let mut auxv_data = Vec::new();

            // AT_EXECFN entry
            auxv_data.extend_from_slice(&31u64.to_le_bytes());
            auxv_data.extend_from_slice(&0x1000u64.to_le_bytes());

            // AT_PLATFORM entry
            auxv_data.extend_from_slice(&15u64.to_le_bytes());
            auxv_data.extend_from_slice(&0x2000u64.to_le_bytes());

            let mut file_data = vec![0u8; 0x1000];
            file_data.extend_from_slice(b"execfn\0");
            file_data.extend_from_slice(&vec![0u8; 0x2000 - 0x1007]);
            file_data.extend_from_slice(b"platform\0");

            let phdrs = vec![
                create_pt_load(0x1000, 0x1000, 100, 100),
                create_pt_load(0x2000, 0x2000, 100, 100),
            ];

            let result = parse_auxv(&auxv_data, true, true, &phdrs, &file_data);
            assert!(result.is_ok());

            let (execfn, platform) = result.unwrap();
            assert_eq!(execfn, Some("execfn".to_string()));
            assert_eq!(platform, Some("platform".to_string()));
        }

        /// Given: Auxv data with an unknown type
        /// When: parse_auxv is called
        /// Then: It ignores the unknown type and returns None
        #[test]
        fn test_parse_auxv_unknown_type() {
            let mut auxv_data = Vec::new();

            // Unknown auxv type (99)
            auxv_data.extend_from_slice(&99u64.to_le_bytes());
            auxv_data.extend_from_slice(&0x1000u64.to_le_bytes());

            let phdrs = vec![];
            let file_data = vec![];

            let result = parse_auxv(&auxv_data, true, true, &phdrs, &file_data);
            assert!(result.is_ok());

            let (execfn, platform) = result.unwrap();
            assert_eq!(execfn, None);
            assert_eq!(platform, None);
        }

        /// Given: Auxv data with a virtual address not in any PT_LOAD segment
        /// When: parse_auxv is called
        /// Then: It returns None for the string (graceful handling)
        #[test]
        fn test_parse_auxv_invalid_virtual_address() {
            let mut auxv_data = Vec::new();

            // AT_EXECFN with invalid vaddr (not in any PT_LOAD)
            auxv_data.extend_from_slice(&31u64.to_le_bytes());
            auxv_data.extend_from_slice(&0x9999u64.to_le_bytes());

            let phdrs = vec![create_pt_load(0x1000, 0x1000, 100, 100)];
            let file_data = vec![0u8; 0x1100];

            let result = parse_auxv(&auxv_data, true, true, &phdrs, &file_data);
            assert!(result.is_ok());

            let (execfn, platform) = result.unwrap();
            assert_eq!(execfn, None);
            assert_eq!(platform, None);
        }
    }

    mod extract_auxv_info_tests {
        use super::*;
        use goblin::elf::Elf;

        /// Given: An ELF with no PT_NOTE segments (iter_note_headers returns None)
        /// When: extract_auxv_info is called
        /// Then: It returns Ok with None for both execfn and platform
        #[test]
        fn test_extract_auxv_info_no_note_headers() {
            // Create a minimal 64-bit ELF header without PT_NOTE segments
            let mut data = vec![0u8; 64];
            data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
            data[4] = 2; // 64-bit
            data[5] = 1; // Little endian
            data[6] = 1; // Current version
            data[16] = 2; // ET_EXEC
            data[18] = 62; // EM_X86_64
            data[52] = 64; // e_ehsize
            data[54] = 56; // e_phentsize
            data[56] = 0; // e_phnum = 0 (no program headers)

            let elf = Elf::parse(&data).unwrap();
            let result = extract_auxv_info(&elf, &data);

            assert!(result.is_ok());
            let (execfn, platform) = result.unwrap();
            assert_eq!(execfn, None);
            assert_eq!(platform, None);
        }
    }
}
