use elf::{abi::DT_NEEDED, endian::AnyEndian, ElfStream};
use std::slice;
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    mem::size_of,
};
use windows_sys::Win32::System::{
    Diagnostics::Debug::{
        IMAGE_FILE_HEADER, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64, IMAGE_OPTIONAL_HEADER_MAGIC,
        IMAGE_SECTION_HEADER,
    },
    SystemServices::{IMAGE_DOS_HEADER, IMAGE_IMPORT_DESCRIPTOR},
};

type DWORD = u32;

#[derive(Debug, PartialEq, Eq)]
pub enum FileType {
    Macho,
    MachoM,
    ELF,
    PE,
    Unknown,
}

#[derive(Debug, PartialEq, Eq)]
pub enum MacCpu {
    ARM64,
    I368,
    X86_64,
    PPC,
    PPC64
}

impl From<&[u8]> for MacCpu {
    fn from(val: &[u8]) -> Self {
        match *val {
            [0x01, 0, 0, 0x07] => MacCpu::X86_64,
            [0x01, 0, 0, 0x0c] => MacCpu::ARM64,
            [0,    0, 0, 0x07] => MacCpu::I368,
            [0,    0, 0, 0x12] => MacCpu::PPC,
            [0x01, 0, 0, 0x12] => MacCpu::PPC64,
            _ => panic!("Unknown CPU type")
        }
    }
}

#[derive(Debug)]
pub struct LibMac {
    // 0 if cmd is 0x0000000D, 1 if 0x0000000c, 13 if 0x00000018
    pub cmd: u8,
    pub curr_ver: String,
    pub compat_ver: String,
    pub path: String,
}

#[derive(Debug)]
pub struct LibMacM {
    pub cpu_type: MacCpu,
    pub libs: Vec<LibMac>
}

#[derive(Debug)]
pub struct LibLinux {
    pub name: String,
}

#[derive(Debug)]
pub struct LibWindows {
    pub name: String,
}

macro_rules! read_le_bytes {
    ($file:ident, $typ:ty) => {{
        let mut bytes = [0; size_of::<$typ>()];
        $file.read_exact(&mut bytes)?;
        <$typ>::from_le_bytes(bytes)
    }};
}

macro_rules! read_be_bytes {
    ($file:ident, $typ:ty) => {{
        let mut bytes = [0; size_of::<$typ>()];
        $file.read_exact(&mut bytes)?;
        <$typ>::from_be_bytes(bytes)
    }};
}

macro_rules! seek_start {
    ($offset:expr, $file:ident) => {
        $file.seek(SeekFrom::Start($offset))?;
    };
}

fn read_string_from_file(file: &mut File) -> io::Result<String> {
    let mut string = String::new();
    // Read the DLL name
    loop {
        let ch = read_le_bytes!(file, u8);
        // String NULL terminate
        if ch == b'\x00' {
            return Ok(string);
        }
        string.push(ch as char);
    }
}

/// Reads a C struct from a file.
fn read_struct<T>(file: &mut File) -> io::Result<T> {
    let size = size_of::<T>();
    let mut struc = std::mem::MaybeUninit::<T>::zeroed();

    // SAFETY:
    unsafe {
        let t_slice = slice::from_raw_parts_mut(&mut struc as *mut _ as *mut u8, size);
        file.read_exact(t_slice)?;

        Ok(struc.assume_init())
    }
}

/// Returns the OS name.
///
/// For Mach-O and ELF files it returns the arch: true if 64 bits, else false.
pub fn fileos(file: &mut impl Read) -> io::Result<(FileType, bool)> {
    let mut line = [0u8; 4];
    file.read_exact(&mut line)?;
    match line {
        [0x4d, 0x5a, _, _] => Ok((FileType::PE, true)),
        // 64bit or 32bit macos
        [0xcf, 0xfa, 0xed, 0xfe] | [0xce, 0xfa, 0xed, 0xfe] => Ok((FileType::Macho, line[0] == 0xcf)),
        [0xca, 0xfe, 0xba, 0xbe] => Ok((FileType::MachoM, true)),
        [0x7f, 0x45, 0x4c, 0x46] => {
            let bits = read_le_bytes!(file, u8);
            Ok((FileType::ELF, bits == 2))
        },
        _ => Ok((FileType::Unknown, false))
    }
}

pub fn find_multi_macho(file: &mut File) -> io::Result<Vec<LibMacM>> {
    file.rewind()?;

    seek_start!(4, file);
    let num_binaries = read_be_bytes!(file, DWORD);

    let mut libs = Vec::new();

    for _ in 0..num_binaries {
        let mut cpu_type = [0; 4];
        file.read_exact(&mut cpu_type)?;
        let cpu_type = MacCpu::from(cpu_type.as_ref());

        // Read File offset
        file.seek_relative(4)?;
        let offset = read_be_bytes!(file, DWORD);

        let pos = file.stream_position()?;

        seek_start!(offset as u64, file);

        fileos(file)?;

        libs.push(
            LibMacM {
                libs: find_macho(file, cpu_type == MacCpu::ARM64 || cpu_type == MacCpu::X86_64, offset as u64)?,
                cpu_type,
            }
        );

        seek_start!(pos+8, file);
    }

    Ok(libs)
}

// -- Mach-O --

pub fn find_macho<T: Read + Seek>(file: &mut T, bits: bool, pos: u64) -> io::Result<Vec<LibMac>>
{
    // Seek to number of load commands
    seek_start!(pos + 16, file);
    let ncmds = read_le_bytes!(file, i32);

    // -- Skip Mach-o header --
    // If 64bits
    file.seek_relative(if bits { 12 } else {8})?;

    let mut libs = Vec::with_capacity(ncmds as usize);

    for _ in 0..ncmds {
        let cmd = read_le_bytes!(file, u32);
        let cmdsize = read_le_bytes!(file, u32) as i64;
        match cmd {
            // LC_LOAD_DYLIB
            0x0000000c | 0x0000000d | 0x00000018 => {
                // Seek to current_version
                file.seek_relative(8)?;
                let mut versions_bytes = [0u8; 8];
                file.read_exact(&mut versions_bytes)?;
                let curr_ver = format!("{}.{}.{}", u32::from_le_bytes([versions_bytes[2], versions_bytes[3], 0, 0]),
                    versions_bytes[1], versions_bytes[0]);
                let compat_ver = format!("{}.{}.{}", u32::from_le_bytes([versions_bytes[6], versions_bytes[7], 0, 0]),
                    versions_bytes[5], versions_bytes[4]);

                let mut path_bytes = vec![0u8; cmdsize as usize - 24];
                file.read_exact(&mut path_bytes)?;
                let mut path = String::with_capacity(cmdsize as usize - 24);
                for byte in path_bytes {
                    if byte.is_ascii() {
                        path.push(byte as char);
                    }
                }

                libs.push(LibMac {
                    cmd: 0x0000000d % cmd as u8,
                    curr_ver,
                    compat_ver,
                    path: path.trim_matches('\0').to_string(),
                });
            }
            // Other load commands
            _ => {
                file.seek_relative(cmdsize - 8)?;
            }
        }
    }

    Ok(libs)
}

// -- ELF --

pub fn find_elf(file: &mut File) -> io::Result<Vec<LibLinux>> {
    let mut elfam = ElfStream::<AnyEndian, &mut File>::open_stream(file).expect("Could not read ELF");
    let mut libs = Vec::new();

    let dynamic_section = elfam.dynamic().expect("Could not read .dynamic section");

    let mut needed = Vec::new();

    // Get DT_NEEDED Dyn's
    if let Some(table) = dynamic_section {
        table.iter().for_each(|lib| if lib.d_tag == DT_NEEDED {needed.push(lib)});
    } else {
        println!("No .dynamic section");
        return Ok(libs);
    }

    let dyn_str = elfam.dynamic_symbol_table().expect("Could not read .dynstr");
    // Get DT_NEEDED Dyn's strings
    if let Some(table) = dyn_str {
        for lib in needed {
            libs.push(
                LibLinux {
                    name: table.1.get(lib.d_val() as usize)
                        .unwrap_or("None").to_string()
                });
        }
    } else {
        println!("No .dynstr section");
    }

    Ok(libs)
}

// -- PE --

/// Gets an RVA and translates it into the actual file location.
fn rva_to_file_offset(bits: bool, number_of_sections: u16, file: &mut File, rva: DWORD) -> io::Result<u32> {
    let curr_pos = file.stream_position()?;

    // Seek to the sections
    seek_start!(
        (size_of::<IMAGE_DOS_HEADER>()
         + if bits { size_of::<IMAGE_NT_HEADERS64>() } else { size_of::<IMAGE_NT_HEADERS32>() }) as u64,
        file
    );

    let mut va = 0;

    for _ in 0..number_of_sections {
        let section_header: IMAGE_SECTION_HEADER = read_struct(file)?;
        if section_header.VirtualAddress <= rva &&
            // SAFETY: The loop iterates over 0..number_of_sections, which if the file is PE valid,
            // VirtualSize should be initialized.
            rva < section_header.VirtualAddress + unsafe { section_header.Misc.VirtualSize } {
            va = rva - section_header.VirtualAddress + section_header.PointerToRawData;
        }

        file.seek_relative(size_of::<IMAGE_SECTION_HEADER>() as i64)?;

    }

    // Return to old position
    seek_start!(curr_pos, file);

    Ok(va)
}

pub fn find_pe(file: &mut File) -> io::Result<Vec<LibWindows>> {
    file.rewind()?;

    let dos_header: IMAGE_DOS_HEADER = read_struct(file)?;

    let image_file_header_size = size_of::<IMAGE_FILE_HEADER>() as u64;
    let dword_size = size_of::<DWORD>() as u64;
    // Seek to NT_HEADERS, skip Signature and FileHeader
    seek_start!(dos_header.e_lfanew as u64 + dword_size + image_file_header_size, file);

    // Read Magic
    let magic = read_le_bytes!(file, IMAGE_OPTIONAL_HEADER_MAGIC);
    // false if 32 bits
    let bits = if magic == 0x10b { false } else if magic == 0x20b { true } else { panic!("Unknown bits") };

    // Seek back to NT_HEADERS
    seek_start!(dos_header.e_lfanew as u64, file);

    let number_of_sections;
    let import_dir_rva;
    if bits {
        let nt_headers: IMAGE_NT_HEADERS64 = read_struct(file)?;
        import_dir_rva = nt_headers.OptionalHeader.DataDirectory[1].VirtualAddress;
        number_of_sections = nt_headers.FileHeader.NumberOfSections;
    } else {
        let nt_headers: IMAGE_NT_HEADERS32 = read_struct(file)?;
        import_dir_rva = nt_headers.OptionalHeader.DataDirectory[1].VirtualAddress;
        number_of_sections = nt_headers.FileHeader.NumberOfSections;
    }

    let dir_entry_import_va = rva_to_file_offset(bits, number_of_sections, file, import_dir_rva)?;
    seek_start!(dir_entry_import_va as u64, file);

    let mut dlls = Vec::new();

    loop {
        let import_descriptor: IMAGE_IMPORT_DESCRIPTOR = read_struct(file)?;
        // We know that the last descriptor is all zeros, so we break before
        if import_descriptor.Name == 0 {
            return Ok(dlls)
        }

        let curr_pos = file.stream_position()?;

        let name_va = rva_to_file_offset(bits, number_of_sections, file, import_descriptor.Name)?;
        seek_start!(name_va as u64, file);

        let name = read_string_from_file(file)?;
        if !name.is_empty() {
            dlls.push(LibWindows { name });
        }

        // After reading the name, we go back to the array
        seek_start!(curr_pos, file);
    }
}
