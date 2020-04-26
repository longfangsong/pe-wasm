extern crate wasm_bindgen;

use goblin::Object;
use wasm_bindgen::prelude::*;
use goblin::pe::header::{Header, DosHeader, CoffHeader};
use goblin::pe::optional_header::{StandardFields, WindowsFields, OptionalHeader};
use goblin::pe::data_directories::{DataDirectory, DataDirectories};
use serde::Serialize;
use goblin::pe::section_table::SectionTable;
use std::str::from_utf8;

#[wasm_bindgen]
#[derive(Copy, Clone)]
pub struct DosHeaderExport {
    pub signature: u16,
    pub pe_pointer: u32,
}

impl From<DosHeader> for DosHeaderExport {
    fn from(raw: DosHeader) -> Self {
        Self {
            signature: raw.signature,
            pe_pointer: raw.pe_pointer,
        }
    }
}

#[wasm_bindgen]
#[derive(Copy, Clone)]
pub struct CoffHeaderExport {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbol_table: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

impl From<CoffHeader> for CoffHeaderExport {
    fn from(raw: CoffHeader) -> Self {
        CoffHeaderExport {
            machine: raw.machine,
            number_of_sections: raw.number_of_sections,
            time_date_stamp: raw.time_date_stamp,
            pointer_to_symbol_table: raw.pointer_to_symbol_table,
            number_of_symbol_table: raw.number_of_symbol_table,
            size_of_optional_header: raw.size_of_optional_header,
            characteristics: raw.characteristics,
        }
    }
}

#[wasm_bindgen]
#[derive(Copy, Clone)]
pub struct StandardFieldsExport {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u64,
    pub size_of_initialized_data: u64,
    pub size_of_uninitialized_data: u64,
    pub address_of_entry_point: u64,
    pub base_of_code: u64,
    pub base_of_data: u32,
}

impl From<StandardFields> for StandardFieldsExport {
    fn from(raw: StandardFields) -> Self {
        Self {
            magic: raw.magic,
            major_linker_version: raw.major_linker_version,
            minor_linker_version: raw.minor_linker_version,
            size_of_code: raw.size_of_code,
            size_of_initialized_data: raw.size_of_initialized_data,
            size_of_uninitialized_data: raw.size_of_uninitialized_data,
            address_of_entry_point: raw.address_of_entry_point,
            base_of_code: raw.base_of_code,
            base_of_data: raw.base_of_data,
        }
    }
}

#[wasm_bindgen]
#[derive(Copy, Clone)]
pub struct WindowsFieldsExport {
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

impl From<WindowsFields> for WindowsFieldsExport {
    fn from(raw: WindowsFields) -> Self {
        Self {
            image_base: raw.image_base,
            section_alignment: raw.section_alignment,
            file_alignment: raw.file_alignment,
            major_operating_system_version: raw.major_image_version,
            minor_operating_system_version: raw.minor_operating_system_version,
            major_image_version: raw.major_image_version,
            minor_image_version: raw.minor_image_version,
            major_subsystem_version: raw.major_subsystem_version,
            minor_subsystem_version: raw.minor_subsystem_version,
            win32_version_value: raw.win32_version_value,
            size_of_image: raw.size_of_image,
            size_of_headers: raw.size_of_headers,
            check_sum: raw.check_sum,
            subsystem: raw.subsystem,
            dll_characteristics: raw.dll_characteristics,
            size_of_stack_reserve: raw.size_of_stack_reserve,
            size_of_stack_commit: raw.size_of_stack_commit,
            size_of_heap_reserve: raw.size_of_heap_reserve,
            size_of_heap_commit: raw.size_of_heap_commit,
            loader_flags: raw.loader_flags,
            number_of_rva_and_sizes: raw.number_of_rva_and_sizes,
        }
    }
}

#[wasm_bindgen]
#[derive(Copy, Clone)]
pub struct DataDirectoryExport {
    pub virtual_address: u32,
    pub size: u32,
}

impl From<DataDirectory> for DataDirectoryExport {
    fn from(raw: DataDirectory) -> Self {
        Self {
            virtual_address: raw.virtual_address,
            size: raw.size,
        }
    }
}

#[wasm_bindgen]
#[derive(Copy, Clone)]
pub struct DataDirectoriesExport {
    pub data_directories0: Option<DataDirectoryExport>,
    pub data_directories1: Option<DataDirectoryExport>,
    pub data_directories2: Option<DataDirectoryExport>,
    pub data_directories3: Option<DataDirectoryExport>,
    pub data_directories4: Option<DataDirectoryExport>,
    pub data_directories5: Option<DataDirectoryExport>,
    pub data_directories6: Option<DataDirectoryExport>,
    pub data_directories7: Option<DataDirectoryExport>,
    pub data_directories8: Option<DataDirectoryExport>,
    pub data_directories9: Option<DataDirectoryExport>,
    pub data_directories10: Option<DataDirectoryExport>,
    pub data_directories11: Option<DataDirectoryExport>,
    pub data_directories12: Option<DataDirectoryExport>,
    pub data_directories13: Option<DataDirectoryExport>,
    pub data_directories14: Option<DataDirectoryExport>,
    pub data_directories15: Option<DataDirectoryExport>,
}

impl From<DataDirectories> for DataDirectoriesExport {
    fn from(raw: DataDirectories) -> Self {
        Self {
            data_directories0: raw.data_directories[0].map(|it| it.into()),
            data_directories1: raw.data_directories[1].map(|it| it.into()),
            data_directories2: raw.data_directories[2].map(|it| it.into()),
            data_directories3: raw.data_directories[3].map(|it| it.into()),
            data_directories4: raw.data_directories[4].map(|it| it.into()),
            data_directories5: raw.data_directories[5].map(|it| it.into()),
            data_directories6: raw.data_directories[6].map(|it| it.into()),
            data_directories7: raw.data_directories[7].map(|it| it.into()),
            data_directories8: raw.data_directories[8].map(|it| it.into()),
            data_directories9: raw.data_directories[9].map(|it| it.into()),
            data_directories10: raw.data_directories[10].map(|it| it.into()),
            data_directories11: raw.data_directories[11].map(|it| it.into()),
            data_directories12: raw.data_directories[12].map(|it| it.into()),
            data_directories13: raw.data_directories[13].map(|it| it.into()),
            data_directories14: raw.data_directories[14].map(|it| it.into()),
            data_directories15: raw.data_directories[15].map(|it| it.into()),
        }
    }
}

#[wasm_bindgen]
#[derive(Copy, Clone)]
pub struct OptionalHeaderExport {
    pub standard_fields: StandardFieldsExport,
    pub windows_fields: WindowsFieldsExport,
    pub data_directories: DataDirectoriesExport,
}

impl From<OptionalHeader> for OptionalHeaderExport {
    fn from(raw: OptionalHeader) -> Self {
        Self {
            standard_fields: raw.standard_fields.into(),
            windows_fields: raw.windows_fields.into(),
            data_directories: raw.data_directories.into(),
        }
    }
}

pub struct WindowsHeaderExport {
    // pub sections: Vec<section_table::SectionTable>,
    /// The size of the binary
    pub size: usize,
    /// The name of this `dll`, if it has one
    pub name: Option<String>,
    /// Whether this is a `dll` or not
    pub is_lib: bool,
    /// Whether the binary is 64-bit (PE32+)
    pub is_64: bool,
    /// the entry point of the binary
    pub entry: usize,
    /// The binary's RVA, or image base - useful for computing virtual addreses
    pub image_base: usize,
}

#[derive(Serialize)]
pub struct SectionTableExport {
    pub name: String,
    pub real_name: Option<String>,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

impl From<SectionTable> for SectionTableExport {
    fn from(raw: SectionTable) -> Self {
        Self {
            name: from_utf8(&raw.name).unwrap().to_string(),
            real_name: raw.real_name,
            virtual_size: raw.virtual_address,
            virtual_address: raw.virtual_address,
            size_of_raw_data: raw.size_of_raw_data,
            pointer_to_raw_data: raw.pointer_to_raw_data,
            pointer_to_relocations: raw.pointer_to_relocations,
            pointer_to_linenumbers: raw.pointer_to_linenumbers,
            number_of_relocations: raw.number_of_relocations,
            number_of_linenumbers: raw.number_of_linenumbers,
            characteristics: raw.characteristics,
        }
    }
}

#[wasm_bindgen]
pub struct HeaderExport {
    pub dos_header: DosHeaderExport,
    pub signature: u32,
    pub coff_header: CoffHeaderExport,
    pub optional_header: Option<OptionalHeaderExport>,
}

impl From<Header> for HeaderExport {
    fn from(raw: Header) -> Self {
        Self {
            dos_header: raw.dos_header.into(),
            signature: raw.signature,
            coff_header: raw.coff_header.into(),
            optional_header: raw.optional_header.map(|it| it.into()),
        }
    }
}

#[wasm_bindgen]
pub fn parse_pe(bytes: &[u8]) -> Option<HeaderExport> {
    if let Ok(Object::PE(pe)) = Object::parse(&bytes) {
        Some(HeaderExport::from(pe.header.into()))
    } else {
        None
    }
}

#[wasm_bindgen]
pub fn get_sections(bytes: &[u8]) -> Option<String> {
    if let Ok(Object::PE(pe)) = Object::parse(&bytes) {
        let exported: Vec<SectionTableExport> =
            pe.sections.iter().map(|it| it.clone().into()).collect();
        serde_json::to_string(&exported).ok()
    } else {
        None
    }
}

