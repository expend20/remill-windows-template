#include "utils/pe_reader.h"

#include <cstring>
#include <fstream>
#include <iostream>

namespace utils {

namespace {

std::optional<std::vector<uint8_t>> ReadFile(const std::string &filepath) {
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file) {
        std::cerr << "Failed to open file: " << filepath << "\n";
        return std::nullopt;
    }

    auto size = file.tellg();
    if (size < static_cast<std::streamoff>(sizeof(DOSHeader))) {
        std::cerr << "File too small for DOS header\n";
        return std::nullopt;
    }

    std::vector<uint8_t> data(static_cast<size_t>(size));
    file.seekg(0);
    file.read(reinterpret_cast<char *>(data.data()), size);

    return data;
}

std::optional<TextSectionInfo>
ParsePE64TextSection(const std::vector<uint8_t> &pe_data) {
    if (pe_data.size() < sizeof(DOSHeader)) {
        std::cerr << "PE data too small for DOS header\n";
        return std::nullopt;
    }

    const auto *dos = reinterpret_cast<const DOSHeader *>(pe_data.data());
    if (dos->e_magic != DOS_SIGNATURE) {
        std::cerr << "Invalid DOS signature\n";
        return std::nullopt;
    }

    if (dos->e_lfanew + sizeof(uint32_t) + sizeof(COFFHeader) > pe_data.size()) {
        std::cerr << "PE offset out of bounds\n";
        return std::nullopt;
    }

    const uint32_t *pe_sig =
        reinterpret_cast<const uint32_t *>(pe_data.data() + dos->e_lfanew);
    if (*pe_sig != PE_SIGNATURE) {
        std::cerr << "Invalid PE signature\n";
        return std::nullopt;
    }

    const auto *coff = reinterpret_cast<const COFFHeader *>(
        pe_data.data() + dos->e_lfanew + sizeof(uint32_t));

    if (coff->Machine != MACHINE_AMD64) {
        std::cerr << "Not an AMD64 PE file\n";
        return std::nullopt;
    }

    const auto *opt = reinterpret_cast<const OptionalHeader64 *>(
        pe_data.data() + dos->e_lfanew + sizeof(uint32_t) + sizeof(COFFHeader));

    if (opt->Magic != PE32PLUS_MAGIC) {
        std::cerr << "Not a PE32+ (64-bit) file\n";
        return std::nullopt;
    }

    size_t sections_offset = dos->e_lfanew + sizeof(uint32_t) +
                             sizeof(COFFHeader) + coff->SizeOfOptionalHeader;

    for (uint16_t i = 0; i < coff->NumberOfSections; ++i) {
        size_t header_offset = sections_offset + i * sizeof(SectionHeader);
        if (header_offset + sizeof(SectionHeader) > pe_data.size()) {
            std::cerr << "Section header out of bounds\n";
            return std::nullopt;
        }

        const auto *section = reinterpret_cast<const SectionHeader *>(
            pe_data.data() + header_offset);

        if (std::strncmp(section->Name, ".text", 8) == 0) {
            // Use VirtualSize (actual code size) not SizeOfRawData (file-aligned)
            uint32_t code_size = section->VirtualSize;
            if (code_size == 0 || code_size > section->SizeOfRawData) {
                code_size = section->SizeOfRawData;
            }

            if (section->PointerToRawData + code_size > pe_data.size()) {
                std::cerr << ".text section data out of bounds\n";
                return std::nullopt;
            }

            TextSectionInfo info;
            info.bytes.assign(
                pe_data.begin() + section->PointerToRawData,
                pe_data.begin() + section->PointerToRawData + code_size);
            info.virtual_address = section->VirtualAddress;
            info.image_base = opt->ImageBase;

            return info;
        }
    }

    std::cerr << ".text section not found\n";
    return std::nullopt;
}

// Helper to read null-terminated string from PE data at given RVA
std::optional<std::string> ReadStringAtRVA(const std::vector<uint8_t>& pe_data,
                                           const std::vector<SectionInfo>& sections,
                                           uint64_t image_base,
                                           uint32_t rva) {
    // Find section containing the RVA
    for (const auto& sec : sections) {
        if (rva >= sec.virtual_address && rva < sec.virtual_address + sec.size) {
            uint64_t offset = rva - sec.virtual_address;
            std::string result;
            while (offset < sec.bytes.size()) {
                char c = static_cast<char>(sec.bytes[offset]);
                if (c == '\0') break;
                result += c;
                offset++;
            }
            return result;
        }
    }
    return std::nullopt;
}

// Parse import table and populate imports vector
void ParseImportTable(PEInfo& info, const std::vector<uint8_t>& pe_data,
                      const OptionalHeader64* opt) {
    // Check if import directory exists
    if (opt->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT) {
        return;  // No import directory
    }

    const auto& import_dir = opt->DataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.VirtualAddress == 0 || import_dir.Size == 0) {
        return;  // No imports
    }

    uint32_t import_rva = import_dir.VirtualAddress;

    // Find section containing import descriptors
    const SectionInfo* import_section = nullptr;
    for (const auto& sec : info.sections) {
        if (import_rva >= sec.virtual_address &&
            import_rva < sec.virtual_address + sec.size) {
            import_section = &sec;
            break;
        }
    }

    if (!import_section) {
        return;  // Import directory not in any loaded section
    }

    // Iterate through import descriptors
    uint64_t desc_offset = import_rva - import_section->virtual_address;
    while (desc_offset + sizeof(ImportDescriptor) <= import_section->bytes.size()) {
        ImportDescriptor desc;
        std::memcpy(&desc, import_section->bytes.data() + desc_offset, sizeof(desc));

        // Check for null terminator (all zeros)
        if (desc.OriginalFirstThunk == 0 && desc.FirstThunk == 0 && desc.Name == 0) {
            break;
        }

        // Read DLL name
        auto dll_name = ReadStringAtRVA(pe_data, info.sections, info.image_base, desc.Name);
        if (!dll_name) {
            desc_offset += sizeof(ImportDescriptor);
            continue;
        }

        // Use OriginalFirstThunk (ILT) if available, otherwise FirstThunk (IAT)
        uint32_t thunk_rva = desc.OriginalFirstThunk ? desc.OriginalFirstThunk : desc.FirstThunk;
        uint32_t iat_rva = desc.FirstThunk;

        // Find section containing thunks
        const SectionInfo* thunk_section = nullptr;
        for (const auto& sec : info.sections) {
            if (thunk_rva >= sec.virtual_address &&
                thunk_rva < sec.virtual_address + sec.size) {
                thunk_section = &sec;
                break;
            }
        }

        if (!thunk_section) {
            desc_offset += sizeof(ImportDescriptor);
            continue;
        }

        // Iterate through thunk entries (64-bit pointers)
        uint64_t thunk_offset = thunk_rva - thunk_section->virtual_address;
        uint32_t iat_entry_rva = iat_rva;

        while (thunk_offset + 8 <= thunk_section->bytes.size()) {
            uint64_t thunk_value;
            std::memcpy(&thunk_value, thunk_section->bytes.data() + thunk_offset, 8);

            if (thunk_value == 0) {
                break;  // End of thunk array
            }

            ImportEntry entry;
            entry.dll_name = *dll_name;
            entry.iat_va = info.image_base + iat_entry_rva;

            if (thunk_value & IMAGE_ORDINAL_FLAG64) {
                // Import by ordinal
                entry.is_ordinal = true;
                entry.ordinal = static_cast<uint16_t>(thunk_value & 0xFFFF);
                entry.function_name = "";
            } else {
                // Import by name - thunk_value is RVA to IMAGE_IMPORT_BY_NAME
                entry.is_ordinal = false;
                entry.ordinal = 0;
                uint32_t name_rva = static_cast<uint32_t>(thunk_value);
                // Skip 2-byte hint and read name
                auto func_name = ReadStringAtRVA(pe_data, info.sections, info.image_base,
                                                  name_rva + 2);
                entry.function_name = func_name.value_or("");
            }

            info.imports.push_back(std::move(entry));

            thunk_offset += 8;
            iat_entry_rva += 8;
        }

        desc_offset += sizeof(ImportDescriptor);
    }
}

std::optional<PEInfo> ParsePE64(const std::vector<uint8_t> &pe_data) {
    if (pe_data.size() < sizeof(DOSHeader)) {
        std::cerr << "PE data too small for DOS header\n";
        return std::nullopt;
    }

    const auto *dos = reinterpret_cast<const DOSHeader *>(pe_data.data());
    if (dos->e_magic != DOS_SIGNATURE) {
        std::cerr << "Invalid DOS signature\n";
        return std::nullopt;
    }

    if (dos->e_lfanew + sizeof(uint32_t) + sizeof(COFFHeader) > pe_data.size()) {
        std::cerr << "PE offset out of bounds\n";
        return std::nullopt;
    }

    const uint32_t *pe_sig =
        reinterpret_cast<const uint32_t *>(pe_data.data() + dos->e_lfanew);
    if (*pe_sig != PE_SIGNATURE) {
        std::cerr << "Invalid PE signature\n";
        return std::nullopt;
    }

    const auto *coff = reinterpret_cast<const COFFHeader *>(
        pe_data.data() + dos->e_lfanew + sizeof(uint32_t));

    if (coff->Machine != MACHINE_AMD64) {
        std::cerr << "Not an AMD64 PE file\n";
        return std::nullopt;
    }

    const auto *opt = reinterpret_cast<const OptionalHeader64 *>(
        pe_data.data() + dos->e_lfanew + sizeof(uint32_t) + sizeof(COFFHeader));

    if (opt->Magic != PE32PLUS_MAGIC) {
        std::cerr << "Not a PE32+ (64-bit) file\n";
        return std::nullopt;
    }

    PEInfo info;
    info.image_base = opt->ImageBase;
    info.entry_point_rva = opt->AddressOfEntryPoint;

    size_t sections_offset = dos->e_lfanew + sizeof(uint32_t) +
                             sizeof(COFFHeader) + coff->SizeOfOptionalHeader;

    for (uint16_t i = 0; i < coff->NumberOfSections; ++i) {
        size_t header_offset = sections_offset + i * sizeof(SectionHeader);
        if (header_offset + sizeof(SectionHeader) > pe_data.size()) {
            std::cerr << "Section header out of bounds\n";
            return std::nullopt;
        }

        const auto *section = reinterpret_cast<const SectionHeader *>(
            pe_data.data() + header_offset);

        // Only read sections that are readable
        if (!(section->Characteristics & IMAGE_SCN_MEM_READ)) {
            continue;
        }

        SectionInfo sec_info;
        sec_info.name = std::string(section->Name, strnlen(section->Name, 8));
        sec_info.virtual_address = section->VirtualAddress;
        sec_info.characteristics = section->Characteristics;

        // Determine actual size
        uint32_t data_size = section->VirtualSize;
        if (data_size == 0 || data_size > section->SizeOfRawData) {
            data_size = section->SizeOfRawData;
        }
        sec_info.size = data_size;

        // Copy section data
        if (section->PointerToRawData + data_size > pe_data.size()) {
            std::cerr << "Section " << sec_info.name << " data out of bounds\n";
            return std::nullopt;
        }

        sec_info.bytes.assign(
            pe_data.begin() + section->PointerToRawData,
            pe_data.begin() + section->PointerToRawData + data_size);

        info.sections.push_back(std::move(sec_info));
    }

    // Parse import table
    ParseImportTable(info, pe_data, opt);

    return info;
}

}  // namespace

const SectionInfo* PEInfo::FindSection(const std::string& name) const {
    for (const auto& sec : sections) {
        if (sec.name == name) {
            return &sec;
        }
    }
    return nullptr;
}

const SectionInfo* PEInfo::FindSectionContaining(uint64_t va) const {
    // va is absolute virtual address, convert to RVA
    if (va < image_base) {
        return nullptr;
    }
    uint64_t rva = va - image_base;

    for (const auto& sec : sections) {
        if (rva >= sec.virtual_address && rva < sec.virtual_address + sec.size) {
            return &sec;
        }
    }
    return nullptr;
}

std::optional<uint8_t> PEInfo::ReadByte(uint64_t va) const {
    const auto* sec = FindSectionContaining(va);
    if (!sec) {
        return std::nullopt;
    }
    uint64_t offset = (va - image_base) - sec->virtual_address;
    if (offset >= sec->bytes.size()) {
        return std::nullopt;
    }
    return sec->bytes[offset];
}

std::optional<uint32_t> PEInfo::ReadDword(uint64_t va) const {
    const auto* sec = FindSectionContaining(va);
    if (!sec) {
        return std::nullopt;
    }
    uint64_t offset = (va - image_base) - sec->virtual_address;
    if (offset + 4 > sec->bytes.size()) {
        return std::nullopt;
    }
    uint32_t value;
    std::memcpy(&value, sec->bytes.data() + offset, sizeof(value));
    return value;
}

std::optional<uint64_t> PEInfo::ReadQword(uint64_t va) const {
    const auto* sec = FindSectionContaining(va);
    if (!sec) {
        return std::nullopt;
    }
    uint64_t offset = (va - image_base) - sec->virtual_address;
    if (offset + 8 > sec->bytes.size()) {
        return std::nullopt;
    }
    uint64_t value;
    std::memcpy(&value, sec->bytes.data() + offset, sizeof(value));
    return value;
}

const ImportEntry* PEInfo::FindImportByIATAddress(uint64_t va) const {
    for (const auto& import : imports) {
        if (import.iat_va == va) {
            return &import;
        }
    }
    return nullptr;
}

std::optional<std::string> PEInfo::ReadNullTerminatedString(uint64_t va) const {
    const auto* sec = FindSectionContaining(va);
    if (!sec) {
        return std::nullopt;
    }
    uint64_t offset = (va - image_base) - sec->virtual_address;
    std::string result;
    while (offset < sec->bytes.size()) {
        char c = static_cast<char>(sec->bytes[offset]);
        if (c == '\0') break;
        result += c;
        offset++;
    }
    return result;
}

std::optional<PEInfo> ReadPE(const std::string& filepath) {
    auto pe_data = ReadFile(filepath);
    if (!pe_data) {
        return std::nullopt;
    }
    return ParsePE64(*pe_data);
}

std::optional<TextSectionInfo> ReadTextSection(const std::string &filepath) {
    auto pe_data = ReadFile(filepath);
    if (!pe_data) {
        return std::nullopt;
    }
    return ParsePE64TextSection(*pe_data);
}

}  // namespace utils
