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
            if (section->PointerToRawData + section->SizeOfRawData >
                pe_data.size()) {
                std::cerr << ".text section data out of bounds\n";
                return std::nullopt;
            }

            TextSectionInfo info;
            info.bytes.assign(
                pe_data.begin() + section->PointerToRawData,
                pe_data.begin() + section->PointerToRawData +
                    section->SizeOfRawData);
            info.virtual_address = section->VirtualAddress;
            info.image_base = opt->ImageBase;

            return info;
        }
    }

    std::cerr << ".text section not found\n";
    return std::nullopt;
}

}  // namespace

std::optional<TextSectionInfo> ReadTextSection(const std::string &filepath) {
    auto pe_data = ReadFile(filepath);
    if (!pe_data) {
        return std::nullopt;
    }
    return ParsePE64TextSection(*pe_data);
}

}  // namespace utils
