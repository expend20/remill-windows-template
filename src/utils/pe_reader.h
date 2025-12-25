#pragma once

#include <cstdint>
#include <string>
#include <vector>

#if __has_include(<optional>)
#include <optional>
#else
#include <experimental/optional>
namespace std {
using experimental::optional;
using experimental::nullopt;
}
#endif

namespace utils {

#pragma pack(push, 1)

struct DOSHeader {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
};

struct COFFHeader {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct OptionalHeader64 {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
};

struct SectionHeader {
    char Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

#pragma pack(pop)

constexpr uint16_t DOS_SIGNATURE = 0x5A4D;
constexpr uint32_t PE_SIGNATURE = 0x00004550;
constexpr uint16_t MACHINE_AMD64 = 0x8664;
constexpr uint16_t PE32PLUS_MAGIC = 0x20B;

struct TextSectionInfo {
    std::vector<uint8_t> bytes;
    uint64_t virtual_address;
    uint64_t image_base;
};

// Section characteristics flags
constexpr uint32_t IMAGE_SCN_MEM_READ = 0x40000000;
constexpr uint32_t IMAGE_SCN_MEM_WRITE = 0x80000000;
constexpr uint32_t IMAGE_SCN_MEM_EXECUTE = 0x20000000;

struct SectionInfo {
    std::string name;
    std::vector<uint8_t> bytes;
    uint64_t virtual_address;  // RVA
    uint64_t size;
    uint32_t characteristics;

    bool IsReadable() const { return characteristics & IMAGE_SCN_MEM_READ; }
    bool IsWritable() const { return characteristics & IMAGE_SCN_MEM_WRITE; }
    bool IsExecutable() const { return characteristics & IMAGE_SCN_MEM_EXECUTE; }
};

struct PEInfo {
    std::vector<SectionInfo> sections;
    uint64_t image_base;
    uint64_t entry_point_rva;

    const SectionInfo* FindSection(const std::string& name) const;
    const SectionInfo* FindSectionContaining(uint64_t va) const;
    std::optional<uint8_t> ReadByte(uint64_t va) const;
    std::optional<uint32_t> ReadDword(uint64_t va) const;
    std::optional<uint64_t> ReadQword(uint64_t va) const;
};

std::optional<PEInfo> ReadPE(const std::string& filepath);

std::optional<TextSectionInfo> ReadTextSection(const std::string &filepath);

}  // namespace utils
