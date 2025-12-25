#include "lifting/memory_provider.h"

namespace lifting {

PEMemoryProvider::PEMemoryProvider(const utils::PEInfo& pe_info)
    : pe_info_(pe_info) {}

std::optional<uint64_t> PEMemoryProvider::ReadMemory(uint64_t address, unsigned size) const {
    switch (size) {
        case 1: {
            auto val = pe_info_.ReadByte(address);
            if (val) return static_cast<uint64_t>(*val);
            return std::nullopt;
        }
        case 2: {
            // Read two bytes and combine
            auto b0 = pe_info_.ReadByte(address);
            auto b1 = pe_info_.ReadByte(address + 1);
            if (b0 && b1) {
                return static_cast<uint64_t>(*b0) | (static_cast<uint64_t>(*b1) << 8);
            }
            return std::nullopt;
        }
        case 4: {
            auto val = pe_info_.ReadDword(address);
            if (val) return static_cast<uint64_t>(*val);
            return std::nullopt;
        }
        case 8: {
            auto val = pe_info_.ReadQword(address);
            if (val) return *val;
            return std::nullopt;
        }
        default:
            return std::nullopt;
    }
}

}  // namespace lifting
