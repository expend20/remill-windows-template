#pragma once

#include <cstdint>

#if __has_include(<optional>)
#include <optional>
#else
#include <experimental/optional>
namespace std {
using experimental::optional;
using experimental::nullopt;
}
#endif

#include "utils/pe_reader.h"

namespace lifting {

class MemoryProvider {
public:
    virtual ~MemoryProvider() = default;
    virtual std::optional<uint64_t> ReadMemory(uint64_t address, unsigned size) const = 0;
};

class PEMemoryProvider : public MemoryProvider {
public:
    explicit PEMemoryProvider(const utils::PEInfo& pe_info);
    std::optional<uint64_t> ReadMemory(uint64_t address, unsigned size) const override;

private:
    const utils::PEInfo& pe_info_;
};

}  // namespace lifting
