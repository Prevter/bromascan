#include "Mach-O.hpp"

namespace bin::mach {
    geode::Result<std::span<uint8_t const>> getSegment(std::span<uint8_t const> binaryData, CPUType type) {
        auto magic = *reinterpret_cast<uint32_t const*>(binaryData.data());

        if (magic == MH_MAGIC_64) {
            auto header64 = reinterpret_cast<mach_header_64 const*>(binaryData.data());
            size_t offset = sizeof(mach_header_64) + header64->sizeofcmds;
            if (offset > binaryData.size()) {
                return geode::Err("Invalid Mach-O 64-bit header size");
            }
            return geode::Ok(binaryData.subspan(offset));
        }

        if (magic == FAT_MAGIC) {
            auto fatHeader = reinterpret_cast<fat_header const*>(binaryData.data());
            auto fatArches = reinterpret_cast<fat_arch const*>(binaryData.data() + sizeof(fat_header));
            for (uint32_t i = 0; i < fatHeader->get_nfat_arch(); ++i) {
                if (fatArches[i].get_cputype() == static_cast<cpu_type_t>(type)) {
                    size_t offset = fatArches[i].get_offset();
                    size_t size = fatArches[i].get_size();
                    if (offset + size > binaryData.size()) {
                        return geode::Err("Invalid fat binary architecture size");
                    }
                    return geode::Ok(binaryData.subspan(offset, size));
                }
            }
            return geode::Err("Specified CPU type not found in fat binary");
        }

        return geode::Err("Unsupported Mach-O format");
    }

    bool isFatBinary(std::span<uint8_t const> binaryData) {
        if (binaryData.size() < sizeof(fat_header)) {
            return false;
        }

        auto magic = *reinterpret_cast<uint32_t const*>(binaryData.data());
        return magic == FAT_MAGIC;
    }

    bool isMachO64(std::span<uint8_t const> binaryData) {
        if (binaryData.size() < sizeof(mach_header_64)) {
            return false;
        }

        auto magic = *reinterpret_cast<uint32_t const*>(binaryData.data());
        return magic == MH_MAGIC_64;
    }
}
