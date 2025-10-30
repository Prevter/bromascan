#include "scanpat.hpp"

#include <fstream>

#include <binaries/Mach-O.hpp>
#include <binaries/PE.hpp>
#include <fmt/format.h>

using namespace geode;

namespace scanpat {
    Result<> Scanner::scan() {
        GEODE_UNWRAP(this->readBinaryFile());
        if (m_verbose) {
            fmt::println("Read binary file: {} ({} bytes)", m_binaryFile, m_binaryData.size());
        }

        GEODE_UNWRAP_INTO(m_platformType, this->resolvePlatform());
        if (m_verbose) {
            fmt::println("Resolved platform: {}", m_platformType);
        }

        switch (m_platformType) {
            case Platform::M1: {
                GEODE_UNWRAP_INTO(m_targetSegment, bin::mach::getSegment(m_binaryData, bin::mach::CPUType::ARM64));
                break;
            }
            case Platform::IMAC: {
                GEODE_UNWRAP_INTO(m_targetSegment, bin::mach::getSegment(m_binaryData, bin::mach::CPUType::X86_64));
                break;
            }
            case Platform::WIN: {
                GEODE_UNWRAP_INTO(auto virtSection, bin::pe::getSection(m_binaryData));
                m_targetSegment = virtSection.data;
                m_baseCorrection = virtSection.virtualAddress;
                break;
            }
            case Platform::IOS: {
                GEODE_UNWRAP_INTO(m_targetSegment, bin::mach::getSegment(m_binaryData, bin::mach::CPUType::ARM64));
                auto segmentStart = reinterpret_cast<uintptr_t>(m_targetSegment.data());
                auto dataStart = reinterpret_cast<uintptr_t>(m_binaryData.data());
                m_baseCorrection = segmentStart - dataStart;
                break;
            }
            default:
                return Err("Unsupported platform");
        }

        if (m_verbose) {
            fmt::println("Extracted target segment (start: {}, size: {})",
                reinterpret_cast<uintptr_t>(m_targetSegment.data()) - reinterpret_cast<uintptr_t>(m_binaryData.data()),
                m_targetSegment.size()
            );
        }

        return Ok();
    }

    Result<> Scanner::readBinaryFile() {
        std::ifstream file(m_binaryFile, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            return Err(fmt::format("Failed to open file: {}", m_binaryFile));
        }

        auto size = file.tellg();
        file.seekg(0, std::ios::beg);
        m_binaryData.resize(size);

        if (!file.read(reinterpret_cast<char*>(m_binaryData.data()), size)) {
            return Err(fmt::format("Failed to read file: {}", m_binaryFile));
        }

        return Ok();
    }

    Result<Platform> Scanner::resolvePlatform() {
        if (m_platform == "auto") {
            if (bin::pe::isPE64(m_binaryData)) {
                return Ok(Platform::WIN);
            }

            if (bin::mach::isFatBinary(m_binaryData)) {
                return Ok(Platform::M1); // leave intel mac as explicit option
            }

            if (bin::mach::isMachO64(m_binaryData)) {
                return Ok(Platform::IOS);
            }

            return Err("Failed to auto-detect platform from binary");
        }
        if (m_platform == "m1") {
            return Ok(Platform::M1);
        }
        if (m_platform == "imac") {
            return Ok(Platform::IMAC);
        }
        if (m_platform == "win") {
            return Ok(Platform::WIN);
        }
        if (m_platform == "ios") {
            return Ok(Platform::IOS);
        }
        return Err(fmt::format("Unknown platform: {}", m_platform));
    }
}
