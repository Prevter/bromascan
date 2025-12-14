#include "scanpat.hpp"

#include <fstream>

#include <sinaps.hpp>
#include <ThreadPool.hpp>
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

        GEODE_UNWRAP(this->readPatternsFile());
        if (m_verbose) {
            fmt::println("Target platform: {}", m_platformType);
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

        GEODE_UNWRAP(this->performScan());

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

    Result<> Scanner::readPatternsFile() {
        std::ifstream file(m_patternsFile);
        if (!file.is_open()) {
            return Err(fmt::format("Failed to open patterns file: {}", m_patternsFile));
        }

        auto jsonData = nlohmann::json::parse(file, nullptr, false);
        if (jsonData.is_discarded()) {
            return Err(fmt::format("Failed to parse patterns file: {}", m_patternsFile));
        }

        auto& classes = jsonData["classes"];
        m_classBindings.reserve(classes.size());

        try {
            for (auto& jsonClass : classes) {
                m_classBindings.emplace_back(jsonClass.get<ClassBinding>());
            }
        } catch (std::exception& e) {
            return Err(fmt::format("Failed to deserialize patterns file: {}: {}", m_patternsFile, e.what()));
        }

        if (m_verbose) {
            fmt::println("Loaded {} class bindings from patterns file: {}",
                m_classBindings.size(),
                m_patternsFile
            );
        }

        auto platformStr = jsonData["platform"].get<std::string_view>();
        if (platformStr == "Windows") {
            m_platformType = Platform::WIN;
        } else if (platformStr == "iMac") {
            m_platformType = Platform::IMAC;
        } else if (platformStr == "M1") {
            m_platformType = Platform::M1;
        } else if (platformStr == "iOS") {
            m_platformType = Platform::IOS;
        } else {
            return Err(fmt::format("Unsupported platform in patterns file: {}", platformStr));
        }

        return Ok();
    }

    Result<> Scanner::performScan() {
        utils::ThreadPool pool{};

        size_t stepSize = 4; // default align to 4 bytes
        if (m_platformType == Platform::WIN || m_platformType == Platform::IMAC) {
            stepSize = 16; // align to 16 bytes for x86_64
        }

        for (auto& classBinding : m_classBindings) {
            if (classBinding.methods.empty()) continue; // skip empty classes to save on thread
            pool.enqueue([this, &classBinding, stepSize]() {
                for (auto& methodBinding : classBinding.methods) {
                    if (!methodBinding.pattern.has_value()) {
                        continue; // skip methods without patterns
                    }

                    auto& patternStr = methodBinding.pattern.value();
                    fmt::println("Scanning for method: {}::{} with pattern: {}",
                        classBinding.name,
                        methodBinding.method.name,
                        patternStr
                    );

                    auto patStr = sinaps::impl::tokenizePatternStringRuntime(patternStr);
                    auto patStrNew = sinaps::to_string(patStr);
                    if (patStrNew != patternStr) {
                        fmt::println("Warning: Pattern string normalization changed:");
                        fmt::println("  Original:   {}", patternStr);
                        fmt::println("  Normalized: {}", patStrNew);
                    }

                    auto res = sinaps::find(
                        m_targetSegment.data(),
                        m_targetSegment.size(),
                        patternStr,
                        stepSize
                    );

                    if (res != sinaps::not_found) {
                        auto address = res + m_baseCorrection;
                        fmt::println("Found method: {}::{} at address: 0x{:X}",
                            classBinding.name,
                            methodBinding.method.name,
                            address
                        );
                    } else {
                        fmt::println("Method not found: {}::{}",
                            classBinding.name,
                            methodBinding.method.name
                        );
                    }

                    break;
                }
            });
            break;
        }

        pool.waitAll();
        return Ok();
    }
}
