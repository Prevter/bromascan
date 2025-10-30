#include "genpat.hpp"

#include <fstream>
#include <ThreadPool.hpp>
#include <fmt/format.h>

#include <tools.hpp>
#include <binaries/Mach-O.hpp>
#include <binaries/PE.hpp>
#include <broma/Reader.hpp>

#include <nlohmann/json.hpp>

#include "asm/aarch64.hpp"
#include "asm/amd64.hpp"

namespace genpat {
    Result<Platform> Generator::resolvePlatform() {
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

    Result<> Generator::savePatternFile() {
        nlohmann::json jsonData;
        jsonData["platform"] = format_as(m_platformType);
        jsonData["classes"] = nlohmann::json::array();

        for (auto const& classBinding : m_classBindings) {
            auto& jsonClass = jsonData["classes"].emplace_back();
            jsonClass["name"] = classBinding.name;
            jsonClass["functions"] = nlohmann::json::array();

            for (auto const& methodBinding : classBinding.methods) {
                auto& jsonMethod = jsonClass["functions"].emplace_back();

                jsonMethod["name"] = methodBinding.method.name;
                jsonMethod["return"] = methodBinding.method.returnType;

                jsonMethod["args"] = nlohmann::json::array();
                for (auto const& arg : methodBinding.method.args) {
                    auto& jsonArg = jsonMethod["args"].emplace_back();
                    jsonArg["name"] = arg.name;
                    jsonArg["type"] = arg.type;
                }

                if (methodBinding.pattern.has_value()) {
                    jsonMethod["pattern"] = methodBinding.pattern.value();
                } else {
                    jsonMethod["pattern"] = nullptr;
                }
            }
        }

        std::ofstream file(m_outputFile);
        if (!file.is_open()) {
            return Err(fmt::format("Failed to open output pattern file: {}", m_outputFile));
        }

        file << jsonData.dump(2);
        if (m_verbose) {
            fmt::println("Saved pattern file: {}", m_outputFile);
        }

        return Ok();
    }

    Result<> Generator::generate() {
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

        GEODE_UNWRAP_INTO(auto bindings, broma::readCodegenData(m_inputFile));
        if (m_verbose) {
            fmt::println("Read Broma codegen data: {} classes", bindings.size());
        }

        static auto const getBinding = [](broma::Function const& method, Platform platform) -> broma::Address {
            switch (platform) {
                case Platform::M1:
                    return method.binding.macosArm;
                case Platform::IMAC:
                    return method.binding.macosIntel;
                case Platform::WIN:
                    return method.binding.windows;
                case Platform::IOS:
                    return method.binding.ios;
                default:
                    return broma::Address{};
            }
        };

        utils::ThreadPool pool{};

        for (auto& cls : bindings) {
            if (cls.methods.empty()) continue; // skip empty classes to save on thread
            m_totalMethods += std::ranges::count_if(cls.methods,
                [&](broma::Function const& method) {
                    auto address = getBinding(method, m_platformType);
                    return address.type == broma::AddressType::Offset;
                }
            );

            pool.enqueue([this, cls = std::move(cls)]() {
                std::vector<sinaps::token_t> outTokens;
                ClassBinding classBinding;
                classBinding.name = std::move(cls.name);

                for (auto const& method : cls.methods) {
                    auto address = getBinding(method, m_platformType);
                    if (address.type != broma::AddressType::Offset) {
                        continue;
                    }

                    auto correctedOffset = address.offset - m_baseCorrection;

                    using namespace assembly;
                    Result<void, GenerateError> res = Err(GenerateError::NotFound);
                    outTokens.clear();

                    if (m_platformType == Platform::M1 || m_platformType == Platform::IOS) {
                        res = generatePattern<aarch64::Generator>(
                            outTokens,
                            m_targetSegment,
                            correctedOffset
                        );
                    } else {
                        res = generatePattern<amd64::Generator>(
                            outTokens,
                            m_targetSegment,
                            correctedOffset
                        );
                    }

                    if (m_verbose) {
                        fmt::println("Method: {}::{} @ 0x{:x}",
                            classBinding.name,
                            method.name,
                            address.offset
                        );
                        if (!res) {
                            fmt::println("Failed to generate pattern: {}", res.unwrapErr());
                        } else {
                            fmt::println(
                                "Generated pattern ({} tokens): {}",
                                outTokens.size(),
                                sinaps::to_string(outTokens)
                            );
                        }
                    }

                    if (res) {
                        ++m_successfulMethods;
                        auto& methodBinding = classBinding.methods.emplace_back();
                        methodBinding.method = method;
                        methodBinding.pattern = sinaps::to_string(outTokens);
                    } else {
                        ++m_failedMethods;
                    }
                }

                if (classBinding.methods.empty()) {
                    return;
                }

                std::scoped_lock lock(m_mutex);
                m_classBindings.emplace_back(std::move(classBinding));
            });
        }

        pool.waitAll();

        fmt::println("Pattern generation complete: {} / {} methods successful",
            m_successfulMethods.load(),
            m_totalMethods
        );

        GEODE_UNWRAP(this->savePatternFile());

        return Ok();
    }

    Result<> Generator::readBinaryFile() {
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
}
