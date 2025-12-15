#include "broutil.hpp"
#include <broma.hpp>
#include <bromascan.hpp>
#include <fstream>
#include <broma/Writer.hpp>
#include <fmt/format.h>
#include <fmt/std.h>

using namespace geode;

namespace broutil {
    BroUtil::BroUtil(std::filesystem::path inputBro, std::filesystem::path outputBro, bool format)
        : m_inputBro(std::move(inputBro)), m_outputBro(std::move(outputBro)), m_format(format) {}

    BroUtil::BroUtil(std::filesystem::path inputBro, std::filesystem::path scanResults, std::filesystem::path outputBro)
        : m_inputBro(std::move(inputBro)),
          m_outputBro(std::move(outputBro)),
          m_scanResults(std::move(scanResults)),
          m_useScanResults(true) {}

    Result<> BroUtil::clearBindings(broma::Root root) const {
        auto clearBindings = [](broma::PlatformNumber& binds) {
            if (binds.win >= 0) binds.win = -1;
            if (binds.imac >= 0) binds.imac = -1;
            if (binds.m1 >= 0) binds.m1 = -1;
            if (binds.ios >= 0) binds.ios = -1;
            if (binds.android32 >= 0) binds.android32 = -1;
            if (binds.android64 >= 0) binds.android64 = -1;
        };

        // clear all bindings except inline definitions
        for (auto& cls : root.classes) {
            for (auto& field : cls.fields) {
                if (auto fn = field.get_as<broma::FunctionBindField>()) {
                    clearBindings(fn->binds);
                }
            }
        }

        for (auto& fn : root.functions) {
            clearBindings(fn.binds);
        }

        return bromascan::writeBromaFile(m_outputBro, root);
    }

    Result<> BroUtil::mergeScanResults(broma::Root root) const {
        // load scan results
        std::ifstream file(m_scanResults);
        if (!file.is_open()) {
            return Err(fmt::format("Failed to open patterns file: {}", m_scanResults));
        }

        auto jsonData = nlohmann::json::parse(file, nullptr, false);
        if (jsonData.is_discarded()) {
            return Err(fmt::format("Failed to parse patterns file: {}", m_scanResults));
        }

        std::vector<ClassBinding> classBindings;
        auto& classes = jsonData["classes"];
        classBindings.reserve(classes.size());

        try {
            for (auto& jsonClass : classes) {
                classBindings.emplace_back(jsonClass.get<ClassBinding>());
            }
        } catch (std::exception& e) {
            return Err(fmt::format("Failed to deserialize patterns file: {}: {}", m_scanResults, e.what()));
        }

        auto platformStr = jsonData["platform"].get<std::string_view>();
        Platform platformType;
        if (platformStr == "Windows") {
            platformType = Platform::WIN;
        } else if (platformStr == "iMac") {
            platformType = Platform::IMAC;
        } else if (platformStr == "M1") {
            platformType = Platform::M1;
        } else if (platformStr == "iOS") {
            platformType = Platform::IOS;
        } else {
            return Err(fmt::format("Unsupported platform in patterns file: {}", platformStr));
        }

        auto setBinding = [platformType](broma::PlatformNumber& binds, uintptr_t offset) {
            switch (platformType) {
                case Platform::WIN:
                    binds.win = static_cast<ptrdiff_t>(offset);
                    break;
                case Platform::IMAC:
                    binds.imac = static_cast<ptrdiff_t>(offset);
                    break;
                case Platform::M1:
                    binds.m1 = static_cast<ptrdiff_t>(offset);
                    break;
                case Platform::IOS:
                    binds.ios = static_cast<ptrdiff_t>(offset);
                    break;
                default:
                    break;
            }
        };

        for (auto& classBinding : classBindings) {
            auto cls = std::ranges::find_if(
                root.classes,
                [&classBinding](broma::Class const& c) {
                    return c.name == classBinding.name;
                }
            );

            if (cls == root.classes.end()) {
                continue;
            }

            fmt::println("Class: {}", classBinding.name);
            for (auto& methodBinding : classBinding.methods) {
                fmt::println("  Method: {}", methodBinding.method.name);
                // find by name, filter by args if overloaded
                auto methodIt = std::ranges::find_if(
                    cls->fields,
                    [&methodBinding](broma::Field const& f) {
                        if (auto fn = f.get_as<broma::FunctionBindField>()) {
                            if (fn->prototype.name != methodBinding.method.name) {
                                return false;
                            }
                            if (fn->prototype.args.size() != methodBinding.method.args.size()) {
                                return false;
                            }
                            for (size_t i = 0; i < fn->prototype.args.size(); ++i) {
                                if (fn->prototype.args[i].first.name != methodBinding.method.args[i].type) {
                                    return false;
                                }
                            }
                            return true;
                        }
                        return false;
                    }
                );

                if (methodIt == cls->fields.end()) {
                    fmt::println("    Method not found in Broma file.");
                    continue;
                }

                if (methodBinding.offset.has_value()) {
                    auto fn = methodIt->get_as<broma::FunctionBindField>();
                    setBinding(fn->binds, methodBinding.offset.value());
                    fmt::println("    Set binding to offset: 0x{:X}", methodBinding.offset.value());
                } else {
                    fmt::println("    No offset found in scan results.");
                }
            }
        }

        return bromascan::writeBromaFile(m_outputBro, root);
    }

    Result<> BroUtil::process() {
        broma::Root root;
        try {
            root = broma::parse_file(m_inputBro);
        } catch (std::exception const& e) {
            return Err(fmt::format("Failed to parse Broma file: {}", e.what()));
        }

        if (m_format) {
            return bromascan::writeBromaFile(m_outputBro, root);
        }

        if (m_useScanResults) {
            return mergeScanResults(std::move(root));
        }

        return clearBindings(std::move(root));
    }
}
