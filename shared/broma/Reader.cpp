#include "Reader.hpp"
#include <fstream>
#include <fmt/format.h>
#include <fmt/std.h>
#include <nlohmann/json.hpp>

namespace bromascan {
    geode::Result<std::vector<Class>> readCodegenData(std::filesystem::path const& path) {
        std::ifstream file(path);
        if (!file.is_open()) {
            return geode::Err(fmt::format("Failed to open Broma codegen data file: {}", path));
        }

        auto jsonData = nlohmann::json::parse(file, nullptr, false);
        if (jsonData.is_discarded()) {
            return geode::Err(fmt::format("Failed to parse Broma codegen data file: {}", path));
        }

        std::vector<Class> classes;
        auto& jsonClasses = jsonData["classes"];
        classes.reserve(jsonClasses.size());

        for (auto& jsonClass : jsonClasses) {
            auto& cls = classes.emplace_back();
            cls.name = jsonClass["name"].get<std::string>();

            auto& jsonFunctions = jsonClass["functions"];
            for (auto& jsonFunction : jsonFunctions) {
                auto& func = cls.methods.emplace_back();
                func.name = jsonFunction["name"].get<std::string>();
                func.returnType = jsonFunction["return"].get<std::string>();
                func.isStatic = jsonFunction["static"].get<bool>();
                func.isVirtual = jsonFunction["virtual"].get<bool>();
                func.isConst = jsonFunction["const"].get<bool>();

                auto& bindings = jsonFunction["bindings"];
                auto readBinding = [&](nlohmann::json const& json) {
                    if (json.is_null()) {
                        return Address{};
                    }

                    if (json.is_string()) {
                        auto str = json.get<std::string_view>();
                        if (str == "link") {
                            return Address{0, AddressType::Link};
                        }
                        if (str == "inline") {
                            return Address{0, AddressType::Inlined};
                        }
                        return Address{};
                    }

                    return Address{
                        json.get<uintptr_t>(),
                        AddressType::Offset
                    };
                };

                func.binding.windows = readBinding(bindings["win"]);
                func.binding.macosIntel = readBinding(bindings["imac"]);
                func.binding.macosArm = readBinding(bindings["m1"]);
                func.binding.ios = readBinding(bindings["ios"]);
                func.binding.android32 = readBinding(bindings["android32"]);
                func.binding.android64 = readBinding(bindings["android64"]);

                auto& jsonArgs = jsonFunction["args"];
                for (auto& jsonArg : jsonArgs) {
                    auto& arg = func.args.emplace_back();
                    arg.name = jsonArg["name"].get<std::string>();
                    arg.type = jsonArg["type"].get<std::string>();
                }
            }
        }

        return geode::Ok(classes);
    }
}
