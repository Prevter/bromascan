#include "bromascan.hpp"

std::string_view format_as(Platform platform) {
    switch (platform) {
        case Platform::M1:
            return "M1";
        case Platform::IMAC:
            return "iMac";
        case Platform::WIN:
            return "Windows";
        case Platform::IOS:
            return "iOS";
        default:
            return "Unknown";
    }
}

void to_json(nlohmann::json& j, MethodBinding const& mb) {
    j["name"] = mb.method.name;
    j["return"] = mb.method.returnType;

    auto& args = j["args"];
    args = nlohmann::json::array();
    for (auto const& arg : mb.method.args) {
        auto& jsonArg = args.emplace_back();
        jsonArg["name"] = arg.name;
        jsonArg["type"] = arg.type;
    }

    if (mb.pattern.has_value()) {
        j["pattern"] = mb.pattern.value();
    }

    if (mb.offset.has_value()) {
        j["offset"] = mb.offset.value();
    }
}

void from_json(nlohmann::json const& j, MethodBinding& mb) {
    mb.method.name = j["name"].get<std::string>();
    mb.method.returnType = j["return"].get<std::string>();

    auto& jsonArgs = j["args"];
    for (auto& jsonArg : jsonArgs) {
        auto& arg = mb.method.args.emplace_back();
        arg.name = jsonArg["name"].get<std::string>();
        arg.type = jsonArg["type"].get<std::string>();
    }

    if (j.contains("pattern") && !j["pattern"].is_null()) {
        mb.pattern = j["pattern"].get<std::string>();
    } else {
        mb.pattern = std::nullopt;
    }

    if (j.contains("offset") && !j["offset"].is_null()) {
        mb.offset = j["offset"].get<uintptr_t>();
    } else {
        mb.offset = std::nullopt;
    }
}

void to_json(nlohmann::json& j, ClassBinding const& cb) {
    j["name"] = cb.name;
    j["functions"] = nlohmann::json::array();
    for (auto const& method : cb.methods) {
        j["functions"].emplace_back(method);
    }
}

void from_json(nlohmann::json const& j, ClassBinding& cb) {
    cb.name = j["name"].get<std::string>();
    auto& jsonMethods = j["functions"];
    for (auto& jsonMethod : jsonMethods) {
        cb.methods.emplace_back(jsonMethod.get<MethodBinding>());
    }
}
