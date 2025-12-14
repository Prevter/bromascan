#pragma once
#include <optional>
#include <string>
#include <string_view>
#include <broma/Types.hpp>
#include <nlohmann/json.hpp>

enum class Platform {
    M1,
    IMAC,
    WIN,
    IOS
};

std::string_view format_as(Platform platform);

struct MethodBinding {
    bromascan::Function method;
    std::optional<std::string> pattern;
    std::optional<uintptr_t> offset;
};

struct ClassBinding {
    std::string name;
    std::vector<MethodBinding> methods;
};

void to_json(nlohmann::json& j, MethodBinding const& mb);
void from_json(nlohmann::json const& j, MethodBinding& mb);
void to_json(nlohmann::json& j, ClassBinding const& cb);
void from_json(nlohmann::json const& j, ClassBinding& cb);