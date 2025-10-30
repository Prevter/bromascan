#pragma once
#include <string_view>

enum class Platform {
    M1,
    IMAC,
    WIN,
    IOS
};

std::string_view format_as(Platform platform);