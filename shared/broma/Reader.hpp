#pragma once
#include <filesystem>
#include <Geode/Result.hpp>
#include "Types.hpp"

namespace broma {
    geode::Result<std::vector<Class>> readCodegenData(std::filesystem::path const& path);
}