#pragma once
#include <broma.hpp>
#include <Geode/Result.hpp>

namespace bromascan {
    geode::Result<> writeBromaFile(
        std::filesystem::path const& path,
        std::span<broma::Class> classes
    );
}