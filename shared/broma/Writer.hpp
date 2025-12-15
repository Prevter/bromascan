#pragma once
#include <broma.hpp>
#include <Geode/Result.hpp>

namespace bromascan {
    geode::Result<> writeBromaFile(
        std::filesystem::path const& path,
        broma::Root const& root
    );
}