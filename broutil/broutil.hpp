#pragma once
#include <ast.hpp>
#include <filesystem>
#include <Geode/Result.hpp>

namespace broutil {
    class BroUtil {
    public:
        BroUtil(
            std::filesystem::path inputBro,
            std::filesystem::path outputBro,
            bool format = false
        );

        BroUtil(
            std::filesystem::path inputBro,
            std::filesystem::path scanResults,
            std::filesystem::path outputBro
        );

        geode::Result<> process();

    private:
        [[nodiscard]] geode::Result<> clearBindings(broma::Root root) const;
        [[nodiscard]] geode::Result<> mergeScanResults(broma::Root root) const;

    private:
        std::filesystem::path m_inputBro;
        std::filesystem::path m_outputBro;
        std::filesystem::path m_scanResults;
        bool m_useScanResults = false;
        bool m_format = false;
    };
}
