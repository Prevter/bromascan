#pragma once
#include <atomic>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include <bromascan.hpp>
#include <broma/Types.hpp>
#include <Geode/Result.hpp>

namespace genpat {
    using namespace geode;

    class Generator {
    public:
        Generator(
            std::string platform,
            std::string binaryFile,
            std::string inputFile,
            std::string outputFile,
            bool verbose
        ) : m_platform(std::move(platform)), m_binaryFile(std::move(binaryFile)), m_inputFile(std::move(inputFile)),
            m_outputFile(std::move(outputFile)), m_verbose(verbose) {}

        Result<> generate();

    private:
        Result<> readBinaryFile();
        Result<Platform> resolvePlatform();
        Result<> savePatternFile();

        struct MethodBinding {
            bromascan::Function method;
            std::optional<std::string> pattern;
        };

        struct ClassBinding {
            std::string name;
            std::vector<MethodBinding> methods;
        };

    private:
        std::vector<uint8_t> m_binaryData;
        std::span<uint8_t const> m_targetSegment;
        std::vector<ClassBinding> m_classBindings;
        std::mutex m_mutex;
        intptr_t m_baseCorrection = 0;
        Platform m_platformType = Platform::WIN;

        size_t m_totalMethods = 0;
        std::atomic<size_t> m_successfulMethods = 0;
        std::atomic<size_t> m_failedMethods = 0;

        std::string m_platform;
        std::string m_binaryFile;
        std::string m_inputFile;
        std::string m_outputFile;
        bool m_verbose;
    };
}
