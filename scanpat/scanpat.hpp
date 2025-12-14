#pragma once
#include <atomic>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include <bromascan.hpp>
#include <Geode/Result.hpp>

namespace scanpat {
    class Scanner {
    public:
        Scanner(
            std::string binaryFile,
            std::string patternsFile,
            std::string outputFile,
            bool verbose
        ) : m_binaryFile(std::move(binaryFile)),
            m_patternsFile(std::move(patternsFile)), m_outputFile(std::move(outputFile)),
            m_verbose(verbose) {}

        geode::Result<> scan();

    private:
        geode::Result<> readBinaryFile();
        geode::Result<> readPatternsFile();
        geode::Result<> performScan();
        geode::Result<> saveResults();

    private:
        std::vector<uint8_t> m_binaryData;
        std::vector<ClassBinding> m_classBindings;
        std::span<uint8_t const> m_targetSegment;
        std::mutex m_mutex;
        intptr_t m_baseCorrection = 0;
        Platform m_platformType = Platform::WIN;

        std::atomic<size_t> m_successfulMethods = 0;
        std::atomic<size_t> m_failedMethods = 0;

        std::string m_binaryFile;
        std::string m_patternsFile;
        std::string m_outputFile;
        bool m_verbose;
    };
}
