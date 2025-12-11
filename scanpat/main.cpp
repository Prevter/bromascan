#include <chrono>
#include <cxxopts.hpp>
#include <fmt/format.h>
#include "scanpat.hpp"

#include <broma/Writer.hpp>

int main(int argc, char* argv[]) {
    {
        auto start = std::chrono::high_resolution_clock::now();
        auto [classes, functions, _] = broma::parse_file("GeometryDash.bro");
        (void) bromascan::writeBromaFile("test.bro", classes);
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        fmt::print("Broma parse and write completed in {} ms\n", duration);
    }

    cxxopts::Options options("scanpat", "Mass-scan function addresses using patterns");
    options.add_options()
        ("v,verbose", "Enable verbose output")
        ("h,help", "Print help")
        ("p,platform", "Target platform (auto, m1, imac, win, ios)", cxxopts::value<std::string>()->default_value("auto"))
        ("version", "Print version information")
        ("binary", "Binary File", cxxopts::value<std::string>())
        ("patterns", "Input Patterns File", cxxopts::value<std::string>())
        ("output", "Output Scan Results File", cxxopts::value<std::string>());
    options.parse_positional({"binary", "patterns", "output"});
    auto result = options.parse(argc, argv);

    if (result.count("help")) {
        fmt::print("{}", options.help());
        return 0;
    }

    if (result.count("version")) {
        fmt::print("scanpat version" SCANPAT_VERSION "\n");
        return 0;
    }

    if (!result.count("binary") || !result.count("patterns") || !result.count("output")) {
        fmt::print("Error: Missing required arguments.\n");
        fmt::print("{}", options.help());
        return 1;
    }

    auto platform = result["platform"].as<std::string>();
    auto binaryFile = result["binary"].as<std::string>();
    auto patternsFile = result["patterns"].as<std::string>();
    auto outputFile = result["output"].as<std::string>();
    bool verbose = result.count("verbose") > 0;
    if (verbose) {
        fmt::print("Platform: {}\n", platform);
        fmt::print("Binary File: {}\n", binaryFile);
        fmt::print("Patterns File: {}\n", patternsFile);
        fmt::print("Output File: {}\n", outputFile);
    }

    auto start = std::chrono::high_resolution_clock::now();
    scanpat::Scanner scanner(
        std::move(platform),
        std::move(binaryFile),
        std::move(patternsFile),
        std::move(outputFile),
        verbose
    );

    if (auto res = scanner.scan(); !res) {
        fmt::print("Error: {}\n", res.unwrapErr());
        return 1;
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    fmt::print("Scan completed in {} ms\n", duration);

    return 0;
}