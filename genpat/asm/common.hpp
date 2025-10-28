#pragma once
#include <span>
#include <vector>

#include <sinaps.hpp>
#include <fmt/format.h>
#include <Geode/Result.hpp>

namespace assembly {
    enum class GenerateError {
        None,
        NotFound,
        PatternTooLarge,
        InvalidInstruction,
    };

    inline std::string_view format_as(GenerateError error) {
        switch (error) {
            case GenerateError::None:
                return "None";
            case GenerateError::NotFound:
                return "NotFound";
            case GenerateError::PatternTooLarge:
                return "PatternTooLarge";
            case GenerateError::InvalidInstruction:
                return "InvalidInstruction";
            default:
                return "Unknown";
        }
    }

    template <typename T>
    concept GeneratorConcept = requires(T t, std::span<uint8_t const> data) {
        { T(data) } -> std::same_as<T>;
        { t.readNextOpcode() } -> std::same_as<geode::Result<typename T::Opcode, GenerateError>>;
    };

    template <GeneratorConcept Generator>
    geode::Result<void, GenerateError> generatePattern(
        std::vector<sinaps::token_t>& outTokens,
        std::span<uint8_t const> data,
        uintptr_t offset,
        size_t maxSize = 256
    ) {
        auto start = data.data() + offset;
        Generator gen(std::span(start, data.size() - offset));

        intptr_t lastFound = 0;
        intptr_t newTarget = offset;

        while (auto opc = gen.readNextOpcode()) {
            if (!opc.unwrap().appendTokens(outTokens)) {
                return geode::Err(GenerateError::InvalidInstruction);
            }

            auto index = sinaps::find(data.data() + lastFound, data.size() - lastFound, outTokens, Generator::IterSize);
            if (newTarget == index) {
                // check if pattern is unique
                auto nextIndex = sinaps::find(
                    data.data() + offset + 1,
                    data.size() - (offset + 1),
                    outTokens,
                    Generator::IterSize
                );

                if (nextIndex == sinaps::not_found) {
                    return geode::Ok();
                }

                lastFound += index;
                newTarget = 0;
            } else if (index != sinaps::not_found) {
                newTarget -= index;
                lastFound += index;
            } else {
                // realistically never reaches here
                return geode::Err(GenerateError::NotFound);
            }

            // if tokens exceed max size, fail
            if (outTokens.size() > maxSize) {
                return geode::Err(GenerateError::PatternTooLarge);
            }
        }

        return geode::Err(GenerateError::NotFound);
    }
}
