#pragma once
#include <Zydis/Disassembler.h>

#include "common.hpp"

namespace assembly::amd64 {
    class Generator {
    public:
        static constexpr size_t IterSize = 1;

        constexpr Generator(std::span<uint8_t const> data)
            : m_data(data) {}

        struct Opcode {
            bool appendTokens(std::vector<sinaps::token_t>& outTokens) const;
            ZydisDisassembledInstruction const& m_instruction;
            uint8_t const* const m_data;
        };

        geode::Result<Opcode, GenerateError> readNextOpcode();

    private:
        std::span<uint8_t const> m_data;
        size_t m_position = 0;
        ZydisDisassembledInstruction m_lastInstruction{};
    };
}
