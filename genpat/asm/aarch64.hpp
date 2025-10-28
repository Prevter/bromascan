#pragma once
#include "common.hpp"

namespace assembly::aarch64 {
    class Generator {
    public:
        static constexpr size_t IterSize = 4;

        constexpr Generator(std::span<uint8_t const> data)
            : m_data(data) {}

        struct Opcode {
            bool appendTokens(std::vector<sinaps::token_t>& outTokens) const;

            uint32_t getMasked() const {
                return getValue() & m_mask;
            }

            uint32_t getValue() const {
                return *reinterpret_cast<uint32_t const*>(m_data.data());
            }

            std::array<uint8_t, 4> const m_data;
            uint32_t const m_mask;
        };

        geode::Result<Opcode, GenerateError> readNextOpcode();

    private:
        std::span<uint8_t const> m_data;
        size_t m_position = 0;
    };
}
