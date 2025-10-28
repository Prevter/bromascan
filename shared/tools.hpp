#pragma once
#include <fmt/format.h>

namespace utils {
    inline void hexdump(std::span<uint8_t const> data, size_t bytesPerLine = 16, size_t startOffset = 0) {
        for (size_t i = 0; i < data.size(); i += bytesPerLine) {
            fmt::print("{:08x}  ", i + startOffset);
            for (size_t j = 0; j < bytesPerLine; ++j) {
                if (i + j < data.size()) {
                    fmt::print("{:02x} ", data[i + j]);
                } else {
                    fmt::print("   ");
                }
            }
            fmt::print(" |");
            for (size_t j = 0; j < bytesPerLine; ++j) {
                if (i + j < data.size()) {
                    uint8_t byte = data[i + j];
                    if (std::isprint(byte)) {
                        fmt::print("{}", static_cast<char>(byte));
                    } else {
                        fmt::print(".");
                    }
                }
            }
            fmt::print("|\n");
        }
    }
}