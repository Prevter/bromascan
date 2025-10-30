#include "bromascan.hpp"

std::string_view format_as(Platform platform) {
    switch (platform) {
        case Platform::M1:
            return "M1";
        case Platform::IMAC:
            return "iMac";
        case Platform::WIN:
            return "Windows";
        case Platform::IOS:
            return "iOS";
        default:
            return "Unknown";
    }
}