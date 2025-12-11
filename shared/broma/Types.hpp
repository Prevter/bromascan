#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace bromascan {
    enum class AddressType {
        Null,
        Link,
        Offset,
        Inlined
    };

    struct Address {
        uintptr_t offset = 0;
        AddressType type = AddressType::Null;
    };

    struct Binding {
        Address windows;
        Address macosIntel;
        Address macosArm;
        Address ios;
        Address android32;
        Address android64;
    };

    struct FuncArg {
        std::string name;
        std::string type;
    };

    struct Function {
        std::string name;
        std::string returnType;
        std::vector<FuncArg> args;
        Binding binding;
        bool isVirtual;
        bool isStatic;
        bool isConst;
    };

    struct Class {
        std::string name;
        std::vector<Function> methods;
    };

    inline std::string_view format_as(AddressType type) {
        switch (type) {
            case AddressType::Null:
                return "Null";
            case AddressType::Link:
                return "Link";
            case AddressType::Offset:
                return "Offset";
            case AddressType::Inlined:
                return "Inlined";
            default:
                return "Unknown";
        }
    }
}
