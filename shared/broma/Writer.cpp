#include "Writer.hpp"
#include <fstream>
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <fmt/std.h>

using namespace geode;

namespace broma {
    constexpr Platform operator~(Platform mac) {
        return static_cast<Platform>(~static_cast<int>(mac));
    }

    std::string format_as(Platform platform) {
        if (platform == Platform::None) {
            return "";
        }

        std::string result;
        if ((platform & Platform::Windows) == Platform::Windows) {
            result += "win, ";
        }

        if ((platform & Platform::Android) == Platform::Android) {
            result += "android, ";
        } else {
            if ((platform & Platform::Android32) == Platform::Android32) {
                result += "android32, ";
            } else if ((platform & Platform::Android64) == Platform::Android64) {
                result += "android64, ";
            }
        }

        if ((platform & Platform::Mac) == Platform::Mac) {
            result += "mac, ";
        } else {
            if ((platform & Platform::MacIntel) == Platform::MacIntel) {
                result += "imac, ";
            } else if ((platform & Platform::MacArm) == Platform::MacArm) {
                result += "m1, ";
            }
        }

        if ((platform & Platform::iOS) == Platform::iOS) {
            result += "ios, ";
        }

        if (!result.empty()) {
            result.pop_back();
            result.pop_back();
        }

        return result;
    }

    std::string format_as(PlatformNumber platformNumber) {
        // -2 = inline
        // -1 = missing/linked
        if (
            platformNumber.imac == -1 &&
            platformNumber.m1 == -1 &&
            platformNumber.ios == -1 &&
            platformNumber.win == -1 &&
            platformNumber.android32 == -1 &&
            platformNumber.android64 == -1
        ) {
            return {};
        }

        // if everything is inline, return empty string
        if (
            platformNumber.imac == -2 &&
            platformNumber.m1 == -2 &&
            platformNumber.ios == -2 &&
            platformNumber.win == -2 &&
            platformNumber.android32 == -2 &&
            platformNumber.android64 == -2
        ) {
            return {};
        }

        // if more than two platforms are inlined, don't list them
        size_t inlineCount = 0;
        if (platformNumber.imac == -2) ++inlineCount;
        if (platformNumber.m1 == -2) ++inlineCount;
        if (platformNumber.ios == -2) ++inlineCount;
        if (platformNumber.win == -2) ++inlineCount;
        if (platformNumber.android32 == -2) ++inlineCount;
        if (platformNumber.android64 == -2) ++inlineCount;

        std::string result = " = ";
        if (platformNumber.win >= 0) {
            result += fmt::format("win 0x{:x}, ", platformNumber.win);
        } else if (platformNumber.win == -2 && inlineCount <= 2) {
            result += "win inline, ";
        }

        if (platformNumber.android32 >= 0) {
            result += fmt::format("android32 0x{:x}, ", platformNumber.android32);
        }
        // realistically never used and causes more confusion
        // else if (platformNumber.android32 == -2 && inlineCount <= 2) {
        //     result += "android32 inline, ";
        // }

        if (platformNumber.android64 >= 0) {
            result += fmt::format("android64 0x{:x}, ", platformNumber.android64);
        }
        // else if (platformNumber.android64 == -2 && inlineCount <= 2) {
        //     result += "android64 inline, ";
        // }

        if (platformNumber.imac >= 0) {
            result += fmt::format("imac 0x{:x}, ", platformNumber.imac);
        } else if (platformNumber.imac == -2 && inlineCount <= 2) {
            result += "imac inline, ";
        }

        if (platformNumber.m1 >= 0) {
            result += fmt::format("m1 0x{:x}, ", platformNumber.m1);
        } else if (platformNumber.m1 == -2 && inlineCount <= 2) {
            result += "m1 inline, ";
        }

        if (platformNumber.ios >= 0) {
            result += fmt::format("ios 0x{:x}, ", platformNumber.ios);
        } else if (platformNumber.ios == -2 && inlineCount <= 2) {
            result += "ios inline, ";
        }

        result.pop_back();
        result.pop_back();
        return result;
    }
}

namespace bromascan {
    struct MethodEntry {
        enum class Kind { Function, Inline } kind;

        broma::FunctionBindField* fn = nullptr;
        broma::InlineField* inl = nullptr;

        std::vector<broma::CommentField*> comments;
        broma::CommentField* trailingComment = nullptr;

        std::string name;
        size_t virtualIndex = SIZE_MAX;

        bool isCtor = false;
        bool isDtor = false;
        bool isStatic = false;
        bool isVirtual = false;

        [[nodiscard]] int sectionRank() const {
            if (isCtor)    return 0;
            if (isDtor)    return 1;
            if (isStatic)  return 2;
            if (isVirtual) return 3;
            return 4;
        }

        MethodEntry& withComments(std::vector<broma::CommentField*>& comm) {
            comments = comm;
            comm.clear();
            return *this;
        }

        static MethodEntry fromFunction(broma::FunctionBindField* fn, size_t vIndex) {
            return MethodEntry {
                .kind = Kind::Function,
                .fn = fn,
                .name = fn->prototype.name,
                .virtualIndex = vIndex,
                .isCtor = fn->prototype.type == broma::FunctionType::Ctor,
                .isDtor = fn->prototype.type == broma::FunctionType::Dtor,
                .isStatic = fn->prototype.is_static,
                .isVirtual = fn->prototype.is_virtual
            };
        }

        static MethodEntry fromInline(broma::InlineField* inl, std::string_view className) {
            std::string_view innerView(inl->inner);
            size_t parenPos = innerView.find('(');
            if (parenPos == std::string_view::npos) {
                parenPos = innerView.size();
            }

            size_t nameEnd = parenPos;
            size_t nameStart = innerView.rfind(' ', nameEnd - 1);
            if (nameStart == std::string_view::npos) {
                nameStart = 0;
            } else {
                nameStart += 1;
            }

            std::string name(innerView.substr(nameStart, nameEnd - nameStart));
            bool isCtor = name == className;
            bool isStatic = innerView.find("static") != std::string_view::npos;

            return MethodEntry {
                .kind = Kind::Inline,
                .inl = inl,
                .name = std::move(name),
                .virtualIndex = SIZE_MAX,
                .isCtor = isCtor,
                .isDtor = false,
                .isStatic = isStatic,
                .isVirtual = false
            };
        }
    };

    struct MemberEntry {
        enum class Kind { Padding, Field } kind;

        broma::MemberField* field = nullptr;
        broma::PadField* pad = nullptr;

        std::vector<broma::CommentField*> comments;
        broma::CommentField* trailingComment = nullptr;

        MemberEntry& withComments(std::vector<broma::CommentField*>& comm) {
            comments = comm;
            comm.clear();
            return *this;
        }

        static MemberEntry fromField(broma::MemberField* field) {
            return MemberEntry {
                .kind = Kind::Field,
                .field = field
            };
        }

        static MemberEntry fromPad(broma::PadField* pad) {
            return MemberEntry {
                .kind = Kind::Padding,
                .pad = pad
            };
        }
    };

    std::string formatDocs(std::string const& docs, size_t indentLevel = 0) {
        if (docs.empty())
            return {};

        std::string result;
        result.reserve(docs.size());

        size_t start = 0;
        while (start < docs.size()) {
            size_t end = docs.find('\n', start);
            if (end == std::string::npos)
                end = docs.size();

            std::string_view line(docs.data() + start, end - start);

            while (!line.empty() && (line.front() == ' ' || line.front() == '\t'))
                line.remove_prefix(1);

            while (!line.empty() && (line.back() == ' ' || line.back() == '\t' || line.back() == '\r'))
                line.remove_suffix(1);

            if (!line.empty()) {
                for (size_t i = 0; i < indentLevel; ++i) {
                    fmt::format_to(std::back_inserter(result), "    ");
                }
                fmt::format_to(std::back_inserter(result), "/// {}\n", line);
            }

            start = end == docs.size() ? end : end + 1;
        }

        return result;
    }

    std::string formatAttributes(
        broma::Attributes const& attributes,
        std::span<std::string const> superClasses,
        size_t indentLevel = 0
    ) {
        fmt::memory_buffer buf;

        // Write documentation first
        if (!attributes.docs.empty()) {
            auto docs = formatDocs(attributes.docs, indentLevel);
            fmt::format_to(std::back_inserter(buf), "{}", docs);
        }

        std::vector<std::string> tags;
        tags.reserve(4 + attributes.depends.size());

        if (attributes.links != broma::Platform::None) {
            tags.emplace_back(fmt::format("link({})", attributes.links));
        }

        if (attributes.missing != broma::Platform::None) {
            tags.emplace_back(fmt::format("missing({})", attributes.missing));
        }

        if (!attributes.since.empty()) {
            tags.emplace_back(fmt::format("since(\"{}\")", attributes.since));
        }

        for (auto const& depend : attributes.depends) {
            if (!std::ranges::contains(superClasses, depend)) {
                tags.emplace_back(fmt::format("depends({})", depend));
            }
        }

        if (!tags.empty()) {
            for (size_t i = 0; i < indentLevel; ++i) {
                fmt::format_to(std::back_inserter(buf), "    ");
            }
            fmt::format_to(std::back_inserter(buf), "[[{}]]\n", fmt::join(tags, ", "));
        }

        return fmt::to_string(buf);
    }

    Result<> writeBromaFile(std::filesystem::path const& path, broma::Root const& root) {
        std::ofstream file(path);
        if (!file.is_open()) {
            return Err(fmt::format("Failed to open Broma output file: {}", path));
        }

        auto const& [classes, functions, headers] = root;

        // write headers
        for (auto& header : headers) {
            if (header.platform == broma::Platform::All) {
                fmt::println(file, "#import <{}>", header.name);
            } else {
                fmt::println(file, "#import {} <{}>", header.platform, header.name);
            }
        }

        if (!headers.empty()) {
            fmt::println(file, "");
        }

        // sort classes by name
        std::vector sortedClasses(classes.begin(), classes.end());
        std::ranges::sort(sortedClasses, [](auto const& a, auto const& b) {
            std::string aLower = a.name;
            std::string bLower = b.name;
            std::ranges::transform(aLower, aLower.begin(), ::tolower);
            std::ranges::transform(bLower, bLower.begin(), ::tolower);
            return aLower < bLower;
        });

        for (auto& cls : sortedClasses) {
            // attributes
            fmt::print(file, "{}", formatAttributes(cls.attributes, cls.superclasses));

            // class declaration
            fmt::print(file, "class {}", cls.name);
            if (!cls.superclasses.empty()) {
                fmt::print(file, " : {}", fmt::join(cls.superclasses, ", "));
            }
            fmt::println(file, " {{");

            // methods
            std::vector<MethodEntry> entries;
            std::vector<MemberEntry> members;
            std::vector<broma::CommentField*> pendingComments;
            entries.reserve(cls.fields.size());
            members.reserve(cls.fields.size());
            bool hasMembers = false;

            bool lastWasMethod = true;

            size_t virtualCounter = 0;
            bool topLevelComment = true;
            bool hadTopLevelComment = false;

            for (auto& field : cls.fields) {
                if (auto fn = field.get_as<broma::FunctionBindField>()) {
                    // methods.emplace_back(fn);
                    entries.emplace_back(
                        MethodEntry::fromFunction(fn, virtualCounter)
                            .withComments(pendingComments)
                    );
                    if (fn->prototype.is_virtual) {
                        virtualCounter++;
                    }
                    lastWasMethod = true;
                } else if (auto inl = field.get_as<broma::InlineField>()) {
                    entries.emplace_back(
                        MethodEntry::fromInline(inl, cls.name)
                            .withComments(pendingComments)
                    );
                    lastWasMethod = true;
                } else if (auto comment = field.get_as<broma::CommentField>()) {
                    if (topLevelComment) {
                        fmt::println(file, "    {}", comment->inner);
                        hadTopLevelComment = true;
                    } else {
                        if (comment->trailing) {
                            // attach to last member if possible
                            if (lastWasMethod && !entries.empty()) {
                                entries.back().trailingComment = comment;
                            } else if (!lastWasMethod && !members.empty()) {
                                members.back().trailingComment = comment;
                            }
                        } else {
                            pendingComments.push_back(comment);
                        }
                    }
                    continue;
                } else if (auto member = field.get_as<broma::MemberField>()) {
                    hasMembers = true;
                    members.emplace_back(
                        MemberEntry::fromField(member)
                            .withComments(pendingComments)
                    );
                    lastWasMethod = false;
                } else if (auto pad = field.get_as<broma::PadField>()) {
                    hasMembers = true;
                    members.emplace_back(
                        MemberEntry::fromPad(pad)
                            .withComments(pendingComments)
                    );
                    lastWasMethod = false;
                }

                topLevelComment = false;
            }

            // sort methods
            std::ranges::sort(entries, [](auto const& a, auto const& b) {
                if (a.sectionRank() != b.sectionRank()) {
                    return a.sectionRank() < b.sectionRank();
                }
                if (a.isVirtual && b.isVirtual) {
                    return a.virtualIndex < b.virtualIndex;
                }

                // for overloads, sort by arguments
                if (a.name == b.name) {
                    if (a.kind == MethodEntry::Kind::Function && b.kind == MethodEntry::Kind::Function) {
                        auto& aArgs = a.fn->prototype.args;
                        auto& bArgs = b.fn->prototype.args;
                        if (aArgs.size() != bArgs.size()) {
                            return aArgs.size() < bArgs.size();
                        }
                        for (size_t i = 0; i < aArgs.size(); ++i) {
                            if (aArgs[i].first.name != bArgs[i].first.name) {
                                return aArgs[i].first.name < bArgs[i].first.name;
                            }
                        }
                    }
                }

                // return a.name < b.name;
                // sort by name case-insensitively
                std::string aLower = a.name;
                std::string bLower = b.name;
                std::ranges::transform(aLower, aLower.begin(), ::tolower);
                std::ranges::transform(bLower, bLower.begin(), ::tolower);
                return aLower < bLower;
            });


            bool hasCtor = false;
            bool hasDtor = false;
            for (auto const& entry : entries) {
                if (entry.isCtor) {
                    hasCtor = true;
                } else if (entry.isDtor) {
                    hasDtor = true;
                }

                if (hasCtor && hasDtor) {
                    break;
                }
            }

            // write methods
            enum class LastSection { Ctor, Static, Virtual, Normal } lastSection = LastSection::Normal;

            if (!entries.empty()) {
                auto& firstEntry = *entries.begin();
                lastSection = firstEntry.isCtor || hadTopLevelComment ? LastSection::Ctor :
                              firstEntry.isStatic ? LastSection::Static :
                              firstEntry.isVirtual ? LastSection::Virtual :
                              LastSection::Normal;
            }

            for (auto const& entry : entries) {
                bool switchedSection = false;

                // separate different types of methods with a newline
                if (entry.isCtor || entry.isDtor) {
                    if (lastSection != LastSection::Ctor) {
                        fmt::println(file, "");
                        lastSection = LastSection::Ctor;
                        switchedSection = true;
                    }
                } else if (entry.isStatic) {
                    if (lastSection != LastSection::Static) {
                        fmt::println(file, "");
                        lastSection = LastSection::Static;
                        switchedSection = true;
                    }
                } else if (entry.isVirtual) {
                    if (lastSection != LastSection::Virtual) {
                        fmt::println(file, "");
                        lastSection = LastSection::Virtual;
                        switchedSection = true;
                    }
                } else {
                    if (lastSection != LastSection::Normal) {
                        fmt::println(file, "");
                        lastSection = LastSection::Normal;
                        switchedSection = true;
                    }
                }

                if (entry.kind == MethodEntry::Kind::Function) {
                    auto* method = &entry.fn->prototype;

                    // write comment
                    for (auto* comment : entry.comments) {
                        fmt::println(file, "    {}", comment->inner);
                    }

                    // blank line if has docs
                    if (!switchedSection && !method->attributes.docs.empty()) {
                        fmt::println(file, "");
                    }

                    // attributes
                    method->attributes.links &= ~cls.attributes.links;
                    method->attributes.missing &= ~cls.attributes.missing;
                    auto attrs = formatAttributes(method->attributes, {}, 1);
                    if (!attrs.empty()) {
                        fmt::print(file, "{}", attrs);
                    }

                    fmt::print(file, "    ");

                    // if callback
                    if (method->is_callback) {
                        fmt::print(file, "callback ");
                    }

                    // declaration
                    if (method->is_static) {
                        fmt::print(file, "static ");
                    } else if (method->is_virtual) {
                        fmt::print(file, "virtual ");
                    }

                    if (method->type != broma::FunctionType::Normal) {
                        fmt::print(file, "{}(", method->name);
                    } else {
                        fmt::print(file, "{} {}(", method->ret.name, method->name);
                    }

                    bool shouldKeepDefaultNames = entry.fn->inner.contains("p0");

                    // args
                    for (size_t i = 0; i < method->args.size(); ++i) {
                        auto const& [argType, argName] = method->args[i];
                        // if argName follows `p0`, `p1`, etc., we can omit it
                        if (!shouldKeepDefaultNames && argName == fmt::format("p{}", i)) {
                            fmt::print(file, "{}", argType.name);
                        } else {
                            fmt::print(file, "{} {}", argType.name, argName);
                        }
                        if (i + 1 < method->args.size()) {
                            fmt::print(file, ", ");
                        }
                    }
                    fmt::print(file, ")");

                    // const qualifier
                    if (method->is_const) {
                        fmt::print(file, " const");
                    }

                    // bindings
                    auto bindStr = fmt::to_string(entry.fn->binds);
                    fmt::print(file, "{}", bindStr);
                    if (!entry.fn->inner.empty()) {
                        fmt::print(file, " {}", entry.fn->inner);
                    } else {
                        fmt::print(file, ";");
                    }

                    if (entry.trailingComment) {
                        fmt::print(file, " {}", entry.trailingComment->inner);
                    }

                    fmt::print(file, "\n");
                } else if (entry.kind == MethodEntry::Kind::Inline) {
                    // write inline field directly
                    fmt::print(file, "    {}", entry.inl->inner);
                    if (entry.trailingComment) {
                        fmt::print(file, " {}", entry.trailingComment->inner);
                    }
                    fmt::print(file, "\n");
                }
            }

            if (hasMembers && (!entries.empty() || hadTopLevelComment)) {
                fmt::println(file, "");
            }

            // members
            for (auto const& member : members) {
                // write comment
                for (auto* comment : member.comments) {
                    fmt::println(file, "    {}", comment->inner);
                }

                if (member.kind == MemberEntry::Kind::Field) {
                    auto* field = member.field;

                    // declaration
                    fmt::print(file, "    ");

                    // type and name
                    fmt::print(file, "{} {}", field->type.name, field->name);

                    // array count
                    if (field->count > 0) {
                        fmt::print(file, "[{}]", field->count);
                    }

                    fmt::print(file, ";");

                    if (member.trailingComment) {
                        fmt::print(file, " {}", member.trailingComment->inner);
                    }

                    fmt::println(file, "");
                } else if (member.kind == MemberEntry::Kind::Padding) {
                    auto* pad = member.pad;

                    // declaration
                    fmt::print(file, "    PAD");

                    // bindings
                    auto bindStr = fmt::to_string(pad->amount);
                    fmt::print(file, "{};", bindStr);

                    if (member.trailingComment) {
                        fmt::print(file, " {}", member.trailingComment->inner);
                    }

                    fmt::println(file, "");
                }
            }

            // trailing comments
            for (auto* comment : pendingComments) {
                fmt::println(file, "    {}", comment->inner);
            }

            // end of class
            fmt::println(file, "}}\n");
        }

        // free functions
        for (auto& fn : functions) {
            auto* method = &fn.prototype;

            // blank line if has docs
            if (!method->attributes.docs.empty()) {
                fmt::println(file, "");
            }

            // attributes
            auto attrs = formatAttributes(method->attributes, {});
            if (!attrs.empty()) {
                fmt::print(file, "{}", attrs);
            }

            fmt::print(file, "{} {}(", method->ret.name, method->name);

            // args
            bool shouldKeepDefaultNames = fn.inner.contains("p0");
            for (size_t i = 0; i < method->args.size(); ++i) {
                auto const& [argType, argName] = method->args[i];

                // if argName follows `p0`, `p1`, etc., we can omit it
                if (!shouldKeepDefaultNames && argName == fmt::format("p{}", i)) {
                    fmt::print(file, "{}", argType.name);
                } else {
                    fmt::print(file, "{} {}", argType.name, argName);
                }

                if (i + 1 < method->args.size()) {
                    fmt::print(file, ", ");
                }
            }

            fmt::print(file, ")");

            // bindings
            auto bindStr = fmt::to_string(fn.binds);
            fmt::print(file, "{}", bindStr);
            if (!fn.inner.empty()) {
                fmt::print(file, " {}", fn.inner);
            } else {
                fmt::print(file, ";");
            }

            fmt::print(file, "\n");
        }

        return Ok();
    }
}
