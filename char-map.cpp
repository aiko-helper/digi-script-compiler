#include "char-map.hpp"

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>

// ASCII-only mapping: every u16 outside the small explicit CHAR_MAP renders
// as the `<0xABCD>` placeholder (and the placeholder inverts cleanly via
// tokenToU16's hex path, so byte round-trip is preserved for arbitrary
// non-CHAR_MAP codepoints).  We do NOT carry an SJIS decoder.

namespace dd {

namespace {

// Small explicit CHAR_MAP (ported from char-map.ts top-level)
// This is the table used by the dead-string detector and by gameCharacterStrict.
// Order matches the TS source for clarity; lookup is by hash.
const std::unordered_map<u16, std::string_view>& smallCharMap() {
    static const std::unordered_map<u16, std::string_view> m = {
        {0x000d, "\n"},

        {0x0005, "<PLAYER>"},
        {0x0006, "<DIGIMON>"},
        {0x0007, "<DIGIMONTYPE>"},
        {0x000a, "<BITS>"},
        {0x000b, "<POINTS>"},
        {0x0011, "<CURRENT SONG>"},
        {0x0013, "<TOURNAMENTS WON>"},
        {0x0014, "<ARENA WINS>"},
        {0x0015, "<ARENA LOSSES>"},

        {0x0a01, "<ORANGE>"},
        {0x0901, "<GREY>"},
        {0x0801, "<BLACK>"},
        {0x0701, "<YELLOW>"},
        {0x0601, "<LIGHTBLUE>"},
        {0x0501, "<GREEN>"},
        {0x0401, "<PINK>"},
        {0x0301, "<RED>"},
        {0x0201, "<BLUE>"},
        {0x0101, "<WHITE>"},

        {0x0104, "<PROSPERITY>"},
        {0x6904, "<YEAR>"},
        {0x6a04, "<DAY>"},
        {0x6b04, "<HOUR>"},
        {0x6c04, "<MINUTE>"},

        {0x0010, "<DISCOUNT>"},
        {0x6707, "<DIGIMONTYPE2>"},
        {0xf911, "<SELECTED TRACK>"},
        {0xf909, "<SELECTED ITEM>"},
        {0x6e09, "<TREASURE ITEM>"},
        {0xc809, "<SOME ITEM>"},
        {0x0312, "<SELECTED TOURNAMENT>"},
        {0xf907, "<CARD>"},
        {0xf308, "<LOST MOVE>"},

        {0x4f82, "0"}, {0x5082, "1"}, {0x5182, "2"}, {0x5282, "3"}, {0x5382, "4"},
        {0x5482, "5"}, {0x5582, "6"}, {0x5682, "7"}, {0x5782, "8"}, {0x5882, "9"},

        {0x6082, "A"}, {0x6182, "B"}, {0x6282, "C"}, {0x6382, "D"}, {0x6482, "E"},
        {0x6582, "F"}, {0x6682, "G"}, {0x6782, "H"}, {0x6882, "I"}, {0x6982, "J"},
        {0x6a82, "K"}, {0x6b82, "L"}, {0x6c82, "M"}, {0x6d82, "N"}, {0x6e82, "O"},
        {0x6f82, "P"}, {0x7082, "Q"}, {0x7182, "R"}, {0x7282, "S"}, {0x7382, "T"},
        {0x7482, "U"}, {0x7582, "V"}, {0x7682, "W"}, {0x7782, "X"}, {0x7882, "Y"},
        {0x7982, "Z"},

        {0x8182, "a"}, {0x8282, "b"}, {0x8382, "c"}, {0x8482, "d"}, {0x8582, "e"},
        {0x8682, "f"}, {0x8782, "g"}, {0x8882, "h"}, {0x8982, "i"}, {0x8a82, "j"},
        {0x8b82, "k"}, {0x8c82, "l"}, {0x8d82, "m"}, {0x8e82, "n"}, {0x8f82, "o"},
        {0x9082, "p"}, {0x9182, "q"}, {0x9282, "r"}, {0x9382, "s"}, {0x9482, "t"},
        {0x9582, "u"}, {0x9682, "v"}, {0x9782, "w"}, {0x9882, "x"}, {0x9982, "y"},
        {0x9a82, "z"},

        {0x4081, " "},
        {0x4281, "."},
        {0x4381, ","},
        {0x4681, ":"},
        {0x4781, ";"},
        {0x4881, "?"},
        {0x4981, "!"},
        {0x5083, "û"},
        {0x6681, "'"},
        {0x7581, "'"},
        {0x7681, "\""},
        {0x7c81, "-"},

        {0x9b81, "<O>"},
        {0xa081, "<SQUARE>"},
        {0xa281, "<X>"},
        {0x7e81, "<TRIANGLE>"},
    };
    return m;
}

// Forward table: u16 -> UTF-8 (or nullptr -> placeholder fallback).  Seeded
// from the small explicit CHAR_MAP only.  O(1) lookup.
const std::array<const char*, 0x10000>& rtTable() {
    static const auto* t = []{
        auto* arr = new std::array<const char*, 0x10000>{};
        for (const auto& [code, sv] : smallCharMap()) {
            // smallCharMap stores std::string_view backed by string literals;
            // .data() is a valid C-string because the literal is nul-terminated.
            (*arr)[code] = sv.data();
        }
        return arr;
    }();
    return *t;
}

// Reverse: token (UTF-8) -> u16.  Built from the small CHAR_MAP only.
const std::unordered_map<std::string_view, u16>& reverseTokenTable() {
    static const auto& t = []() -> const std::unordered_map<std::string_view, u16>& {
        static std::unordered_map<std::string_view, u16> m;
        const auto& small = smallCharMap();
        m.reserve(small.size());
        for (const auto& [code, sv] : small) m.try_emplace(sv, code);
        return m;
    }();
    return t;
}

inline std::string hexToken(u16 v) {
    return std::string{"<0x"} + toHexPadded(v, 4) + ">";
}

} // namespace

bool charMapHas(u16 code) {
    const auto& m = smallCharMap();
    return m.find(code) != m.end();
}

std::string gameCharacterStrict(u16 code) {
    const auto& m = smallCharMap();
    auto it = m.find(code);
    if (it != m.end()) return std::string{it->second};
    if (code == 0) return {};
    return hexToken(code);
}

std::string gameCharacterRT(u16 code) {
    const char* p = rtTable()[code];
    if (p) return std::string{p};
    if (code == 0) return {};
    return hexToken(code);
}

int tokenToU16(std::string_view tok) {
    if (startsWith(tok, "<0x") && endsWith(tok, ">")) {
        // Parse "<0xABCD>" -- hex inside the angle brackets.
        std::string_view hex = tok.substr(3, tok.size() - 4);
        unsigned v = 0;
        for (char c : hex) {
            v <<= 4;
            if      (c >= '0' && c <= '9') v |= (c - '0');
            else if (c >= 'a' && c <= 'f') v |= (c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') v |= (c - 'A' + 10);
            else return -1;
        }
        return static_cast<int>(v);
    }
    const auto& rev = reverseTokenTable();
    auto it = rev.find(tok);
    if (it == rev.end()) return -1;
    return it->second;
}

namespace {
// Read one UTF-8 codepoint starting at body[i].  Returns the byte length
// (1..4) of the consumed sequence.  We don't care about the codepoint
// value here -- we re-use the source bytes as the lookup key into
// reverseTokenTable, which is keyed by UTF-8 strings.
int utf8Len(unsigned char lead) {
    if ((lead & 0x80) == 0)    return 1;
    if ((lead & 0xe0) == 0xc0) return 2;
    if ((lead & 0xf0) == 0xe0) return 3;
    if ((lead & 0xf8) == 0xf0) return 4;
    return 1; // malformed; treat as single byte to make progress
}
} // namespace

std::vector<u16> parseStringToU16s(std::string_view body) {
    std::vector<u16> out;
    std::size_t i = 0;
    while (i < body.size()) {
        char ch = body[i];

        if (ch == '\\' && i + 1 < body.size()) {
            char esc = body[i + 1];
            std::string_view u;
            switch (esc) {
                case '\\': u = "\\"; break;
                case '"':  u = "\""; break;
                case 'n':  u = "\n"; break;
                case 'r':  u = "\r"; break;
                case 't':  u = "\t"; break;
                default:
                    throw std::runtime_error(std::string{"unknown escape \\"} + esc);
            }
            int v = tokenToU16(u);
            if (v < 0) throw std::runtime_error(std::string{"unmapped char in string"});
            out.push_back(static_cast<u16>(v));
            i += 2;
            continue;
        }

        if (ch == '<') {
            std::size_t close = body.find('>', i);
            if (close == std::string_view::npos) {
                throw std::runtime_error("unterminated token in string");
            }
            std::string_view tok = body.substr(i, close - i + 1);
            int v = tokenToU16(tok);
            if (v < 0) throw std::runtime_error(std::string{"unknown token "} + std::string{tok});
            out.push_back(static_cast<u16>(v));
            i = close + 1;
            continue;
        }

        // Single UTF-8 codepoint.  CHAR_MAP keys are full UTF-8 byte
        // sequences for the codepoint, so we use the raw bytes as the key.
        int n = utf8Len(static_cast<unsigned char>(ch));
        if (i + static_cast<std::size_t>(n) > body.size()) n = 1;
        std::string_view key = body.substr(i, n);
        int v = tokenToU16(key);
        if (v < 0) {
            throw std::runtime_error(std::string{"unmapped char \""} + std::string{key} + "\" in string");
        }
        out.push_back(static_cast<u16>(v));
        i += n;
    }
    return out;
}

std::string quoteString(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 2);
    out.push_back('"');
    for (char c : s) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"':  out += "\\\""; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:   out.push_back(c); break;
        }
    }
    out.push_back('"');
    return out;
}

} // namespace dd
