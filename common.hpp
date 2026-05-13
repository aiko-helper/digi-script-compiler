// Small header-only utilities used across the port.
//
// Scope: little-endian integer reads/writes (matches DataView),
// file I/O wrappers (readFileSync/writeFileSync/existsSync),
// path helpers (basename/join),
// string helpers mimicking the TS flavour (startsWith, padStart, etc.).
//
// Everything here is std-only; no third-party deps.

#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>
#include <span>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <sstream>
#include <bit>

namespace dd {

using u8  = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using i8  = std::int8_t;
using i16 = std::int16_t;
using i32 = std::int32_t;

// --- Little-endian readers (DataView.getX(..., true) equivalents) ----------
// Bounds-checking is the caller's responsibility; all SCN parsing paths
// track cursors explicitly and we don't want a per-byte overhead tax.

inline u8  readU8 (std::span<const u8> b, std::size_t off) { return b[off]; }
inline i8  readI8 (std::span<const u8> b, std::size_t off) { return static_cast<i8>(b[off]); }
inline u16 readU16(std::span<const u8> b, std::size_t off) {
    return static_cast<u16>(b[off] | (static_cast<u16>(b[off + 1]) << 8));
}
inline i16 readI16(std::span<const u8> b, std::size_t off) {
    return static_cast<i16>(readU16(b, off));
}
inline u32 readU32(std::span<const u8> b, std::size_t off) {
    return static_cast<u32>(b[off])
         | (static_cast<u32>(b[off + 1]) << 8)
         | (static_cast<u32>(b[off + 2]) << 16)
         | (static_cast<u32>(b[off + 3]) << 24);
}
inline i32 readI32(std::span<const u8> b, std::size_t off) {
    return static_cast<i32>(readU32(b, off));
}

inline void writeU8 (std::vector<u8>& b, std::size_t off, u8 v)  { b[off] = v; }
inline void writeI8 (std::vector<u8>& b, std::size_t off, i8 v)  { b[off] = static_cast<u8>(v); }
inline void writeU16(std::vector<u8>& b, std::size_t off, u16 v) {
    b[off]     = static_cast<u8>(v & 0xff);
    b[off + 1] = static_cast<u8>((v >> 8) & 0xff);
}
inline void writeI16(std::vector<u8>& b, std::size_t off, i16 v) { writeU16(b, off, static_cast<u16>(v)); }
inline void writeU32(std::vector<u8>& b, std::size_t off, u32 v) {
    b[off]     = static_cast<u8>(v & 0xff);
    b[off + 1] = static_cast<u8>((v >> 8) & 0xff);
    b[off + 2] = static_cast<u8>((v >> 16) & 0xff);
    b[off + 3] = static_cast<u8>((v >> 24) & 0xff);
}
inline void writeI32(std::vector<u8>& b, std::size_t off, i32 v) { writeU32(b, off, static_cast<u32>(v)); }

// --- File I/O --------------------------------------------------------------

inline std::vector<u8> readFileBytes(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open " + p.string());
    in.seekg(0, std::ios::end);
    auto n = static_cast<std::streamsize>(in.tellg());
    in.seekg(0, std::ios::beg);
    std::vector<u8> out(static_cast<std::size_t>(n));
    if (n > 0) in.read(reinterpret_cast<char*>(out.data()), n);
    return out;
}

inline std::string readFileText(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open " + p.string());
    std::stringstream ss; ss << in.rdbuf();
    return ss.str();
}

inline void writeFileBytes(const std::filesystem::path& p, std::span<const u8> bytes) {
    std::ofstream out(p, std::ios::binary);
    if (!out) throw std::runtime_error("cannot write " + p.string());
    if (!bytes.empty()) out.write(reinterpret_cast<const char*>(bytes.data()),
                                  static_cast<std::streamsize>(bytes.size()));
}

inline void writeFileText(const std::filesystem::path& p, std::string_view text) {
    std::ofstream out(p, std::ios::binary);
    if (!out) throw std::runtime_error("cannot write " + p.string());
    if (!text.empty()) out.write(text.data(), static_cast<std::streamsize>(text.size()));
}

// --- String helpers (TS-shaped conveniences) -------------------------------

inline bool startsWith(std::string_view s, std::string_view p) {
    return s.size() >= p.size() && std::memcmp(s.data(), p.data(), p.size()) == 0;
}
inline bool endsWith(std::string_view s, std::string_view p) {
    return s.size() >= p.size() && std::memcmp(s.data() + s.size() - p.size(), p.data(), p.size()) == 0;
}

// padStart(width, '0') for hex numbers -- matches TS `.toString(16).padStart(n, "0")`.
inline std::string toHexPadded(std::uint64_t v, int width) {
    static const char hex[] = "0123456789abcdef";
    std::string out;
    do { out.push_back(hex[v & 0xf]); v >>= 4; } while (v != 0);
    while (static_cast<int>(out.size()) < width) out.push_back('0');
    // reverse
    for (std::size_t i = 0, j = out.size() - 1; i < j; ++i, --j) std::swap(out[i], out[j]);
    return out;
}
// Same but no minimum width -- just the hex digits of v (lowercase, no 0x).
inline std::string toHex(std::uint64_t v) {
    return toHexPadded(v, 1);
}

inline std::string toDec(long long v) {
    return std::to_string(v);
}

// Trim whitespace (spaces, tabs, CR, LF).
inline std::string_view trim(std::string_view s) {
    std::size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) a++;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) b--;
    return s.substr(a, b - a);
}

// Split on any run of ASCII whitespace, dropping empty tokens.
inline std::vector<std::string_view> splitWhitespace(std::string_view s) {
    std::vector<std::string_view> out;
    std::size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) i++;
        if (i >= s.size()) break;
        std::size_t start = i;
        while (i < s.size() && s[i] != ' ' && s[i] != '\t') i++;
        out.emplace_back(s.data() + start, i - start);
    }
    return out;
}

inline std::string basename(const std::filesystem::path& p) {
    return p.filename().string();
}

inline std::string toUpperAscii(std::string_view s) {
    std::string out(s);
    for (auto& c : out) if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
    return out;
}

} // namespace dd
