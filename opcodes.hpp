// Opcode definitions for the Digimon World 1 script VM.
//
// FIXED_OPCODES is a direct port of opcode-table.ts (itself generated from
// SydMontague/DW1JavaTool).  CUSTOM_OPCODES lists opcodes whose argument
// layout is variable-length; their decoders live in custom-ops.{hpp,cpp}.
//
// Ground truth: https://github.com/SydMontague/DW1JavaTool

#pragma once

#include "common.hpp"

#include <array>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace dd {

enum class FieldKind : u8 { U8, S8, U16, S16, U32, S32 };

struct Field {
    std::string_view n;
    FieldKind        k;
};

struct FixedOpcode {
    std::string_view   mnemonic;
    u8                 size;
    std::vector<Field> fields;
};

// Byte widths per field kind; matches FIELD_SIZE in opcodes.ts.
constexpr std::array<u8, 6> FIELD_SIZE = { 1, 1, 2, 2, 4, 4 };

inline u8 fieldSize(FieldKind k) { return FIELD_SIZE[static_cast<std::size_t>(k)]; }

// Read one field value from `bytes` at `offset` using LE encoding.
// Signed kinds return their value widened to i32 (TS mirror: getInt*).
// Unsigned kinds return their value as i32 too (all numeric results live
// in signed-32 space to match TS's Number model where needed).
inline i32 readField(std::span<const u8> bytes, std::size_t off, FieldKind k) {
    switch (k) {
        case FieldKind::U8:  return static_cast<i32>(readU8(bytes, off));
        case FieldKind::S8:  return static_cast<i32>(readI8(bytes, off));
        case FieldKind::U16: return static_cast<i32>(readU16(bytes, off));
        case FieldKind::S16: return static_cast<i32>(readI16(bytes, off));
        case FieldKind::U32: return static_cast<i32>(readU32(bytes, off));
        case FieldKind::S32: return readI32(bytes, off);
    }
    return 0;
}

// Opcode byte -> FixedOpcode.  Missing keys mean "not fixed-length" (may
// still be a custom opcode); callers query both tables.
using FixedOpcodeTable = std::unordered_map<u8, FixedOpcode>;

const FixedOpcodeTable& fixedOpcodes();

struct CustomOpcode {
    u8               op;
    std::string_view mnemonic;
};

// Variable-length opcodes handled by hand-written decoders.
const std::vector<CustomOpcode>& customOpcodes();

// Mnemonic synonyms
// User-facing aliases for canonical FixedOpcode mnemonics, optionally with
// per-field name aliases.  Disasm renders in the synonym's named-arg form;
// asm accepts the synonym anywhere the canonical mnemonic was accepted.
struct MnemonicSynonym {
    std::string_view user;
    std::string_view canonical;
    std::vector<std::pair<std::string_view, std::string_view>> fieldAliases;
};

const std::vector<MnemonicSynonym>& mnemonicSynonyms();
const MnemonicSynonym* findSynonymByUser(std::string_view user);
const MnemonicSynonym* findSynonymByCanonical(std::string_view canonical);
std::string_view translateFieldName(const MnemonicSynonym* syn, std::string_view userFieldName);
// Reverse: canonical -> user-facing field name (for disasm).
std::string_view reverseFieldName(const MnemonicSynonym* syn, std::string_view canonicalFieldName);

} // namespace dd
