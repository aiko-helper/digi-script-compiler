// Game character codec: u16 codepoint <-> display string.
//
// Mirrors char-map.ts.  Two surfaces:
//
//   * gameCharacterStrict / charMapHas -- uses ONLY the small explicit
//     CHAR_MAP table (control glyphs + button icons + ASCII fast-path).
//     Drives the dead-string detector in disasm so it doesn't false-
//     positive on bytes that merely happen to decode as SJIS.
//
//   * gameCharacterRT / parseStringToU16s -- uses the full precomputed
//     u16 -> UTF-8 table (char_map_data.hpp), built once from the TS
//     gameCharacterRT.  Round-trip safe: collisions resolve to "<0xABCD>".

#pragma once

#include "common.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace dd {

// Membership test for the *small* explicit CHAR_MAP only (NOT the full RT
// table).  Matches `code in CHAR_MAP` from disasm.ts.
bool charMapHas(u16 code);

// Strict variant: small CHAR_MAP only; "" for code 0; otherwise "<0xABCD>".
std::string gameCharacterStrict(u16 code);

// Round-trip-safe full decode (CHAR_MAP + canonical SJIS, "<0xABCD>" for
// collisions).  Driven by the precomputed table.
std::string gameCharacterRT(u16 code);

// Token (single character or "<NAME>" or "<0xABCD>") -> u16.  Returns -1
// when the token is not in the reverse map and is not a "<0xHHHH>" form.
int tokenToU16(std::string_view tok);

// Parse a `.string` body (no surrounding quotes) into the encoded u16
// stream.  Recognises \\, \", \n, \r, \t escapes and <...> tokens.
// Throws std::runtime_error on unknown escape / token.
std::vector<u16> parseStringToU16s(std::string_view body);

// Quote a UTF-8 string with the same escape conventions as TS quoteString.
std::string quoteString(std::string_view s);

} // namespace dd
