// Variable-length opcode decoders.
//
// Each decoder is invoked with the section bytes and `after` = offset of
// the first argument byte (so the opcode byte itself sits at `after - 1`).
// Returns the rendered C-statement body, the number of bytes consumed
// (including the opcode byte), and the list of script-relative target
// offsets the instruction references.
//
// On a truncation / unknown sub-op the decoder throws std::runtime_error;
// the disasm path catches and falls back to a raw `bytes` run.

#pragma once

#include "common.hpp"
#include "container.hpp"
#include "targets.hpp"

#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

namespace dd {

struct Decoded {
    std::string text;       // C-statement form, no trailing semicolon
    std::size_t consumed;   // bytes (including the opcode byte)
};

// Decoder signature.  `currentSec` is the section the decoded instruction
// lives in; passed to resolveLabel so intra-section targets render as
// bare `L_<4hex>`.  `labels` is mutated: every resolved target adds itself
// to its target section's label set.
using Decoder = std::function<Decoded(std::span<const u8> bytes,
                                      std::size_t after,
                                      std::size_t sectionEnd,
                                      const Script* script,
                                      const Section* currentSec,
                                      LabelMap* labels)>;

// Opcode -> decoder.  Empty (find()==end()) means "not a custom opcode".
const std::unordered_map<u8, Decoder>& customDecoders();

} // namespace dd
