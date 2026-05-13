// Disassemble a parsed SCN container into .dgs text (C-like syntax).
//
// Output shape:
//
//   section <name>(<id>[, 0x<dis>]) {  // len=...
//       mnemonic(arg, arg);
//       if (<expr>) goto L_NNNN;
//   L_NNNN:
//       return;
//   }
//
// Whitespace is not load-bearing for the parser, but the emitter uses a
// consistent four-space indent inside sections and labels at column 0.

#pragma once

#include "common.hpp"
#include "container.hpp"
#include "targets.hpp"

#include <string>
#include <vector>

namespace dd {

// Disassembled body lines, one block per section in `script.sections` order.
struct ScriptDisasm {
    std::vector<std::vector<std::string>> perSection;
};

ScriptDisasm disasmScript(const Script& script);

} // namespace dd
