// Assemble .digi text back into a byte-exact SCN file.
//
// Inverse of disasm.cpp + container.cpp.  Two passes:
//   1) parse all lines; compute each section's byte size by summing
//      instruction sizes; lay out each script.
//   2) emit bytes with target labels resolved against pass-1 offsets.
//
// `;!container`, `;!file`, `;!alignment`, `;!script`, `;!sections` directives
// carry round-trip metadata (pointer-table layout, filename table) that
// isn't otherwise derivable from the text.

#pragma once

#include "common.hpp"
#include "symbols.hpp"

#include <filesystem>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace dd {

struct Instr {
    std::string body;                   // mnemonic + args, as written
    std::size_t size = 0;
    std::vector<std::string> labels;    // labels preceding this instr (share its offset)
    std::string srcFile;                // source filename (empty until #line tracked)
    int         srcLine = 0;            // 1-based
    int         srcCol = 0;             // 1-based; column of first non-whitespace char
};

struct SecAST {
    int         id;
    bool        hasDisambig = false;
    u16         disambig = 0;
    std::string name;
    std::vector<Instr> instrs;
    std::size_t offset = 0;
    std::size_t size = 0;
    std::unordered_map<std::string, std::size_t> labelMap;  // filled in pass 1
    std::vector<std::string> trailingLabels;                // labels after the last instr
};

struct ScriptAST {
    int         index = 0;
    std::size_t startOffset = 0;
    std::size_t endOffset = 0;
    u16         headerU16 = 0;
    u16         sentinelOff = 0;
    std::vector<SecAST> sections;
    SymbolTable localSymbols;   // bindings declared in `symbols { ... }` blocks
};

struct FileRecord { int slot; std::string name; };

enum class AsmKind { Maphead, DG };

struct ContainerAST {
    AsmKind                  kind = AsmKind::Maphead;
    std::vector<FileRecord>  files;       // DG only
    u32                      alignment = 0x800; // DG only
    std::vector<ScriptAST>   scripts;
};

ContainerAST    parseSource(std::string_view text);

// Optional sourcemap entry: one per emitted instruction.  Sorted by fileOff
// in the order spans are produced.
struct EmitSpan {
    std::size_t fileOff;       // absolute byte offset in the assembled SCN
    std::size_t length;        // bytes emitted for this instruction
    int         scriptIndex;
    int         sectionId;
    u16         sectionDisambig;  // section's start offset within its script
    std::string source;        // source filename if known (from #line), else empty
    int         line;          // 1-based; 0 if unknown
    int         col;           // 1-based; 0 if unknown
    std::string body;          // the instruction body as written
};
struct EmitMap {
    std::vector<EmitSpan> spans;
};

std::vector<u8> assembleContainer(ContainerAST& ast, EmitMap* outMap = nullptr);

} // namespace dd
