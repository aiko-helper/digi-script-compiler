// Container parsing for Digimon World 1 SCN files.
//
// MAPHEAD.SCN  - one inline script (N=1).
// DG.SCN       - 224 u32 file-offset pointers, then 223 scripts (N=224).
//
// Each individual script is an "SCNScript": u16 headerSize, then a table
// of {u16 sectionId, u16 sectionOffset} pairs terminated by sectionId ==
// 0xFFFF, then opcode bytes for each section.

#pragma once

#include "common.hpp"

#include <filesystem>
#include <string>
#include <unordered_map>
#include <vector>

namespace dd {

struct Section {
    u16             id;        // sectionId
    u16             offset;    // byte offset from start of the script
    u16             end;       // exclusive
    std::vector<u8> bytes;
};

// Per-script user-supplied section name overrides.  Loaded from names.toml.
// Key is the canonical section identity:
//   "<id>"            for unique-id sections        e.g. "5"
//   "<id>@0x<off>"    for duplicate-id sections      e.g. "81@0x19a"
// Value is the user's name (e.g. "mainMenu").  Sections with no entry
// fall back to the default name "section_<id>".
struct NameMap {
    std::unordered_map<std::string, std::string> byKey;
};

struct Script {
    int                  index;          // 0-based slot inside the container
    std::string          name;           // "MAP<N>.SCN" or "DG<N>.SCN" or "MAPHEAD.SCN"
    std::size_t          startOffset;    // file offset where this script starts
    std::size_t          endOffset;      // file offset where the next starts (or EOF)
    u16                  headerU16;      // first u16 of the script
    u16                  sentinelOffset; // 0xFFFF entry's "offset" field -- preserved for round-trip
    std::vector<Section> sections;
    NameMap              names;          // populated post-parse from names.toml
};

enum class ContainerKind { Maphead, DG };

struct ScriptContainer {
    std::filesystem::path path;
    std::vector<u8>       bytes;
    std::vector<Script>   scripts;
    u32                   alignment;     // DG only; default 0x800
    ContainerKind         kind;
};

// Parse a standalone SCN file (one inline script).
ScriptContainer parseMaphead(const std::filesystem::path& path);

// Parse DG.SCN -- `numberScripts` u32 pointers, `numberScripts - 1` scripts.
ScriptContainer parseDG(const std::filesystem::path& path, std::size_t numberScripts = 224);

// Auto-dispatch by filename: "DG.SCN" -> parseDG; otherwise parseMaphead.
ScriptContainer parseContainer(const std::filesystem::path& path);

} // namespace dd
