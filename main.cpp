// CLI entrypoint for digi-disasm.
//
// Usage:
//   digi-disasm <input.SCN> <out-path>
//     -- single-SCN input (e.g. MAPHEAD.SCN): writes one .dgs file at <out-path>
//       containing the entire script (pragmas + symbols + all sections inline).
//     -- archive input (DG.SCN): treats <out-path> as a directory, writes
//       <out-path>/_metadata.dgs plus one <member>.dgs per non-empty slot
//       (e.g. MAP192.dgs, DG221.dgs).
//
//   digi-disasm --assemble <in-path> <output.SCN>
//     -- accepts either a single .dgs file or a directory of .dgs files
//       (archive shape).  Round-trip is byte-exact against the original SCN.
//
//   digi-disasm --diff <in-path> <reference.SCN>
//     -- first-divergence diagnostic: maps a failing byte back to source via
//       the EmitMap produced during assembly.

#include "common.hpp"
#include "container.hpp"
#include "disasm.hpp"
#include "assemble.hpp"
#include "targets.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <unordered_set>
#include <vector>

namespace fs = std::filesystem;

namespace {

[[noreturn]] void usage() {
    std::fprintf(stderr, "usage: digi-disasm <input.SCN> <out-path>\n");
    std::fprintf(stderr, "   or: digi-disasm --assemble <in-path> <output.SCN>\n");
    std::fprintf(stderr, "   or: digi-disasm --diff <in-path> <reference.SCN>\n");
    std::exit(2);
}

// Strip a trailing `.SCN`/`.scn` suffix and append `.dgs`.
std::string dgsNameFor(std::string_view scnName) {
    std::string out{scnName};
    if (out.size() >= 4) {
        std::string suf = out.substr(out.size() - 4);
        if (suf == ".SCN" || suf == ".scn") out.resize(out.size() - 4);
    }
    out += ".dgs";
    return out;
}

// Copy a user-owned input (entities.dgs, functions.dgs) from CWD to the
// output directory so per-script `#include "<name>"` resolves locally.
// Silently skips when the CWD copy is absent -- assemble will then fail
// with a clear "cannot open" message, which is the intended behaviour.
void copyCwdFile(const fs::path& dir, const char* name) {
    fs::path src{name};
    if (!fs::exists(src)) return;
    fs::path dst = dir / name;
    if (fs::absolute(src) == fs::absolute(dst)) return;  // same file (CWD == output)
    dd::writeFileText(dst, dd::readFileText(src));
}

// Write one script as a single .dgs file: pragmas, then sections in their
// canonical (script.sections[]) order.  That order determines the SCN's
// section-table byte layout, so file order must match.
void writeScriptDgs(const fs::path& path,
                    const dd::Script& script,
                    const dd::ScriptDisasm& rendered,
                    bool isStandaloneSCN) {
    std::vector<std::string> lines;

    {
        std::string head = "// ";
        head += script.name.empty() ? (std::string{"script "} + dd::toDec(script.index)) : script.name;
        lines.push_back(std::move(head));
    }
    if (isStandaloneSCN) lines.emplace_back("#pragma container");
    lines.emplace_back("#include \"functions.dgs\"");

    {
        std::string s = "#pragma script index=";
        s += dd::toDec(script.index);
        s += " start=0x";       s += dd::toHex(script.startOffset);
        s += " end=0x";         s += dd::toHex(script.endOffset);
        s += " headerU16=0x";   s += dd::toHex(script.headerU16);
        s += " sentinelOff=0x"; s += dd::toHex(script.sentinelOffset);
        lines.push_back(std::move(s));
    }

    // entities.dgs has `symbols { ... }` blocks which require curScript to be
    // set (per assemble.cpp's parser).  So the include lives AFTER the
    // #pragma script directive, not at the top of the file.
    lines.emplace_back("#include \"entities.dgs\"");

    // Emit sections in their canonical (script.sections[]) order -- that order
    // determines the byte layout of the SCN's section table, so file order
    // must match.
    for (std::size_t i = 0; i < script.sections.size(); ++i) {
        lines.emplace_back("");
        for (const auto& l : rendered.perSection[i]) lines.push_back(l);
    }

    std::string text;
    for (const auto& l : lines) { text += l; text += '\n'; }

    fs::path parent = path.parent_path();
    if (!parent.empty()) fs::create_directories(parent);
    dd::writeFileText(path, text);
}

// Archive-level metadata: container marker, alignment, and slot->name table.
void writeArchiveMetadata(const fs::path& dir, const dd::ScriptContainer& c) {
    std::vector<std::string> lines;
    lines.emplace_back("// archive metadata");
    lines.emplace_back("#pragma container");
    lines.emplace_back("#include \"functions.dgs\"");
    {
        std::string l = "#pragma alignment 0x";
        l += dd::toHex(c.alignment);
        lines.push_back(std::move(l));
    }
    for (const auto& s : c.scripts) {
        std::string l = "#pragma file ";
        l += dd::toDec(s.index);
        l += ' ';
        l += s.name;
        lines.push_back(std::move(l));
    }
    std::string text;
    for (const auto& l : lines) { text += l; text += '\n'; }
    dd::writeFileText(dir / "_metadata.dgs", text);
}

// Recursively expand `#include "path"` directives.  Paths resolve relative
// to the includer's directory.  Idempotent -- including the same canonical
// path twice expands it once (safe for shared-macro headers pulled in by
// many files).  `#line` directives are emitted around the include so that
// error locations downstream stay accurate.
std::string expandIncludes(const std::string& text,
                           const fs::path& baseDir,
                           const std::string& includerFile,
                           std::unordered_set<std::string>& seen) {
    std::string out;
    out.reserve(text.size());
    std::size_t pos = 0;
    int curLine = 0;
    while (pos < text.size()) {
        std::size_t eol = text.find('\n', pos);
        std::string_view rawLine = (eol == std::string::npos)
            ? std::string_view{text}.substr(pos)
            : std::string_view{text}.substr(pos, eol - pos);
        curLine++;
        std::string_view tl = dd::trim(rawLine);
        if (dd::startsWith(tl, "#include")) {
            std::string_view r = dd::trim(tl.substr(8));
            if (r.size() >= 2 && r.front() == '"' && r.back() == '"') {
                fs::path incPath = baseDir / std::string{r.substr(1, r.size() - 2)};
                fs::path canon = fs::weakly_canonical(incPath);
                std::string canonStr = canon.string();
                if (!seen.count(canonStr)) {
                    seen.insert(canonStr);
                    std::string incText = dd::readFileText(canon);
                    out += "#line 1 \"";
                    out += canonStr;
                    out += "\"\n";
                    out += expandIncludes(incText, canon.parent_path(), canonStr, seen);
                    if (!out.empty() && out.back() != '\n') out += '\n';
                }
                if (!includerFile.empty()) {
                    out += "#line ";
                    out += std::to_string(curLine + 1);
                    out += " \"";
                    out += includerFile;
                    out += "\"\n";
                }
                if (eol == std::string::npos) break;
                pos = eol + 1;
                continue;
            }
        }
        out.append(rawLine);
        if (eol == std::string::npos) break;
        out += '\n';
        pos = eol + 1;
    }
    return out;
}

// Read either a single .dgs file or an archive directory and produce a single
// concatenated source string ready for parseSource.  `#line` directives
// preserve per-file source paths in the EmitMap.
std::string readDgsInput(const fs::path& p) {
    if (!fs::exists(p)) {
        throw std::runtime_error("input not found: " + p.string());
    }

    std::unordered_set<std::string> seen;

    if (fs::is_regular_file(p)) {
        std::string out;
        out += "#line 1 \"";
        out += p.string();
        out += "\"\n";
        out += expandIncludes(dd::readFileText(p), p.parent_path(), p.string(), seen);
        return out;
    }

    fs::path metaPath = p / "_metadata.dgs";
    if (!fs::exists(metaPath)) {
        throw std::runtime_error("not a .dgs archive (no _metadata.dgs): " + p.string());
    }
    std::string meta = dd::readFileText(metaPath);

    std::string out;
    out += "#line 1 \"";
    out += metaPath.string();
    out += "\"\n";
    out += expandIncludes(meta, metaPath.parent_path(), metaPath.string(), seen);

    // Walk `#pragma file <slot> <name>` lines and append each member's .dgs.
    std::size_t pos = 0;
    while (pos < meta.size()) {
        std::size_t eol = meta.find('\n', pos);
        std::string_view line = std::string_view{meta}.substr(pos,
            (eol == std::string::npos) ? meta.size() - pos : eol - pos);
        std::string_view tl = dd::trim(line);
        if (dd::startsWith(tl, "#pragma file")) {
            auto toks = dd::splitWhitespace(tl.substr(12));
            if (toks.size() >= 2) {
                fs::path sub = p / dgsNameFor(toks[1]);
                if (fs::exists(sub)) {
                    out += '\n';
                    out += "#line 1 \"";
                    out += sub.string();
                    out += "\"\n";
                    out += expandIncludes(dd::readFileText(sub), sub.parent_path(), sub.string(), seen);
                }
            }
        }
        if (eol == std::string::npos) break;
        pos = eol + 1;
    }
    return out;
}

// command handlers

int doSplit(const std::string& input, const std::string& outPath) {
    auto c = dd::parseContainer(input);

    if (c.kind == dd::ContainerKind::Maphead) {
        fs::path p{outPath};
        fs::path parent = p.parent_path();
        if (parent.empty()) parent = ".";
        fs::create_directories(parent);
        copyCwdFile(parent, "entities.dgs");
        copyCwdFile(parent, "functions.dgs");
        writeScriptDgs(p, c.scripts[0], dd::disasmScript(c.scripts[0]),
                       /*isStandaloneSCN=*/true);
        std::printf("wrote %s\n", p.string().c_str());
    } else {
        fs::path dir{outPath};
        fs::create_directories(dir);
        copyCwdFile(dir, "entities.dgs");
        copyCwdFile(dir, "functions.dgs");
        writeArchiveMetadata(dir, c);
        std::size_t count = 0;
        for (const auto& script : c.scripts) {
            if (script.sections.empty() && script.startOffset == script.endOffset) continue;
            writeScriptDgs(dir / dgsNameFor(script.name), script, dd::disasmScript(script),
                           /*isStandaloneSCN=*/false);
            count++;
        }
        std::printf("wrote %zu .dgs files to %s/\n", count, dir.string().c_str());
    }
    return 0;
}

// --diff: first-divergence diagnostic
int doDiff(const std::string& inPath, const std::string& refPath) {
    auto refBytes = dd::readFileBytes(refPath);

    std::string text = readDgsInput(inPath);
    auto ast = dd::parseSource(text);

    dd::EmitMap emitMap;
    auto reasm = dd::assembleContainer(ast, &emitMap);

    const std::size_t n = std::min(refBytes.size(), reasm.size());
    std::size_t i = 0;
    while (i < n && refBytes[i] == reasm[i]) ++i;

    if (i == n && refBytes.size() == reasm.size()) {
        std::printf("PARITY: identical (%zu bytes)\n", refBytes.size());
        return 0;
    }

    if (refBytes.size() != reasm.size()) {
        std::printf("SIZE: reference=%zu reasm=%zu (delta %+lld)\n",
            refBytes.size(), reasm.size(),
            static_cast<long long>(reasm.size()) - static_cast<long long>(refBytes.size()));
    }

    if (i == n) {
        std::printf("DIVERGE: bytes match up to offset 0x%zx; "
                    "longer file has %zu extra bytes\n",
            i, std::max(refBytes.size(), reasm.size()) - n);
        return 1;
    }

    const auto& spans = emitMap.spans;
    const dd::EmitSpan* span = nullptr;
    auto it = std::upper_bound(spans.begin(), spans.end(), i,
        [](std::size_t off, const dd::EmitSpan& s){ return off < s.fileOff; });
    if (it != spans.begin()) {
        --it;
        if (it->fileOff <= i && i < it->fileOff + it->length) span = &*it;
    }

    std::printf("DIVERGE at file offset 0x%zx (decimal %zu)\n", i, i);
    if (span) {
        std::printf("  source:   %s:%d:%d\n",
            span->source.empty() ? "<unknown>" : span->source.c_str(),
            span->line, span->col);
        std::printf("  script:   %d, section: %d (disambig 0x%04x)\n",
            span->scriptIndex, span->sectionId, span->sectionDisambig);
        std::printf("  opcode:   %s\n", span->body.c_str());
        std::printf("  span:     [0x%zx, 0x%zx) length %zu, diff at byte %zu of span\n",
            span->fileOff, span->fileOff + span->length, span->length, i - span->fileOff);
    } else {
        std::printf("  source:   <no opcode span -- likely in a script header / pointer table>\n");
    }

    auto hexWindow = [&](const std::vector<dd::u8>& v) -> std::string {
        std::size_t lo = (i >= 8) ? i - 8 : 0;
        std::size_t hi = std::min(i + 9, v.size());
        std::string s;
        for (std::size_t k = lo; k < hi; ++k) {
            if (k == i) s += '[';
            s += dd::toHexPadded(v[k], 2);
            if (k == i) s += ']';
            if (k + 1 < hi) s += ' ';
        }
        return s;
    };
    std::printf("  expected: %s\n", hexWindow(refBytes).c_str());
    std::printf("  got:      %s\n", hexWindow(reasm).c_str());

    return 1;
}

int doAssemble(const std::string& inPath, const std::string& outPath) {
    std::string text = readDgsInput(inPath);
    auto ast = dd::parseSource(text);
    auto bytes = dd::assembleContainer(ast);
    dd::writeFileBytes(outPath, bytes);
    std::printf("wrote %zu bytes to %s\n", bytes.size(), outPath.c_str());
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) usage();

    std::string a1 = argv[1];
    if (a1 == "--assemble") {
        if (argc != 4) usage();
        try { return doAssemble(argv[2], argv[3]); }
        catch (const std::exception& e) {
            std::fprintf(stderr, "error: %s\n", e.what()); return 1;
        }
    }
    if (a1 == "--diff") {
        if (argc != 4) usage();
        try { return doDiff(argv[2], argv[3]); }
        catch (const std::exception& e) {
            std::fprintf(stderr, "error: %s\n", e.what()); return 1;
        }
    }

    if (argc != 3) usage();
    try { return doSplit(argv[1], argv[2]); }
    catch (const std::exception& e) {
        std::fprintf(stderr, "error: %s\n", e.what()); return 1;
    }
}
