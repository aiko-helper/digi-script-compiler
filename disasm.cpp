#include "disasm.hpp"
#include "char-map.hpp"
#include "common.hpp"
#include "custom-ops.hpp"
#include "opcodes.hpp"
#include "predicate_neg.hpp"
#include "symbols.hpp"
#include "targets.hpp"

#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

namespace dd {

namespace {

constexpr std::string_view INDENT = "  "; // two-space body indent

// Fixed opcodes whose s16 fields are script-byte-offsets (not bare numbers).
bool isTargetField(std::string_view mnemonic, std::string_view fieldName) {
    if (mnemonic == "jump" && fieldName == "target") return true;
    if (mnemonic == "jumpAndLink" && fieldName == "value") return true;
    return false;
}

bool isTextOpByte(u8 b) {
    return b == 0x0d || b == 0x81 || b == 0x82;
}

std::size_t countDeadStringPairs(std::span<const u8> b, std::size_t pc) {
    std::size_t cursor = pc;
    std::size_t count = 0;
    while (cursor + 1 < b.size() && isTextOpByte(b[cursor])) {
        u16 code = static_cast<u16>(b[cursor]) | (static_cast<u16>(b[cursor + 1]) << 8);
        if (!charMapHas(code)) break;
        count++;
        cursor += 2;
    }
    return count;
}

bool canDecodeFirstOp(std::span<const u8> bytes, const Script* script,
                     const Section* sec) {
    if (bytes.empty()) return true;
    u8 op = bytes[0];
    const auto& cdmap = customDecoders();
    auto cit = cdmap.find(op);
    if (cit != cdmap.end() && script) {
        try {
            Decoded d = cit->second(bytes, 1, bytes.size(), script, sec, nullptr);
            if (d.consumed >= 1 && d.consumed <= bytes.size()) return true;
        } catch (...) { /* truncated */ }
    }
    const auto& fxmap = fixedOpcodes();
    auto fit = fxmap.find(op);
    return fit != fxmap.end() && fit->second.size <= bytes.size();
}


// Extract (fieldName, argValueText) pairs for a fixed-opcode instruction.
// Empty (zero-valued `empty` slot) fields are dropped.
struct FieldArg { std::string_view fieldName; std::string value; };

std::vector<FieldArg> extractFieldArgs(const FixedOpcode& def,
                                       std::span<const u8> bytes,
                                       std::size_t pc,
                                       const Script* script,
                                       const Section* currentSec,
                                       LabelMap* labels) {
    std::vector<FieldArg> out;
    std::size_t cursor = pc + 1;
    for (const auto& f : def.fields) {
        i32 val = readField(bytes, cursor, f.k);
        cursor += fieldSize(f.k);
        if (f.n == "empty" && val == 0) continue;
        std::string text;
        if (script && isTargetField(def.mnemonic, f.n)) {
            text = resolveLabel(*script, currentSec, val, labels);
        } else if (auto sk = fieldSymbolKind(def.mnemonic, f.n)) {
            std::string name = symbolTable().lookupName(*sk, static_cast<int>(val));
            if (!name.empty()) {
                text = std::string{symKindLabel(*sk)};
                text += '.';
                text += name;
            } else {
                // Unnamed but kinded: emit `Kind(N)` so the type is still
                // visible in the source.  The assembler parses this back to
                // the same int via parseNumOrSym's `Kind(N)` rule.
                text = std::string{symKindLabel(*sk)};
                text += '(';
                text += toDec(static_cast<long long>(val));
                text += ')';
            }
        } else {
            text = toDec(static_cast<long long>(val));
        }
        out.push_back({ f.n, std::move(text) });
    }
    return out;
}

// Render a fixed-opcode line as `mnemonic(arg, arg, ...)` (no semicolon).
// `endSection` is surfaced as bare `return`.  `jump <target>` becomes
// `goto <label>` (no parens).  Synonym-bearing opcodes (e.g. `storeRandom`
// -> `roll`) render in named-arg form using the synonym's user field names.
std::string renderFixed(const FixedOpcode& def,
                        std::span<const u8> bytes,
                        std::size_t pc,
                        const Script* script,
                        const Section* currentSec,
                        LabelMap* labels) {
    auto args = extractFieldArgs(def, bytes, pc, script, currentSec, labels);

    if (def.mnemonic == "endSection" && args.empty()) return "return";
    if (def.mnemonic == "jump" && args.size() == 1) {
        return "goto " + args[0].value;
    }

    // `pstat[<idx>] = time()` sugar for `storeDate(<idx>)`.  When the pstat
    // index resolves to a bound `PStat.Name`, emit the ruby-style `:Name`
    // bare form for symmetry with `removeItems([:A, ...])`.
    if (def.mnemonic == "storeDate" && args.size() == 1) {
        const std::string& v = args[0].value;
        std::string idx;
        if (v.size() > 6 && v.compare(0, 6, "PStat.") == 0) {
            idx = ":";
            idx.append(v, 6, std::string::npos);
        } else {
            idx = v;
        }
        return "pstat[" + idx + "] = time()";
    }

    // Movement family -- unified verbs `move` / `moveCamera` / `look` / `rotate` /
    // `teleport` / `warp` with kind-named args.  Falls through if not movement.
    {
        std::string_view m = def.mnemonic;
        auto& a = args;
        auto sz = a.size();
        if (m == "entityWalkTo" && sz == 4) {
            return "move(entity: " + a[0].value + ", to: (" + a[1].value + ", " + a[2].value + "), sprint: " + a[3].value + ")";
        }
        if (m == "entityWalkToEntity" && sz == 3) {
            return "move(entity: " + a[0].value + ", to: " + a[2].value + ", sprint: " + a[1].value + ")";
        }
        if (m == "entityWalkToWithCamera" && sz == 4) {
            return "move(entity: " + a[0].value + ", to: (" + a[1].value + ", " + a[2].value + "), sprint: " + a[3].value + ", withCamera: true)";
        }
        if (m == "entityWalkToEntityWithCamera" && sz == 3) {
            return "move(entity: " + a[0].value + ", to: " + a[2].value + ", sprint: " + a[1].value + ", withCamera: true)";
        }
        if (m == "moveEntityTo" && sz == 4) {
            return "move(entity: " + a[0].value + ", to: (" + a[1].value + ", " + a[2].value + "), animDuration: " + a[3].value + ")";
        }
        if (m == "moveEntityToAxis" && sz == 4) {
            return "move(entity: " + a[0].value + ", axis: " + a[2].value + ", to: " + a[1].value + ", speed: " + a[3].value + ")";
        }
        if (m == "moveEntityToAxisWithCamera" && sz == 4) {
            return "move(entity: " + a[0].value + ", axis: " + a[2].value + ", to: " + a[1].value + ", speed: " + a[3].value + ", withCamera: true)";
        }
        if (m == "moveCameraTo" && sz == 3) {
            return "moveCamera(to: (" + a[1].value + ", " + a[2].value + "), slowdown: " + a[0].value + ")";
        }
        if (m == "moveCameraToEntity" && sz == 2) {
            return "moveCamera(to: " + a[0].value + ", speed: " + a[1].value + ")";
        }
        if (m == "lookAt" && sz == 2) {
            return "look(entity: " + a[0].value + ", at: " + a[1].value + ")";
        }
        if (m == "setRotation" && sz == 2) {
            return "rotate(entity: " + a[0].value + ", to: " + a[1].value + ")";
        }
        if (m == "teleport" && sz == 1) {
            return "teleport(pstat: " + a[0].value + ")";
        }
        if (m == "warpTo" && sz == 3) {
            return "warp(to: " + a[0].value + ", spawn: " + a[1].value + ", trigger: " + a[2].value + ")";
        }
    }

    if (const auto* syn = findSynonymByCanonical(def.mnemonic)) {
        std::string out{syn->user};
        out += '(';
        for (std::size_t i = 0; i < args.size(); ++i) {
            if (i) out += ", ";
            out += reverseFieldName(syn, args[i].fieldName);
            out += ": ";
            out += args[i].value;
        }
        out += ')';
        return out;
    }

    // Named-arg rendering is opt-in per opcode -- we only switch on it for
    // opcodes whose field names have been hand-vetted (otherwise misleading
    // names get baked into otherwise-correct disassembly).  When opted in,
    // first arg stays positional (it usually carries a typed kind like
    // `Item.X`); the rest get `field: value`.  Parser always accepts both
    // forms either way.
    auto preferNamedDisasm = [](std::string_view mn) {
        return mn == "spawnItem";
    };
    std::string out{def.mnemonic};
    out += '(';
    const bool useNamed = args.size() >= 2 && preferNamedDisasm(def.mnemonic);
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (i) out += ", ";
        if (useNamed && i >= 1 && args[i].fieldName != "empty") {
            out.append(args[i].fieldName);
            out += ": ";
        }
        out += args[i].value;
    }
    out += ')';
    return out;
}

struct DecodedInstr {
    std::size_t offset;     // in-section offset
    std::size_t consumed;   // bytes
    std::string body;       // C statement body (no trailing semicolon)
};

// Decode one section into a vector of statements and a set of in-section
// label offsets.  `labels` is shared across all sections in the script --
// targets that land outside the current section are registered against
// their containing section's index.
std::vector<DecodedInstr> decodeSectionStmts(const Section& s,
                                             const Script& script,
                                             LabelMap& labels,
                                             std::size_t /*indexOfSection*/) {
    std::vector<DecodedInstr> out;
    if (s.bytes.empty()) return out;

    std::span<const u8> b{s.bytes};
    const Script* sp = &script;
    const Section* secp = &s;

    // Orphan-data section: first byte won't decode as any known opcode.
    if (!canDecodeFirstOp(b, sp, secp)) {
        std::string body = "bytes {";
        if (!b.empty()) body += ' ';
        for (std::size_t i = 0; i < b.size(); ++i) {
            if (i) body += ' ';
            body += toHexPadded(b[i], 2);
        }
        if (!b.empty()) body += ' ';
        body += '}';
        out.push_back({0, b.size(), std::move(body)});
        return out;
    }

    std::size_t pc = 0;
    long long rawStart = -1;

    auto flushRaw = [&](std::size_t endPc) {
        if (rawStart < 0) return;
        const std::size_t start = static_cast<std::size_t>(rawStart);
        std::size_t n = endPc - start;
        std::string body = "bytes {";
        if (n) body += ' ';
        for (std::size_t i = 0; i < n; ++i) {
            if (i) body += ' ';
            body += toHexPadded(b[start + i], 2);
        }
        if (n) body += ' ';
        body += '}';
        out.push_back({start, n, std::move(body)});
        rawStart = -1;
    };

    const auto& fxmap = fixedOpcodes();
    const auto& cdmap = customDecoders();

    while (pc < b.size()) {
        // Dead-string detector first.
        std::size_t deadPairs = countDeadStringPairs(b, pc);
        if (deadPairs > 0
            && pc + deadPairs * 2 + 1 < b.size()
            && b[pc + deadPairs * 2] == 0
            && b[pc + deadPairs * 2 + 1] == 0) {
            flushRaw(pc);
            std::string text;
            for (std::size_t k = 0; k < deadPairs; ++k) {
                u16 code = static_cast<u16>(b[pc + k * 2]) |
                           (static_cast<u16>(b[pc + k * 2 + 1]) << 8);
                text += gameCharacterStrict(code);
            }
            std::size_t consumed = deadPairs * 2 + 2;
            std::string body = "dead_string(";
            body += quoteString(text);
            body += ')';
            out.push_back({pc, consumed, std::move(body)});
            pc += consumed;
            continue;
        }

        u8 op = b[pc];
        auto cit = cdmap.find(op);
        auto fit = fxmap.find(op);

        // Custom decoder first.  Catches truncation so we can fall back to raw.
        if (cit != cdmap.end()) {
            try {
                Decoded d = cit->second(b, pc + 1, b.size(), sp, secp, &labels);
                if (d.consumed < 1 || pc + d.consumed > b.size()) {
                    throw std::runtime_error("bad consumed");
                }
                flushRaw(pc);
                out.push_back({pc, d.consumed, std::move(d.text)});
                pc += d.consumed;
                continue;
            } catch (...) { /* fall through to raw */ }
        }
        if (fit != fxmap.end() && pc + fit->second.size <= b.size()) {
            flushRaw(pc);
            std::string text = renderFixed(fit->second, b, pc, sp, secp, &labels);
            out.push_back({pc, fit->second.size, std::move(text)});
            pc += fit->second.size;
            continue;
        }
        // Unknown / truncated -- extend raw run.
        if (rawStart < 0) rawStart = static_cast<long long>(pc);
        pc += 1;
    }
    flushRaw(pc);
    return out;
}

// A statement that unconditionally transfers control elsewhere -- nothing
// can fall through past it.  `goto X`, `return`, `if (...) goto X; else
// goto Y` all qualify.  Plain `if (...) goto X;` (no else) does NOT --
// the false branch falls through.
bool isUnconditionalTerminator(std::string_view body) {
    if (body == "return") return true;
    if (body.size() >= 5 && body[0] == 'g' && body[1] == 'o' && body[2] == 't' && body[3] == 'o' && body[4] == ' ') return true;
    if (body.size() >= 3 && body[0] == 'i' && body[1] == 'f' && (body[2] == ' ' || body[2] == '(')) {
        return body.find("; else goto ") != std::string_view::npos;
    }
    return false;
}

// When a section's head is a run of N >= 2 consecutive unconditional
// terminators with no labelled gaps, treat it as a jump table dispatched
// from outside the script -- emit a label at each entry past offset 0.
//
// (Offset 0 is the section's natural entry point, already addressable by
// the bare section name.)
void addJumpTableHeadLabels(std::unordered_set<int>& labels,
                            const std::vector<DecodedInstr>& stmts) {
    std::size_t headCount = 0;
    std::size_t expected = 0;
    for (const auto& instr : stmts) {
        if (instr.offset != expected) break;
        if (!isUnconditionalTerminator(instr.body)) break;
        ++headCount;
        expected += instr.consumed;
    }
    if (headCount < 2) return;
    for (std::size_t i = 1; i < headCount; ++i) {
        labels.insert(static_cast<int>(stmts[i].offset));
    }
}

// Build the section header line.  Drops the redundant default name when
// no user rename is in effect:
//   `section(<id>) {`                         -- default-named, unique id
//   `section(<id>, 0x<dis>) {`                -- default-named, duplicate id
//   `section <name>(<id>[, 0x<dis>]) {`       -- user-named (or onEnter)
// `len` comment appended.
std::string sectionHeaderLine(const Script& script, const Section& sec) {
    bool dup = false;
    {
        int n = 0;
        for (const auto& s : script.sections) if (s.id == sec.id) { n++; if (n > 1) { dup = true; break; } }
    }
    const std::string name = sectionName(script, sec);
    const std::string defName = defaultSectionName(script, sec);
    std::string out = "section";
    if (name != defName) {
        out += ' ';
        out += name;
    }
    out += '(';
    out += toDec(sec.id);
    if (dup) {
        out += ", 0x";
        out += toHexPadded(sec.offset, 4);
    }
    out += ") {";
    return out;
}

// Parse `mnemonic(arg, arg, ...)` from a body string.  `args` views into
// `body`.  Returns nullopt if `body` isn't a plain call (e.g. starts with
// `if`, `goto`, or contains a trailing tail after `)`).
struct CallBody {
    std::string_view mnemonic;
    std::vector<std::string_view> args;
};
std::optional<CallBody> parseSimpleCall(std::string_view body) {
    std::size_t lp = body.find('(');
    if (lp == std::string_view::npos) return std::nullopt;
    if (body.empty() || body.back() != ')') return std::nullopt;
    CallBody out;
    out.mnemonic = body.substr(0, lp);
    // Identifier check on mnemonic.
    if (out.mnemonic.empty()) return std::nullopt;
    char c0 = out.mnemonic.front();
    if (!(c0 == '_' || (c0 >= 'A' && c0 <= 'Z') || (c0 >= 'a' && c0 <= 'z'))) return std::nullopt;
    for (char c : out.mnemonic) {
        if (!(c == '_' || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))) {
            return std::nullopt;
        }
    }
    std::string_view inside = body.substr(lp + 1, body.size() - lp - 2);
    int depth = 0;
    bool inStr = false;
    std::size_t start = 0;
    auto pushArg = [&](std::size_t end) {
        std::string_view a = inside.substr(start, end - start);
        while (!a.empty() && (a.front() == ' ' || a.front() == '\t')) a.remove_prefix(1);
        while (!a.empty() && (a.back() == ' ' || a.back() == '\t')) a.remove_suffix(1);
        if (!a.empty() || end > start) out.args.push_back(a);
    };
    for (std::size_t i = 0; i < inside.size(); ++i) {
        char c = inside[i];
        if (inStr) {
            if (c == '\\' && i + 1 < inside.size()) { ++i; continue; }
            if (c == '"') inStr = false;
            continue;
        }
        if (c == '"') { inStr = true; continue; }
        if (c == '(' || c == '[') depth++;
        else if (c == ')' || c == ']') depth--;
        else if (c == ',' && depth == 0) {
            pushArg(i);
            start = i + 1;
        }
    }
    if (!inside.empty()) pushArg(inside.size());
    return out;
}

// Parse a decimal or 0xHEX literal.  Returns nullopt on non-numeric input.
std::optional<int> tryParseInt(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);
    if (s.empty()) return std::nullopt;
    int sign = 1;
    std::size_t i = 0;
    if (s[i] == '-') { sign = -1; ++i; }
    else if (s[i] == '+') { ++i; }
    if (i >= s.size()) return std::nullopt;
    int v = 0;
    if (i + 1 < s.size() && s[i] == '0' && (s[i+1] == 'x' || s[i+1] == 'X')) {
        i += 2;
        if (i >= s.size()) return std::nullopt;
        while (i < s.size()) {
            char c = s[i];
            int d;
            if (c >= '0' && c <= '9') d = c - '0';
            else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
            else return std::nullopt;
            v = v * 16 + d;
            ++i;
        }
    } else {
        while (i < s.size()) {
            char c = s[i];
            if (c < '0' || c > '9') return std::nullopt;
            v = v * 10 + (c - '0');
            ++i;
        }
    }
    return v * sign;
}

// ============================================================================
// Composite catalog -- functions.dgs as the macro definition source.
//
// Every "composite" function in functions.dgs (body is more than a single
// raw(...) call) defines a forward inlining shape; the assembler textually
// substitutes parameters into the body at invocation.
//
// genericBeautifyComposites is the inverse: it walks the catalog, tries each
// composite's body shape as a window against the decoded stream, and rewrites
// a successful match to the composite's named call.  This replaces a long
// series of bespoke per-shape beautifyX functions.
// ============================================================================

bool compIsIdentStart(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}
bool compIsIdentCont(char c) {
    return compIsIdentStart(c) || (c >= '0' && c <= '9');
}
std::string_view compLeadingIdent(std::string_view s) {
    if (s.empty() || !compIsIdentStart(s[0])) return {};
    std::size_t n = 1;
    while (n < s.size() && compIsIdentCont(s[n])) ++n;
    return s.substr(0, n);
}
std::string_view compStripLineComment(std::string_view line) {
    bool inStr = false;
    for (std::size_t i = 0; i + 1 < line.size(); ++i) {
        char c = line[i];
        if (inStr) {
            if (c == '\\') { ++i; continue; }
            if (c == '"') inStr = false;
            continue;
        }
        if (c == '"') { inStr = true; continue; }
        if (c == '/' && line[i + 1] == '/') return line.substr(0, i);
    }
    return line;
}
std::size_t compFindMatchingRparen(std::string_view s, std::size_t lparen) {
    int depth = 0;
    bool inStr = false;
    for (std::size_t i = lparen; i < s.size(); ++i) {
        char c = s[i];
        if (inStr) {
            if (c == '\\') { ++i; continue; }
            if (c == '"') inStr = false;
            continue;
        }
        if (c == '"') { inStr = true; continue; }
        if (c == '(') depth++;
        else if (c == ')') { depth--; if (depth == 0) return i; }
    }
    return std::string_view::npos;
}
std::vector<std::string_view> compSplitTopCommas(std::string_view s) {
    std::vector<std::string_view> out;
    std::size_t start = 0;
    int depth = 0;
    bool inStr = false;
    for (std::size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (inStr) {
            if (c == '\\') { ++i; continue; }
            if (c == '"') inStr = false;
            continue;
        }
        if (c == '"') { inStr = true; continue; }
        if (c == '(' || c == '[' || c == '{') depth++;
        else if (c == ')' || c == ']' || c == '}') depth--;
        else if (depth == 0 && c == ',') {
            out.push_back(trim(s.substr(start, i - start)));
            start = i + 1;
        }
    }
    std::string_view tail = trim(s.substr(start));
    if (!tail.empty() || !out.empty()) out.push_back(tail);
    return out;
}
std::vector<std::string_view> compSplitTopSemis(std::string_view s) {
    std::vector<std::string_view> out;
    std::size_t start = 0;
    int depth = 0;
    bool inStr = false;
    for (std::size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (inStr) {
            if (c == '\\') { ++i; continue; }
            if (c == '"') inStr = false;
            continue;
        }
        if (c == '"') { inStr = true; continue; }
        if (c == '(' || c == '[' || c == '{') depth++;
        else if (c == ')' || c == ']' || c == '}') depth--;
        else if (depth == 0 && c == ';') {
            std::string_view t = trim(s.substr(start, i - start));
            if (!t.empty()) out.push_back(t);
            start = i + 1;
        }
    }
    std::string_view tail = trim(s.substr(start));
    if (!tail.empty()) out.push_back(tail);
    return out;
}

// Extract `name: value` -> {name, value}, or {"", whole} when no colon.
struct NamedArg { std::string fieldName; std::string value; };
NamedArg compSplitNamedArg(std::string_view arg) {
    arg = trim(arg);
    auto pos = arg.find(':');
    if (pos == std::string_view::npos) return { "", std::string{arg} };
    auto isIdent = [](std::string_view s) {
        if (s.empty() || !compIsIdentStart(s[0])) return false;
        for (char c : s) if (!compIsIdentCont(c)) return false;
        return true;
    };
    std::string_view left  = trim(arg.substr(0, pos));
    std::string_view right = trim(arg.substr(pos + 1));
    if (!isIdent(left)) return { "", std::string{arg} };
    return { std::string{left}, std::string{right} };
}

struct CompArg {
    std::string fieldName;   // "" if positional
    std::string value;       // arg value text after any "name:" prefix
    int paramIdx = -1;       // -1 = literal; >= 0 = composite param index
};

// A single item in a composite (function) body.
//
// Three shapes, mutually exclusive:
//   - flat call: `mnemonic(args)` -- the original v1 form.  isReturn=isIfBlock=false.
//   - `return`:  isReturn=true.
//   - `if (cond) { body }`: isIfBlock=true.  condTokens is the tokenized template
//     for the predicate (param names may appear as tokens, bound at match time);
//     body is the (recursive) list of items inside the if's braces.
struct CompItem {
    bool isReturn = false;
    bool isIfBlock = false;
    std::string mnemonic;          // when flat call
    std::vector<CompArg> args;     // when flat call
    std::vector<std::string> condTokens;   // when isIfBlock
    std::vector<CompItem> body;            // when isIfBlock
};

struct Composite {
    std::string name;
    std::vector<std::string> paramNames;
    std::vector<bool> paramPreferNamed;  // emit with `name:` prefix at call site
    // Per-param kind (from `name: Kind` / `name: Kind[]` annotations).
    // When set, the fold-emit step renders matched bindings as `Kind.Name`
    // (or `Kind(N)` for unnamed values) instead of bare ints -- mirroring
    // the rendering of fixed opcodes.
    std::vector<std::optional<SymKind>> paramKinds;
    // Per-param default-expr text (from `name: Kind = <expr>`).  When the
    // matched binding numerically equals the default AND every later param
    // is also being dropped, the emit step omits it from the call.
    std::vector<std::optional<std::string>> paramDefaults;
    std::vector<CompItem> items;
};

// Find which composite param (if any) this raw arg-text refers to.
int findParamIdx(std::string_view value,
                 const std::vector<std::string>& paramNames) {
    for (std::size_t k = 0; k < paramNames.size(); ++k) {
        if (value == paramNames[k]) return static_cast<int>(k);
    }
    return -1;
}

// Resolve a symbolic token (`:Name` or `Kind.Name`) to its integer value via
// the global symbol table.  Returns nullopt for plain ints, unknown names, or
// `:Name` collisions across kinds.  Used so template tokens like
// `pstat[:RollScratch]` match concrete `pstat[110]` from disasm output.
std::optional<int> tryResolveSymbolicToken(std::string_view tok) {
    if (tok.empty()) return std::nullopt;
    if (tok[0] == ':') {
        std::string_view name = tok.substr(1);
        if (name.empty()) return std::nullopt;
        static constexpr SymKind kAll[] = {
            SymKind::Entity, SymKind::Digimon, SymKind::Item, SymKind::Move,
            SymKind::Stat, SymKind::Condition, SymKind::Map,
            SymKind::Trigger, SymKind::PStat, SymKind::Animation,
        };
        std::optional<int> hit;
        for (SymKind k : kAll) {
            int v;
            if (symbolTable().tryLookupBareName(k, name, v)) {
                if (hit && *hit != v) return std::nullopt;  // ambiguous
                hit = v;
            }
        }
        return hit;
    }
    std::size_t dot = tok.find('.');
    if (dot != std::string_view::npos) {
        auto k = symKindFromLabel(tok.substr(0, dot));
        if (!k) return std::nullopt;
        int v;
        if (symbolTable().tryLookupBareName(*k, tok.substr(dot + 1), v)) return v;
    }
    // `Kind(N)` explicit-cast form: capitalized identifier, then `(int)`.
    if (tok.size() > 3 && tok.back() == ')'
        && tok[0] >= 'A' && tok[0] <= 'Z') {
        std::size_t lp = tok.find('(');
        if (lp != std::string_view::npos) {
            // Validate kind label so we don't swallow accidental `Foo(123)`
            // identifiers; otherwise fall through to nullopt.
            if (symKindFromLabel(tok.substr(0, lp))) {
                if (auto v = tryParseInt(tok.substr(lp + 1, tok.size() - lp - 2))) {
                    return v;
                }
            }
        }
    }
    return std::nullopt;
}

// True when `a` and `b` denote the same integer after symbol resolution.
// Treats `:RollScratch` == `110` == `PStat.RollScratch` and friends.
bool tokensNumericallyEqual(std::string_view a, std::string_view b) {
    auto resolve = [](std::string_view s) -> std::optional<int> {
        if (auto v = tryParseInt(s)) return v;
        return tryResolveSymbolicToken(s);
    };
    auto av = resolve(a), bv = resolve(b);
    return av && bv && *av == *bv;
}

// Tokenize a predicate-atom (or atom-chain) string for template matching.
// Tokens preserve structure for token-by-token compare:
//   - identifier: letter/_-led run including digits, `.`, `:` (kind-qualifiers
//     like `Stat.Offense` and ruby-style `:Sym` stay one token)
//   - number: digit-led run, with `0x` prefix for hex
//   - operator: greedy `<=`, `>=`, `==`, `!=`, `&&`, `||`; else single char
//   - punctuation: `(`, `)`, `[`, `]`, `,`, `+`, `-`, `*`, `/`, `%`
// Whitespace is separator and dropped.  Unknown chars are skipped silently.
std::vector<std::string> tokenizePredicate(std::string_view s) {
    std::vector<std::string> out;
    std::size_t i = 0;
    auto isIdStart = [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
    };
    auto isIdCont = [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
            || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == ':';
    };
    while (i < s.size()) {
        char c = s[i];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') { ++i; continue; }
        if (c == '<' || c == '>' || c == '=' || c == '!') {
            std::size_t j = i + 1;
            if (j < s.size() && s[j] == '=') ++j;
            out.emplace_back(s.substr(i, j - i));
            i = j;
            continue;
        }
        if (c == '&' || c == '|') {
            std::size_t j = i + 1;
            if (j < s.size() && s[j] == c) ++j;
            out.emplace_back(s.substr(i, j - i));
            i = j;
            continue;
        }
        if (c == '(' || c == ')' || c == '[' || c == ']'
         || c == ',' || c == '+' || c == '-' || c == '*'
         || c == '/' || c == '%') {
            out.emplace_back(1, c);
            ++i;
            continue;
        }
        if (isIdStart(c) || c == ':') {
            std::size_t j = i + 1;
            while (j < s.size() && isIdCont(s[j])) ++j;
            out.emplace_back(s.substr(i, j - i));
            i = j;
            continue;
        }
        if (c >= '0' && c <= '9') {
            std::size_t j = i + 1;
            if (c == '0' && j < s.size() && (s[j] == 'x' || s[j] == 'X')) {
                ++j;
                while (j < s.size()) {
                    char d = s[j];
                    if ((d >= '0' && d <= '9') || (d >= 'a' && d <= 'f')
                     || (d >= 'A' && d <= 'F')) ++j;
                    else break;
                }
            } else {
                while (j < s.size() && s[j] >= '0' && s[j] <= '9') ++j;
            }
            out.emplace_back(s.substr(i, j - i));
            i = j;
            continue;
        }
        ++i;  // unknown -- skip
    }
    return out;
}

// Match a tokenized template predicate against a concrete predicate string,
// binding param-name tokens to concrete tokens (consistent-binding check).
//
// Literal tokens must match string-equal OR numeric-equal (so the template
// `0x10` matches a concrete `16`).
bool matchPredicateTemplate(
        const std::vector<std::string>& templateTokens,
        std::string_view concrete,
        std::vector<std::optional<std::string>>& bindings,
        const std::vector<std::string>& paramNames) {
    auto concreteToks = tokenizePredicate(concrete);
    if (concreteToks.size() != templateTokens.size()) return false;
    for (std::size_t k = 0; k < templateTokens.size(); ++k) {
        const std::string& tmpl = templateTokens[k];
        const std::string& got  = concreteToks[k];
        int pi = findParamIdx(tmpl, paramNames);
        if (pi >= 0) {
            if (bindings[pi]) {
                if (*bindings[pi] != got) return false;
            } else {
                bindings[pi] = got;
            }
            continue;
        }
        if (tmpl == got) continue;
        // Equality fallback: treat tokens as equal when they denote the same
        // integer after symbol resolution (so `:RollScratch` matches `110`
        // and `PStat.RollScratch` matches both).
        if (tokensNumericallyEqual(tmpl, got)) continue;
        return false;
    }
    return true;
}

// Translate `raw(opcode, ...)` body item into the disasm-canonical mnemonic
// call by reading fixedOpcodes() and dropping empty-zero fields (matches
// extractFieldArgs at disasm.cpp top).  Returns nullopt on unsupported shape.
std::optional<CompItem> translateRawToMnemonic(
        const std::vector<std::string_view>& rawArgs,
        const std::vector<std::string>& paramNames) {
    if (rawArgs.empty()) return std::nullopt;
    auto opOpt = tryParseInt(rawArgs[0]);
    if (!opOpt || *opOpt < 0 || *opOpt > 0xff) return std::nullopt;
    u8 op = static_cast<u8>(*opOpt);
    const auto& fx = fixedOpcodes();
    auto it = fx.find(op);
    if (it == fx.end()) return std::nullopt;
    const FixedOpcode& def = it->second;
    if (rawArgs.size() != 1 + def.fields.size()) return std::nullopt;

    CompItem item;
    item.mnemonic = std::string{def.mnemonic};
    for (std::size_t k = 0; k < def.fields.size(); ++k) {
        const Field& f = def.fields[k];
        std::string_view a = trim(rawArgs[k + 1]);
        // s16(x) / s32(x) wrappers -- the inner expression is the actual value.
        if ((a.size() > 4 && a.substr(0, 4) == "s16(" && a.back() == ')')
         || (a.size() > 4 && a.substr(0, 4) == "s32(" && a.back() == ')')) {
            a = trim(a.substr(4, a.size() - 5));
        }
        auto v = tryParseInt(a);
        if (f.n == "empty" && v && *v == 0) continue;
        CompArg ca;
        ca.value = std::string{a};
        ca.paramIdx = findParamIdx(a, paramNames);
        item.args.push_back(std::move(ca));
    }
    return item;
}

// Forward decl -- the recursive body parser invokes itself for if-block bodies.
struct ParsedCompBody {
    std::vector<CompItem> items;
    bool ok = false;
};
ParsedCompBody parseCompBody(std::string_view body,
                              const std::vector<std::string>& paramNames);

// Parse `mnemonic(args)` into a CompItem (literals/param-refs/named-arg form).
std::optional<CompItem> parseBodyCall(std::string_view line,
                                       const std::vector<std::string>& paramNames) {
    std::string_view t = trim(line);
    if (t == "return") {
        CompItem item; item.isReturn = true; return item;
    }
    auto lp = t.find('(');
    if (lp == std::string_view::npos || t.empty() || t.back() != ')') return std::nullopt;
    std::string_view mn = trim(t.substr(0, lp));
    std::string_view ident = compLeadingIdent(mn);
    if (ident.size() != mn.size()) return std::nullopt;
    std::string_view inside = t.substr(lp + 1, t.size() - lp - 2);
    auto parts = compSplitTopCommas(inside);

    CompItem item;
    if (mn == "raw") {
        auto translated = translateRawToMnemonic(parts, paramNames);
        if (!translated) return std::nullopt;
        return translated;
    }
    item.mnemonic = std::string{mn};
    for (auto p : parts) {
        if (p.empty()) continue;
        NamedArg na = compSplitNamedArg(p);
        CompArg ca;
        ca.fieldName = std::move(na.fieldName);
        ca.value = std::move(na.value);
        ca.paramIdx = findParamIdx(ca.value, paramNames);
        item.args.push_back(std::move(ca));
    }
    return item;
}

// Recursive descent over a function body (or if-block body).  Supports flat
// `mnemonic(args);` calls AND block-form `if (cond) { body }`.  Still rejects
// `for`/`loop`/`while`/`do`/`switch` (scope limit -- those have bespoke
// beautifiers).  Returns `ok=false` when the body has shape we don't model.
ParsedCompBody parseCompBody(std::string_view body,
                              const std::vector<std::string>& paramNames) {
    ParsedCompBody out;
    auto isWS = [](char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r';
    };
    auto isIdStart = [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
    };
    auto isIdCont = [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
            || (c >= '0' && c <= '9') || c == '_';
    };

    std::size_t i = 0;
    while (i < body.size()) {
        while (i < body.size() && (isWS(body[i]) || body[i] == ';')) ++i;
        if (i >= body.size()) break;
        if (i + 1 < body.size() && body[i] == '/' && body[i + 1] == '/') {
            while (i < body.size() && body[i] != '\n') ++i;
            continue;
        }

        // Identify leading keyword.  We accept `if (` and reject other
        // control-flow keywords explicitly.
        std::size_t kwEnd = i;
        while (kwEnd < body.size() && isIdCont(body[kwEnd])) ++kwEnd;
        std::string_view kw = body.substr(i, kwEnd - i);
        if (kw == "for" || kw == "loop" || kw == "while" || kw == "do" || kw == "switch") {
            return out;  // ok=false, drop this composite
        }
        if (kw == "if") {
            // Block-form `if (cond) { body }`.  No `else` support in v1.
            std::size_t lp = kwEnd;
            while (lp < body.size() && isWS(body[lp])) ++lp;
            if (lp >= body.size() || body[lp] != '(') return out;
            std::size_t rp = compFindMatchingRparen(body, lp);
            if (rp == std::string_view::npos) return out;
            std::string_view cond = trim(body.substr(lp + 1, rp - lp - 1));
            std::size_t after = rp + 1;
            while (after < body.size() && isWS(body[after])) ++after;
            if (after >= body.size() || body[after] != '{') return out;
            // Capture body until matching `}`.
            std::size_t br = after + 1;
            int depth = 1;
            std::size_t brEnd = br;
            while (brEnd < body.size() && depth > 0) {
                char c = body[brEnd];
                if (c == '{') ++depth;
                else if (c == '}') --depth;
                if (depth > 0) ++brEnd;
            }
            if (depth != 0) return out;
            std::string_view innerBody = body.substr(br, brEnd - br);
            auto inner = parseCompBody(innerBody, paramNames);
            if (!inner.ok) return out;
            CompItem item;
            item.isIfBlock = true;
            item.condTokens = tokenizePredicate(cond);
            item.body = std::move(inner.items);
            out.items.push_back(std::move(item));
            i = brEnd + 1;
            continue;
        }

        // Otherwise it's a flat statement ending in `;`.  Find the top-level
        // `;` (paren/bracket-aware, string-aware would be ideal but functions
        // unlikely contain string literals here).
        std::size_t semi = i;
        int parenDepth = 0;
        while (semi < body.size()) {
            char c = body[semi];
            if (c == '(' || c == '[') ++parenDepth;
            else if (c == ')' || c == ']') --parenDepth;
            else if (parenDepth == 0 && c == ';') break;
            else if (parenDepth == 0 && c == '{') return out;  // unexpected nested block
            ++semi;
        }
        std::string_view stmt = trim(body.substr(i, semi - i));
        if (!stmt.empty()) {
            auto call = parseBodyCall(stmt, paramNames);
            if (!call) return out;
            out.items.push_back(std::move(*call));
        }
        i = (semi < body.size()) ? semi + 1 : semi;
    }
    (void)isIdStart;
    out.ok = true;
    return out;
}

// Forward decl: defined alongside loadPairLoopsFromDgs below.  Used here so
// loadCompositesFromDgs() can skip function bodies that match the pair-loop
// shape and route them to the pair-loop catalog instead.
std::optional<std::tuple<std::string, std::string, std::string, CompItem>>
tryParsePairLoopBody(std::string_view body,
                     const std::vector<std::string>& paramNames);

// Parse functions.dgs.  Skips built-ins (single raw(...) body) and any
// composite that contains control-flow we can't model.  Each kept composite
// has its body lowered to a tree of CompItems (flat calls + block-form ifs).
std::vector<Composite> loadCompositesFromDgs(const std::filesystem::path& path) {
    std::vector<Composite> out;
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) return out;
    std::string text = readFileText(path);

    std::vector<std::string_view> lines;
    {
        std::size_t pos = 0;
        while (pos <= text.size()) {
            std::size_t nl = text.find('\n', pos);
            std::string_view ln = (nl == std::string::npos)
                ? std::string_view{text}.substr(pos)
                : std::string_view{text}.substr(pos, nl - pos);
            if (!ln.empty() && ln.back() == '\r') ln.remove_suffix(1);
            lines.push_back(ln);
            if (nl == std::string::npos) break;
            pos = nl + 1;
        }
    }

    std::size_t i = 0;
    while (i < lines.size()) {
        std::string_view raw = compStripLineComment(lines[i]);
        std::string_view ln  = trim(raw);
        if (!startsWith(ln, "function")
            || (ln.size() > 8 && ln[8] != ' ' && ln[8] != '\t')) {
            ++i; continue;
        }
        std::string_view rest = trim(ln.substr(8));
        std::string_view nameView = compLeadingIdent(rest);
        if (nameView.empty()) { ++i; continue; }
        Composite comp;
        comp.name = std::string{nameView};
        rest = trim(rest.substr(nameView.size()));
        if (rest.empty() || rest[0] != '(') { ++i; continue; }
        std::size_t rp = compFindMatchingRparen(rest, 0);
        if (rp == std::string_view::npos) { ++i; continue; }
        for (auto p : compSplitTopCommas(rest.substr(1, rp - 1))) {
            std::string_view tp = trim(p);
            if (tp.empty()) continue;
            // `[PreferNamed]` prefix opts this param into named-arg styling
            // (`name: value`) at matched call sites.
            bool preferNamed = false;
            if (startsWith(tp, "[PreferNamed]")) {
                preferNamed = true;
                tp = trim(tp.substr(std::string_view{"[PreferNamed]"}.size()));
            }
            // Split off `= <default>` at top level (mirror of the assembler's
            // param parser).  Skips `==`/`=>`/`!=`/`<=`/`>=` and anything in
            // nested `[]`/`()`/`{}`.
            std::optional<std::string> defaultExpr;
            {
                int bd = 0, pd = 0, cd = 0;
                std::size_t eq = std::string_view::npos;
                for (std::size_t k = 0; k < tp.size(); ++k) {
                    char c = tp[k];
                    if (c == '[') ++bd;
                    else if (c == ']') --bd;
                    else if (c == '(') ++pd;
                    else if (c == ')') --pd;
                    else if (c == '{') ++cd;
                    else if (c == '}') --cd;
                    else if (c == '=' && bd == 0 && pd == 0 && cd == 0) {
                        char nx = (k + 1 < tp.size()) ? tp[k + 1] : '\0';
                        char pv = (k > 0) ? tp[k - 1] : '\0';
                        if (nx == '=' || nx == '>' || pv == '=' || pv == '!' || pv == '<' || pv == '>') continue;
                        eq = k;
                        break;
                    }
                }
                if (eq != std::string_view::npos) {
                    defaultExpr = std::string{trim(tp.substr(eq + 1))};
                    tp = trim(tp.substr(0, eq));
                }
            }
            // `name` or `name: Kind`/`name: Kind[]` -- pull out the name + kind.
            auto colon = tp.find(':');
            std::string_view pn = (colon == std::string_view::npos) ? tp
                                                                    : trim(tp.substr(0, colon));
            std::optional<SymKind> pkind;
            if (colon != std::string_view::npos) {
                std::string_view kt = trim(tp.substr(colon + 1));
                if (kt.size() >= 2 && kt.substr(kt.size() - 2) == "[]") {
                    kt = trim(kt.substr(0, kt.size() - 2));
                }
                // Array of pairs `(K1, K2)` and the literal `int` marker
                // both stay un-kinded for fold-render purposes.
                if (!kt.empty() && kt.front() != '(' && kt != "int") {
                    pkind = symKindFromLabel(kt);
                }
            }
            comp.paramNames.emplace_back(pn);
            comp.paramPreferNamed.push_back(preferNamed);
            comp.paramKinds.push_back(pkind);
            comp.paramDefaults.push_back(defaultExpr);
        }
        // Body starts with `{` on this or a later line; collect until matching `}`.
        std::string body;
        std::string_view tail = trim(rest.substr(rp + 1));
        std::size_t depth = 0;
        auto consumeChunk = [&](std::string_view chunk) {
            for (char c : chunk) {
                if (depth >= 1) body += c;
                if (c == '{') ++depth;
                else if (c == '}') {
                    if (depth == 0) return;
                    --depth;
                    if (depth == 0) {
                        // Drop the closing brace we just appended.
                        if (!body.empty() && body.back() == '}') body.pop_back();
                    }
                }
            }
        };
        consumeChunk(tail);
        ++i;
        while (depth > 0 && i < lines.size()) {
            std::string_view r2 = compStripLineComment(lines[i]);
            body += '\n';
            consumeChunk(r2);
            ++i;
        }

        // Pair-loop composites (body == `for X, Y in P { call }`) are
        // captured by loadPairLoopsFromDgs() instead; skip here.
        if (tryParsePairLoopBody(body, comp.paramNames)) continue;

        // Parse the body recursively (flat calls + block-form ifs).  Drops
        // composites we can't model (for/loop/while/do/switch, unknown shapes).
        auto parsed = parseCompBody(body, comp.paramNames);
        if (!parsed.ok || parsed.items.empty()) continue;
        comp.items = std::move(parsed.items);

        // Skip built-ins: a single item that is just one raw-call after
        // translation -- those decode 1:1, no beautification to do.
        if (comp.items.size() == 1 && !comp.items[0].isIfBlock) continue;
        out.push_back(std::move(comp));
    }
    return out;
}


const std::vector<Composite>& compositeCatalog() {
    static const std::vector<Composite> cat = loadCompositesFromDgs("functions.dgs");
    return cat;
}

// Composite whose body is exactly `for X, Y in P { call(...) }`.  Folds runs
// of `call(...)` with two slots varying together (one per pair) into the
// `funcName([X1 => Y1, X2 => Y2, ...], <other params>)` form.
//
// Sentinels in innerCall.args[k].paramIdx beyond the normal paramNames range:
//   kIterAIdx (-10) -- this arg position is bound to the loop's first iter
//   kIterBIdx (-11) -- bound to the loop's second iter
struct PairLoopComposite {
    std::string name;
    std::vector<std::string> paramNames;
    std::vector<bool> paramPreferNamed;
    std::size_t pairsParamIdx = 0;     // index in paramNames
    bool isPair = false;               // true: 2 iters + `K=>V` form;
                                       // false: 1 iter + bare-value form
    CompItem innerCall;
};
static constexpr int kIterAIdx = -10;
static constexpr int kIterBIdx = -11;

// Scan a function body for a single- or double-iter for-loop shape.
// Returns (iterA, iterB, pairsParam, innerCall) on a match.  iterB is empty
// for single-iter `for X in P { call }` bodies; non-empty for pair-iter
// `for X, Y in P { call }`.  paramsForBody is the function's paramNames
// followed by [iterA] or [iterA, iterB] so findParamIdx can resolve both
// regular params and iters during parseBodyCall.
std::optional<std::tuple<std::string, std::string, std::string, CompItem>>
tryParsePairLoopBody(std::string_view body,
                     const std::vector<std::string>& paramNames) {
    // Strip leading/trailing whitespace + the surrounding `for ... { ... }`.
    auto isWS = [](char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; };
    std::size_t i = 0;
    while (i < body.size() && isWS(body[i])) ++i;
    if (body.size() - i < 4 || body.substr(i, 4) != "for ") return std::nullopt;
    i += 4;
    while (i < body.size() && isWS(body[i])) ++i;
    auto isId = [](char c) { return (c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_'; };
    std::size_t a0 = i;
    while (i < body.size() && isId(body[i])) ++i;
    std::string iterA{body.substr(a0, i - a0)};
    while (i < body.size() && isWS(body[i])) ++i;
    std::string iterB;
    if (i < body.size() && body[i] == ',') {
        ++i;
        while (i < body.size() && isWS(body[i])) ++i;
        std::size_t b0 = i;
        while (i < body.size() && isId(body[i])) ++i;
        iterB.assign(body.substr(b0, i - b0));
        while (i < body.size() && isWS(body[i])) ++i;
    }
    if (body.size() - i < 3 || body.substr(i, 2) != "in") return std::nullopt;
    i += 2;
    while (i < body.size() && isWS(body[i])) ++i;
    std::size_t p0 = i;
    while (i < body.size() && isId(body[i])) ++i;
    std::string pairsParam{body.substr(p0, i - p0)};
    while (i < body.size() && isWS(body[i])) ++i;
    if (i >= body.size() || body[i] != '{') return std::nullopt;
    ++i;
    // Capture loop body to matching `}` -- assume no nested braces (true for
    // the intended single-call shape).
    std::size_t loopBodyStart = i;
    int depth = 1;
    while (i < body.size() && depth > 0) {
        if (body[i] == '{') ++depth;
        else if (body[i] == '}') { --depth; if (depth == 0) break; }
        ++i;
    }
    if (depth != 0) return std::nullopt;
    std::string_view inner = body.substr(loopBodyStart, i - loopBodyStart);
    // After `}` only whitespace should remain.
    for (std::size_t k = i + 1; k < body.size(); ++k) {
        if (!isWS(body[k])) return std::nullopt;
    }

    // Inner must be exactly one statement.
    std::string innerStr{inner};
    // Strip trailing `;` and trim.
    while (!innerStr.empty() && (isWS(innerStr.back()) || innerStr.back() == ';')) {
        innerStr.pop_back();
    }
    // parseBodyCall takes paramNames; include the iters so the args bind.
    std::vector<std::string> withIters = paramNames;
    withIters.push_back(iterA);
    int aIdx = static_cast<int>(paramNames.size());
    int bIdx = -1;
    if (!iterB.empty()) {
        withIters.push_back(iterB);
        bIdx = aIdx + 1;
    }
    auto call = parseBodyCall(innerStr, withIters);
    if (!call) return std::nullopt;
    if (call->isReturn || call->isIfBlock) return std::nullopt;
    // Rewrite paramIdx values that point at the iter slots into the sentinels.
    for (auto& arg : call->args) {
        if (arg.paramIdx == aIdx) arg.paramIdx = kIterAIdx;
        else if (bIdx >= 0 && arg.paramIdx == bIdx) arg.paramIdx = kIterBIdx;
    }
    return std::make_tuple(std::move(iterA), std::move(iterB),
                           std::move(pairsParam), std::move(*call));
}

// Match one arg value against a template-arg value, with param binding.
// Handles four cases:
//   * exact string equality (literal match)
//   * template is a param ref (`x` in `paramNames`) -- bind it or check
//     consistency against an earlier binding
//   * symbolic-numeric equivalence (`PStat(245)` <-> `245`, `:Foo` <-> N, ...)
//   * tuple decomposition (`(x, y)` vs `(242, -1810)`) -- recurse on each
//     comma-separated component.  This is what lets `moveCamera(to: (x, y),
//     ...)` in a composite body fold over concrete tuples in the bytecode.
bool matchArgValue(const std::string& tmpl,
                   const std::string& got,
                   std::vector<std::optional<std::string>>& bindings,
                   const std::vector<std::string>& paramNames) {
    if (tmpl == got) return true;
    int pi = findParamIdx(tmpl, paramNames);
    if (pi >= 0) {
        if (bindings[pi]) return *bindings[pi] == got;
        bindings[pi] = got;
        return true;
    }
    if (tokensNumericallyEqual(tmpl, got)) return true;
    auto isTuple = [](std::string_view s) {
        s = trim(s);
        return s.size() >= 2 && s.front() == '(' && s.back() == ')';
    };
    if (isTuple(tmpl) && isTuple(got)) {
        std::string_view ti = trim(std::string_view{tmpl});
        std::string_view gi = trim(std::string_view{got});
        ti = ti.substr(1, ti.size() - 2);
        gi = gi.substr(1, gi.size() - 2);
        auto tParts = compSplitTopCommas(ti);
        auto gParts = compSplitTopCommas(gi);
        if (tParts.size() != gParts.size()) return false;
        for (std::size_t k = 0; k < tParts.size(); ++k) {
            std::string tk{trim(tParts[k])};
            std::string gk{trim(gParts[k])};
            if (!matchArgValue(tk, gk, bindings, paramNames)) return false;
        }
        return true;
    }
    return false;
}

// Re-scan functions.dgs for pair-loop composites.  Mirrors the function-def
// scaffolding of loadCompositesFromDgs() but captures the iter names and
// inner-call template instead of dropping the body.
std::vector<PairLoopComposite> loadPairLoopsFromDgs(const std::filesystem::path& path) {
    std::vector<PairLoopComposite> out;
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) return out;
    std::string text = readFileText(path);
    std::vector<std::string_view> lines;
    {
        std::size_t pos = 0;
        while (pos <= text.size()) {
            std::size_t nl = text.find('\n', pos);
            std::string_view ln = (nl == std::string::npos)
                ? std::string_view{text}.substr(pos)
                : std::string_view{text}.substr(pos, nl - pos);
            if (!ln.empty() && ln.back() == '\r') ln.remove_suffix(1);
            lines.push_back(ln);
            if (nl == std::string::npos) break;
            pos = nl + 1;
        }
    }
    std::size_t i = 0;
    while (i < lines.size()) {
        std::string_view raw = compStripLineComment(lines[i]);
        std::string_view ln = trim(raw);
        if (!startsWith(ln, "function")
            || (ln.size() > 8 && ln[8] != ' ' && ln[8] != '\t')) {
            ++i;
            continue;
        }
        std::string_view rest = trim(ln.substr(8));
        std::string_view nameView = compLeadingIdent(rest);
        if (nameView.empty()) { ++i; continue; }
        PairLoopComposite plc;
        plc.name = std::string{nameView};
        rest = trim(rest.substr(nameView.size()));
        if (rest.empty() || rest[0] != '(') { ++i; continue; }
        std::size_t rp = compFindMatchingRparen(rest, 0);
        if (rp == std::string_view::npos) { ++i; continue; }
        // Track the array param position so the fold knows which slot
        // receives the `[...]` literal (single-iter: bare values; pair-iter:
        // `K=>V`).  At most one such param per function -- a body iterating
        // multiple lists isn't a shape we model.
        std::optional<std::size_t> arrayIdx;
        bool arrayIsPair = false;
        std::size_t paramIdxCount = 0;
        for (auto p : compSplitTopCommas(rest.substr(1, rp - 1))) {
            std::string_view tp = trim(p);
            if (tp.empty()) continue;
            bool preferNamed = false;
            if (startsWith(tp, "[PreferNamed]")) {
                preferNamed = true;
                tp = trim(tp.substr(std::string_view{"[PreferNamed]"}.size()));
            }
            auto colon = tp.find(':');
            std::string_view pn = (colon == std::string_view::npos) ? tp
                                                                    : trim(tp.substr(0, colon));
            // Recognize either `Kind[]` (single) or `(K1, K2)[]` (pair).
            // First array-typed param wins as the iteration target.
            if (colon != std::string_view::npos) {
                std::string_view typeT = trim(tp.substr(colon + 1));
                bool endsArr = typeT.size() >= 2 && typeT.substr(typeT.size() - 2) == "[]";
                if (endsArr && !arrayIdx) {
                    arrayIdx = paramIdxCount;
                    arrayIsPair = !typeT.empty() && typeT.front() == '(';
                }
            }
            plc.paramNames.emplace_back(pn);
            plc.paramPreferNamed.push_back(preferNamed);
            ++paramIdxCount;
        }
        if (!arrayIdx) { ++i; continue; }
        plc.pairsParamIdx = *arrayIdx;
        plc.isPair = arrayIsPair;
        // Collect body.
        std::string body;
        std::string_view tail = trim(rest.substr(rp + 1));
        std::size_t depth = 0;
        auto consumeChunk = [&](std::string_view chunk) {
            for (char c : chunk) {
                if (depth >= 1) body += c;
                if (c == '{') ++depth;
                else if (c == '}') {
                    if (depth == 0) return;
                    --depth;
                    if (depth == 0) {
                        if (!body.empty() && body.back() == '}') body.pop_back();
                    }
                }
            }
        };
        consumeChunk(tail);
        ++i;
        while (depth > 0 && i < lines.size()) {
            std::string_view r2 = compStripLineComment(lines[i]);
            body += '\n';
            consumeChunk(r2);
            ++i;
        }
        auto parsed = tryParsePairLoopBody(body, plc.paramNames);
        if (!parsed) continue;
        // Iter-count must match the array shape (1 iter <-> Kind[],
        // 2 iters <-> (K1, K2)[]); skip otherwise.
        const std::string& iterB = std::get<1>(*parsed);
        if (plc.isPair != !iterB.empty()) continue;
        plc.innerCall = std::move(std::get<3>(*parsed));
        out.push_back(std::move(plc));
    }
    return out;
}

const std::vector<PairLoopComposite>& pairLoopCatalog() {
    static const std::vector<PairLoopComposite> cat = loadPairLoopsFromDgs("functions.dgs");
    return cat;
}

// Render an int back into the most-readable typed-value form (for the
// `K => V` pair-list emit).  Mirrors the source-arg lookup used by the
// fixed-opcode renderer: `Kind.Name` if a name binding exists, else
// `Kind(N)`.  Bare-int fallback when no kind context.
std::string renderTypedValue(int v, SymKind k) {
    std::string nm = symbolTable().lookupName(k, v);
    if (!nm.empty()) {
        std::string out{symKindLabel(k)};
        out += '.';
        out += nm;
        return out;
    }
    std::string out{symKindLabel(k)};
    out += '(';
    out += toDec(static_cast<long long>(v));
    out += ')';
    return out;
}

// Try to fold a run of consecutive calls into one PairLoopComposite call.
// Min run length 2 (a single call doesn't justify the bracket-list ceremony).
void beautifyPairLoopComposites(std::vector<DecodedInstr>& stmts,
                                const std::unordered_set<int>& labelOffsets) {
    const auto& catalog = pairLoopCatalog();
    if (catalog.empty()) return;
    std::vector<DecodedInstr> outStmts;
    outStmts.reserve(stmts.size());
    std::size_t i = 0;
    while (i < stmts.size()) {
        std::optional<std::pair<std::string, std::size_t>> best;
        for (const auto& plc : catalog) {
            // Tentatively match consecutive stmts against the inner call.
            std::vector<std::optional<std::string>> bindings(plc.paramNames.size());
            std::vector<std::pair<std::string, std::string>> pairs;
            std::size_t j = i;
            while (j < stmts.size()) {
                if (j != i && labelOffsets.count(static_cast<int>(stmts[j].offset))) break;
                auto call = parseSimpleCall(stmts[j].body);
                if (!call) break;
                if (call->mnemonic != plc.innerCall.mnemonic) break;
                if (call->args.size() != plc.innerCall.args.size()) break;
                std::string itA, itB;
                bool ok = true;
                bool sawA = false, sawB = false;
                auto bindingsTry = bindings;
                for (std::size_t a = 0; a < plc.innerCall.args.size(); ++a) {
                    NamedArg gotNA = compSplitNamedArg(call->args[a]);
                    const auto& want = plc.innerCall.args[a];
                    if (!want.fieldName.empty() && want.fieldName != gotNA.fieldName) { ok = false; break; }
                    const std::string& gotVal = gotNA.value;
                    if (want.paramIdx == kIterAIdx) {
                        itA = gotVal; sawA = true;
                    } else if (want.paramIdx == kIterBIdx) {
                        itB = gotVal; sawB = true;
                    } else if (want.paramIdx >= 0) {
                        int pi = want.paramIdx;
                        if (bindingsTry[pi]) {
                            if (*bindingsTry[pi] != gotVal) { ok = false; break; }
                        } else bindingsTry[pi] = gotVal;
                    } else {
                        if (!matchArgValue(want.value, gotVal, bindingsTry, plc.paramNames)) { ok = false; break; }
                    }
                }
                if (!ok) break;
                if (!sawA) break;
                if (plc.isPair && !sawB) break;
                bindings = std::move(bindingsTry);
                pairs.emplace_back(std::move(itA), std::move(itB));
                ++j;
            }
            // Threshold 3 matches beautifyForRanges / beautifyForArray; a
            // 2-call run reads worse as `setX([A=>1, A=>2], ...)` than as
            // two plain calls.
            if (pairs.size() < 3) continue;
            // When folded, always wrap multi-line -- a 3+ item bracketed
            // list is hard to scan on a single line.  The renderer prepends
            // section/loop indent to each subsequent line via extraIndent();
            // we add the inner INDENTs explicitly here.  All params are
            // emitted in declaration order; everything except the leading
            // positional run is named so reordering and skipped slots are
            // unambiguous to the assembler.
            std::string body = plc.name;
            body += "(";
            bool needComma = false;
            // Once we emit a named arg, every subsequent arg must also be
            // named (per the assembler's `positional-after-named` rule).
            bool forceNamed = false;
            // Helper: render the array literal across lines.
            auto renderArray = [&]() {
                body += "[\n";
                for (std::size_t k = 0; k < pairs.size(); ++k) {
                    body += INDENT;
                    body += INDENT;
                    body += pairs[k].first;
                    if (plc.isPair) {
                        body += " => ";
                        body += pairs[k].second;
                    }
                    body += ",\n";  // trailing comma on last item too
                }
                body += INDENT;
                body += "]";
            };
            bool ok = true;
            for (std::size_t k = 0; k < plc.paramNames.size(); ++k) {
                if (needComma) body += ", ";
                needComma = true;
                bool isArr = (k == plc.pairsParamIdx);
                // Switch to named once we hit any param past the first
                // positional run, OR the [PreferNamed]-flagged param, OR
                // when the param order would otherwise be ambiguous.
                bool wantNamed = forceNamed
                    || (k < plc.paramPreferNamed.size() && plc.paramPreferNamed[k])
                    || (isArr && k != 0);
                if (wantNamed) {
                    body += plc.paramNames[k];
                    body += ": ";
                    forceNamed = true;
                }
                if (isArr) {
                    renderArray();
                } else {
                    if (!bindings[k]) { ok = false; break; }
                    body += *bindings[k];
                }
            }
            if (!ok) continue;
            body += ")";
            std::size_t consumed = j - i;
            if (!best || consumed > best->second) best = std::make_pair(std::move(body), consumed);
        }
        if (best) {
            std::size_t consumedBytes = 0;
            for (std::size_t k = 0; k < best->second; ++k) consumedBytes += stmts[i + k].consumed;
            outStmts.push_back({stmts[i].offset, consumedBytes, std::move(best->first)});
            i += best->second;
        } else {
            outStmts.push_back(stmts[i]);
            ++i;
        }
    }
    stmts = std::move(outStmts);
}
// Recursive helper for tryMatchComposite -- walks a list of CompItems against
// stmts starting at `idx`, returning the number of stmts consumed on success.
// Handles flat calls, `return`, and block-form `if (cond) { body }` items.
// Threads `bindings` through recursive calls so a param introduced in one
// branch is checked-consistent against later uses (including inside if-blocks).
std::optional<std::size_t> matchCompItems(
        const std::vector<CompItem>& items,
        const std::vector<DecodedInstr>& stmts,
        std::size_t idx,
        const std::size_t startIdx,
        const std::unordered_set<int>& labelOffsets,
        std::vector<std::optional<std::string>>& bindings,
        const std::vector<std::string>& paramNames) {
    const std::size_t origIdx = idx;
    for (const auto& want : items) {
        if (idx >= stmts.size()) return std::nullopt;
        // No label may break a multi-stmt match between items (except at the
        // very start of the outer match).
        if (idx != startIdx && labelOffsets.count(static_cast<int>(stmts[idx].offset))) {
            return std::nullopt;
        }
        if (want.isReturn) {
            if (stmts[idx].body != "return") return std::nullopt;
            ++idx;
            continue;
        }
        if (want.isIfBlock) {
            std::string_view b = stmts[idx].body;
            if (!startsWith(b, "if (") || b.size() < 7 || b.back() != '{') return std::nullopt;
            // Strip leading `if (` (4 chars) and trailing `) {` (3 chars).
            std::string_view cond = b.substr(4, b.size() - 4 - 3);
            if (!matchPredicateTemplate(want.condTokens, cond, bindings, paramNames)) {
                return std::nullopt;
            }
            ++idx;
            auto innerConsumed = matchCompItems(want.body, stmts, idx, startIdx,
                                                labelOffsets, bindings, paramNames);
            if (!innerConsumed) return std::nullopt;
            idx += *innerConsumed;
            if (idx >= stmts.size() || stmts[idx].body != "}") return std::nullopt;
            ++idx;
            continue;
        }
        // Flat call.
        auto call = parseSimpleCall(stmts[idx].body);
        if (!call) return std::nullopt;
        if (call->mnemonic != want.mnemonic) return std::nullopt;
        if (call->args.size() != want.args.size()) return std::nullopt;
        for (std::size_t a = 0; a < want.args.size(); ++a) {
            NamedArg gotNA = compSplitNamedArg(call->args[a]);
            if (!want.args[a].fieldName.empty()
                && want.args[a].fieldName != gotNA.fieldName) return std::nullopt;
            const std::string& gotVal = gotNA.value;
            if (want.args[a].paramIdx >= 0) {
                int pi = want.args[a].paramIdx;
                if (bindings[pi]) {
                    if (*bindings[pi] != gotVal) return std::nullopt;
                } else {
                    bindings[pi] = gotVal;
                }
            } else {
                const std::string& wantVal = want.args[a].value;
                if (!matchArgValue(wantVal, gotVal, bindings, paramNames)) {
                    return std::nullopt;
                }
            }
        }
        ++idx;
    }
    return idx - origIdx;
}

// Match one composite's body against the window starting at stmts[i].
// On success, returns the (rewritten-call-body, stmts-consumed) pair.
std::optional<std::pair<std::string, std::size_t>> tryMatchComposite(
        const Composite& comp,
        const std::vector<DecodedInstr>& stmts,
        std::size_t i,
        const std::unordered_set<int>& labelOffsets) {
    std::vector<std::optional<std::string>> bindings(comp.paramNames.size());
    auto consumed = matchCompItems(comp.items, stmts, i, i,
                                    labelOffsets, bindings, comp.paramNames);
    if (!consumed) return std::nullopt;
    for (auto& b : bindings) {
        if (!b) return std::nullopt;
    }
    // Default-trim: walk backwards and drop trailing params whose binding
    // numerically equals their declared default.  Stops on first mismatch --
    // a default-equal arg in the middle of differing trailing args has to
    // stay (positional binding wouldn't survive its omission).  Named-style
    // params are also kept; dropping them would silently change which slot
    // the next positional arg lands in.
    std::size_t emitCount = bindings.size();
    while (emitCount > 0) {
        std::size_t k = emitCount - 1;
        if (k >= comp.paramDefaults.size() || !comp.paramDefaults[k]) break;
        if (k < comp.paramPreferNamed.size() && comp.paramPreferNamed[k]) break;
        if (!tokensNumericallyEqual(*bindings[k], *comp.paramDefaults[k])) break;
        --emitCount;
    }

    std::string body = comp.name;
    body += '(';
    // The macro-call parser rejects positional args after named ones, so once
    // any [PreferNamed] param is emitted with its `name:` prefix, every
    // subsequent param must be named too (even if the signature didn't mark
    // it [PreferNamed]).  This lets users sprinkle [PreferNamed] anywhere in
    // the signature without re-ordering.
    bool namedSeen = false;
    for (std::size_t k = 0; k < emitCount; ++k) {
        if (k) body += ", ";
        bool wantNamed = namedSeen
            || (k < comp.paramPreferNamed.size() && comp.paramPreferNamed[k]);
        if (wantNamed) {
            body += comp.paramNames[k];
            body += ": ";
            namedSeen = true;
        }
        // Render bare ints through the param's declared kind so the call
        // reads `battle(Digimon.Agumon)` instead of `battle(3)`.  Non-int
        // bindings (already-symbolic from a nested fold) pass through.
        const std::string& bound = *bindings[k];
        if (k < comp.paramKinds.size() && comp.paramKinds[k]) {
            if (auto iv = tryParseInt(bound)) {
                body += renderTypedValue(*iv, *comp.paramKinds[k]);
                continue;
            }
        }
        body += bound;
    }
    body += ')';
    return std::make_pair(std::move(body), *consumed);
}

// One sweep of the generic beautifier; returns true if it rewrote anything.
bool genericBeautifyOnce(std::vector<DecodedInstr>& stmts,
                          const std::unordered_set<int>& labelOffsets) {
    const auto& catalog = compositeCatalog();
    if (catalog.empty()) return false;
    std::vector<DecodedInstr> out;
    out.reserve(stmts.size());
    bool changed = false;
    std::size_t i = 0;
    while (i < stmts.size()) {
        // Longest-match-wins: prefer the composite that consumes the most stmts.
        std::optional<std::pair<std::string, std::size_t>> bestMatch;
        for (const auto& comp : catalog) {
            auto m = tryMatchComposite(comp, stmts, i, labelOffsets);
            if (!m) continue;
            if (!bestMatch || m->second > bestMatch->second) bestMatch = std::move(m);
        }
        if (bestMatch) {
            std::size_t consumed = 0;
            for (std::size_t k = 0; k < bestMatch->second; ++k) {
                consumed += stmts[i + k].consumed;
            }
            out.push_back({stmts[i].offset, consumed, std::move(bestMatch->first)});
            i += bestMatch->second;
            changed = true;
        } else {
            out.push_back(stmts[i]);
            ++i;
        }
    }
    if (changed) stmts = std::move(out);
    return changed;
}

void genericBeautifyComposites(std::vector<DecodedInstr>& stmts,
                                const std::unordered_set<int>& labelOffsets) {
    while (genericBeautifyOnce(stmts, labelOffsets)) {}
}

// Collapse consecutive `addStats/reduceStats/setStats(Stat.X, V)` runs into
// the named-arg list form.  Threshold: 2 or more in a row with no label in
// between.
void beautifyStatsList(std::vector<DecodedInstr>& stmts,
                       const std::unordered_set<int>& labelOffsets) {
    static constexpr std::array<std::string_view, 3> ops = {"addStats", "reduceStats", "setStats"};
    auto isStatOp = [&](std::string_view m) {
        for (auto x : ops) if (m == x) return true;
        return false;
    };
    std::vector<DecodedInstr> out;
    out.reserve(stmts.size());
    std::size_t i = 0;
    while (i < stmts.size()) {
        auto c0 = parseSimpleCall(stmts[i].body);
        if (!c0 || !isStatOp(c0->mnemonic) || c0->args.size() != 2
            || !c0->args[0].starts_with("Stat.")) {
            out.push_back(stmts[i]);
            ++i;
            continue;
        }
        std::size_t runEnd = i;
        for (std::size_t j = i + 1; j < stmts.size(); ++j) {
            if (labelOffsets.count(static_cast<int>(stmts[j].offset))) break;
            auto cj = parseSimpleCall(stmts[j].body);
            if (!cj || cj->mnemonic != c0->mnemonic || cj->args.size() != 2
                || !cj->args[0].starts_with("Stat.")) break;
            runEnd = j;
        }
        std::size_t runLen = runEnd - i + 1;
        if (runLen >= 1) {
            std::string merged{c0->mnemonic};
            merged += '(';
            for (std::size_t k = i; k <= runEnd; ++k) {
                if (k > i) merged += ", ";
                auto ck = parseSimpleCall(stmts[k].body);
                std::string_view sn = ck->args[0];
                sn.remove_prefix(5); // "Stat."
                // Lowercase first letter for the named-arg key.
                if (!sn.empty() && sn.front() >= 'A' && sn.front() <= 'Z') {
                    merged += static_cast<char>(sn.front() - 'A' + 'a');
                    merged.append(sn.substr(1));
                } else {
                    merged.append(sn);
                }
                merged += ": ";
                merged.append(ck->args[1]);
            }
            merged += ')';
            std::size_t consumed = 0;
            for (std::size_t k = i; k <= runEnd; ++k) consumed += stmts[k].consumed;
            out.push_back({stmts[i].offset, consumed, std::move(merged)});
            i = runEnd + 1;
            continue;
        }
        out.push_back(stmts[i]);
        ++i;
    }
    stmts = std::move(out);
}

// Collapse consecutive same-mnemonic statements that differ in exactly one
// numeric argument position by a stride of +1 into a `for id in S..E { ... }`
// loop.  Requires >= 3 consecutive statements.  Loop variable is named `id`.
// Split a `Kind(N)` token into (kind-prefix, int).  For plain ints the
// prefix is empty.  Returns nullopt when the arg can't be reduced to an
// integer at all (e.g. a string literal or a `Kind.Name` we couldn't
// resolve symbolically).
struct TypedInt { std::string prefix; int value; };
std::optional<TypedInt> typedIntFromArg(std::string_view arg) {
    if (auto v = tryParseInt(arg)) return TypedInt{"", *v};
    if (arg.size() > 3 && arg.back() == ')'
        && arg[0] >= 'A' && arg[0] <= 'Z') {
        auto lp = arg.find('(');
        if (lp != std::string_view::npos
            && symKindFromLabel(arg.substr(0, lp))) {
            auto inner = arg.substr(lp + 1, arg.size() - lp - 2);
            if (auto v = tryParseInt(inner)) {
                return TypedInt{std::string{arg.substr(0, lp + 1)}, *v};
            }
        }
    }
    if (auto v = tryResolveSymbolicToken(arg)) {
        return TypedInt{"", *v};
    }
    return std::nullopt;
}

void beautifyForRanges(std::vector<DecodedInstr>& stmts,
                       const std::unordered_set<int>& labelOffsets) {
    std::vector<DecodedInstr> out;
    out.reserve(stmts.size());
    std::size_t i = 0;
    while (i < stmts.size()) {
        auto c0 = parseSimpleCall(stmts[i].body);
        if (!c0 || c0->args.empty()) {
            out.push_back(stmts[i]);
            ++i;
            continue;
        }
        // Extend a run by checking each step's arg lists.
        std::size_t runEnd = i;
        int diffPos = -1;
        for (std::size_t j = i + 1; j < stmts.size(); ++j) {
            if (labelOffsets.count(static_cast<int>(stmts[j].offset))) break;
            auto cj = parseSimpleCall(stmts[j].body);
            if (!cj || cj->mnemonic != c0->mnemonic || cj->args.size() != c0->args.size()) break;
            auto cPrev = parseSimpleCall(stmts[j - 1].body);
            if (!cPrev) break;
            int d = -1;
            bool ok = true;
            for (std::size_t k = 0; k < cPrev->args.size(); ++k) {
                if (cPrev->args[k] != cj->args[k]) {
                    if (d != -1) { ok = false; break; }
                    d = static_cast<int>(k);
                }
            }
            if (!ok || d == -1) break;
            auto va = typedIntFromArg(cPrev->args[d]);
            auto vb = typedIntFromArg(cj->args[d]);
            if (!va || !vb || va->prefix != vb->prefix || vb->value - va->value != 1) break;
            if (diffPos == -1) diffPos = d;
            else if (diffPos != d) break;
            runEnd = j;
        }
        std::size_t runLen = runEnd - i + 1;
        if (runLen >= 3 && diffPos != -1) {
            auto cEnd = parseSimpleCall(stmts[runEnd].body);
            auto vS = typedIntFromArg(c0->args[diffPos]);
            auto vE = typedIntFromArg(cEnd->args[diffPos]);
            // Build the loop-body call with `id` replacing the iterator slot.
            std::string call{c0->mnemonic};
            call += '(';
            for (std::size_t k = 0; k < c0->args.size(); ++k) {
                if (k) call += ", ";
                if (static_cast<int>(k) == diffPos) call += "id";
                else call.append(c0->args[k]);
            }
            call += ')';
            // Render endpoints in whatever shape the source used -- bare int
            // or `Kind(N)` wrapper -- so the range form mirrors the call.
            auto renderEndpoint = [&](const TypedInt& t) {
                std::string s = t.prefix;
                s += toDec(static_cast<long long>(t.value));
                if (!t.prefix.empty()) s += ')';
                return s;
            };
            std::string forBody = "for id in ";
            forBody += renderEndpoint(*vS);
            forBody += "..";
            forBody += renderEndpoint(*vE);
            forBody += " {\n";
            forBody += INDENT;
            forBody += INDENT;
            forBody += call;
            forBody += ";\n";
            forBody += INDENT;
            forBody += "}";
            std::size_t consumed = 0;
            for (std::size_t k = i; k <= runEnd; ++k) consumed += stmts[k].consumed;
            out.push_back({stmts[i].offset, consumed, std::move(forBody)});
            i = runEnd + 1;
            continue;
        }
        out.push_back(stmts[i]);
        ++i;
    }
    stmts = std::move(out);
}

// Collapse the canonical choice triple
//     setSelection(t1, t2, ...);
//     showTextbox("L1\nL2\n...\n");
//     waitForSelectionChoice();
// into `choice { "L1" -> t1, "L2" -> t2, ... }`.  Number of labels in the
// showTextbox string must equal number of setSelection targets.
void beautifyChoice(std::vector<DecodedInstr>& stmts,
                    const std::unordered_set<int>& labelOffsets) {
    std::vector<DecodedInstr> out;
    out.reserve(stmts.size());
    std::size_t i = 0;
    while (i < stmts.size()) {
        if (i + 2 < stmts.size()
            && !labelOffsets.count(static_cast<int>(stmts[i + 1].offset))
            && !labelOffsets.count(static_cast<int>(stmts[i + 2].offset))) {
            auto c0 = parseSimpleCall(stmts[i].body);
            auto c1 = parseSimpleCall(stmts[i + 1].body);
            auto c2 = parseSimpleCall(stmts[i + 2].body);
            if (c0 && c0->mnemonic == "setSelection" && !c0->args.empty()
                && c1 && c1->mnemonic == "showTextbox" && c1->args.size() == 1
                && c2 && c2->mnemonic == "waitForSelectionChoice" && c2->args.empty()) {
                std::string_view txt = c1->args[0];
                if (txt.size() >= 2 && txt.front() == '"' && txt.back() == '"') {
                    txt = txt.substr(1, txt.size() - 2);
                    // Split on the literal two-char sequence `\n`.  Drop a
                    // trailing empty fragment so "Pay\nDon't pay\n" yields
                    // exactly two labels.
                    std::vector<std::string_view> labels;
                    std::size_t segStart = 0;
                    for (std::size_t k = 0; k + 1 < txt.size(); ++k) {
                        if (txt[k] == '\\' && txt[k + 1] == 'n') {
                            labels.push_back(txt.substr(segStart, k - segStart));
                            segStart = k + 2;
                            ++k;
                        }
                    }
                    if (segStart < txt.size()) labels.push_back(txt.substr(segStart));
                    if (labels.size() == c0->args.size()) {
                        std::string body = "choice { ";
                        for (std::size_t k = 0; k < labels.size(); ++k) {
                            if (k) body += ", ";
                            body += '"';
                            body.append(labels[k]);
                            body += "\" -> ";
                            body.append(c0->args[k]);
                        }
                        body += " }";
                        std::size_t consumed = stmts[i].consumed
                                             + stmts[i + 1].consumed
                                             + stmts[i + 2].consumed;
                        out.push_back({stmts[i].offset, consumed, std::move(body)});
                        i += 3;
                        continue;
                    }
                }
            }
        }
        out.push_back(stmts[i]);
        ++i;
    }
    stmts = std::move(out);
}

// Collapse consecutive `removeItem(Item.X, V);` runs.  Two forms:
//   * Uniform V ->  `removeItems([:A, :B, ...], V);`
//   * Mixed V  ->  `removeItems([:A => v1, :B => v2, ...]);` (hash form)
// Threshold >= 2; >= 8 items emits a 4-per-line grid.
void beautifyRemoveItems(std::vector<DecodedInstr>& stmts,
                         const std::unordered_set<int>& labelOffsets) {
    std::vector<DecodedInstr> out;
    out.reserve(stmts.size());
    std::size_t i = 0;
    while (i < stmts.size()) {
        auto c0 = parseSimpleCall(stmts[i].body);
        if (!c0 || c0->mnemonic != "removeItem" || c0->args.size() != 2) {
            out.push_back(stmts[i]);
            ++i;
            continue;
        }
        // Extend run over any removeItem call (count may differ).
        std::size_t runEnd = i;
        for (std::size_t j = i + 1; j < stmts.size(); ++j) {
            if (labelOffsets.count(static_cast<int>(stmts[j].offset))) break;
            auto cj = parseSimpleCall(stmts[j].body);
            if (!cj || cj->mnemonic != "removeItem" || cj->args.size() != 2) break;
            runEnd = j;
        }
        const std::size_t runLen = runEnd - i + 1;
        if (runLen < 2) { out.push_back(stmts[i]); ++i; continue; }

        // Are all counts uniform?
        const std::string_view firstCount = c0->args[1];
        bool uniform = true;
        for (std::size_t k = i + 1; k <= runEnd; ++k) {
            auto ck = parseSimpleCall(stmts[k].body);
            if (ck->args[1] != firstCount) { uniform = false; break; }
        }

        auto fmtItem = [](std::string_view a) -> std::string {
            if (a.size() > 5 && a.substr(0, 5) == "Item.") {
                std::string s = ":";
                s.append(a.substr(5));
                return s;
            }
            return std::string{a};
        };

        std::string body = "removeItems([";
        if (runLen >= 8) {
            body += "\n";
            for (std::size_t k = i; k <= runEnd; ++k) {
                auto ck = parseSimpleCall(stmts[k].body);
                const std::size_t inGroup = (k - i) % 4;
                if (inGroup == 0) body += "    ";
                body += fmtItem(ck->args[0]);
                if (!uniform) {
                    body += " => ";
                    body.append(ck->args[1]);
                }
                if (k != runEnd) body += ",";
                if (inGroup == 3 || k == runEnd) body += "\n";
                else body += " ";
            }
            body += "  ]";
        } else {
            for (std::size_t k = i; k <= runEnd; ++k) {
                if (k > i) body += ", ";
                auto ck = parseSimpleCall(stmts[k].body);
                body += fmtItem(ck->args[0]);
                if (!uniform) {
                    body += " => ";
                    body.append(ck->args[1]);
                }
            }
            body += "]";
        }
        if (uniform) {
            body += ", ";
            body.append(firstCount);
        }
        body += ")";

        std::size_t consumed = 0;
        for (std::size_t k = i; k <= runEnd; ++k) consumed += stmts[k].consumed;
        out.push_back({stmts[i].offset, consumed, std::move(body)});
        i = runEnd + 1;
    }
    stmts = std::move(out);
}

// Used by beautifyForArray to reject patterns whose body has a top-level
// named-arg; the synthesized iterator would shadow the key.
bool bodyHasNamedArg(std::string_view body);

// General `for x in [v1, v2, ...] { call(..., x, ...); }` collapse: >= 3
// consecutive same-mnemonic calls where exactly ONE arg position varies
// (others identical).  Excludes opcodes handled by domain-specific
// collapses (removeItem, learnMove, stat ops, setDialogOwner/showTextbox).
// If all varying values share a `Kind.` prefix, it's stripped to `:Sym`.
void beautifyForArray(std::vector<DecodedInstr>& stmts,
                      const std::unordered_set<int>& labelOffsets) {
    auto domainSpecific = [](std::string_view mn) {
        // `speak` (the dialog sugar) is excluded by user request -- wrapping
        // distinct dialog lines in a for-loop hides meaning.
        return mn == "removeItem" || mn == "learnMove"
            || mn == "addStats"   || mn == "reduceStats" || mn == "setStats"
            || mn == "setDialogOwner" || mn == "showTextbox"
            || mn == "speak";
    };
    std::vector<DecodedInstr> out;
    out.reserve(stmts.size());
    std::size_t i = 0;
    while (i < stmts.size()) {
        auto c0 = parseSimpleCall(stmts[i].body);
        if (!c0 || c0->args.empty() || domainSpecific(c0->mnemonic)) {
            out.push_back(stmts[i]); ++i; continue;
        }
        std::size_t runEnd = i;
        int diffPos = -1;
        for (std::size_t j = i + 1; j < stmts.size(); ++j) {
            if (labelOffsets.count(static_cast<int>(stmts[j].offset))) break;
            auto cj = parseSimpleCall(stmts[j].body);
            if (!cj || cj->mnemonic != c0->mnemonic
                || cj->args.size() != c0->args.size()) break;
            // Compare against the FIRST occurrence so the same slot stays
            // the iterator across the whole run.
            int d = -1; bool ok = true;
            for (std::size_t k = 0; k < c0->args.size(); ++k) {
                if (c0->args[k] != cj->args[k]) {
                    if (d != -1) { ok = false; break; }
                    d = static_cast<int>(k);
                }
            }
            if (!ok || d == -1) break;
            if (diffPos == -1) diffPos = d;
            else if (diffPos != d) break;
            runEnd = j;
        }
        const std::size_t runLen = runEnd - i + 1;
        if (runLen < 3 || diffPos == -1) {
            out.push_back(stmts[i]); ++i; continue;
        }

        // Refuse if the body itself contains a named-arg form (e.g.
        // spawnItem's `x: 39`).  The iterator name (`x`) could shadow the
        // literal key, corrupting expansion at parse time.
        if (bodyHasNamedArg(stmts[i].body)) {
            out.push_back(stmts[i]); ++i; continue;
        }

        // Collect varying values across occurrences.
        std::vector<std::string> values;
        for (std::size_t k = i; k <= runEnd; ++k) {
            auto ck = parseSimpleCall(stmts[k].body);
            values.emplace_back(ck->args[diffPos]);
        }
        // Detect a common `Kind.` prefix -> ruby-style `:Name`.
        std::string commonPrefix;
        bool havePrefix = true;
        for (std::size_t k = 0; k < values.size(); ++k) {
            std::size_t dot = values[k].find('.');
            // Reject pstat[...]-style brackets that contain a dot like none.
            if (dot == std::string::npos || values[k].find('[') != std::string::npos) {
                havePrefix = false; break;
            }
            std::string p = values[k].substr(0, dot + 1);
            if (k == 0) commonPrefix = std::move(p);
            else if (commonPrefix != p) { havePrefix = false; break; }
        }
        auto fmt = [&](const std::string& v) -> std::string {
            if (havePrefix && v.size() > commonPrefix.size()
                && v.compare(0, commonPrefix.size(), commonPrefix) == 0) {
                return std::string{":"} + v.substr(commonPrefix.size());
            }
            return v;
        };

        // Build call template with `x` at the varying slot.
        std::string call{c0->mnemonic};
        call += '(';
        for (std::size_t a = 0; a < c0->args.size(); ++a) {
            if (a > 0) call += ", ";
            if (static_cast<int>(a) == diffPos) call += "x";
            else call.append(c0->args[a]);
        }
        call += ')';

        // Emit; for-block body is always multi-line.  Long lists use a
        // 4-per-row grid for the array literal itself.
        std::string body = "for x in [";
        if (values.size() >= 8) {
            body += "\n";
            for (std::size_t k = 0; k < values.size(); ++k) {
                const std::size_t inGroup = k % 4;
                if (inGroup == 0) body += "    ";
                body += fmt(values[k]);
                if (k + 1 != values.size()) body += ",";
                if (inGroup == 3 || k + 1 == values.size()) body += "\n";
                else body += " ";
            }
            body += "  ]";
        } else {
            for (std::size_t k = 0; k < values.size(); ++k) {
                if (k > 0) body += ", ";
                body += fmt(values[k]);
            }
            body += "]";
        }
        body += " {\n";
        body += INDENT;
        body += INDENT;
        body += call;
        body += ";\n";
        body += INDENT;
        body += "}";
        std::size_t consumed = 0;
        for (std::size_t k = i; k <= runEnd; ++k) consumed += stmts[k].consumed;
        out.push_back({stmts[i].offset, consumed, std::move(body)});
        i = runEnd + 1;
    }
    stmts = std::move(out);
}

// Extract the value side of a `label: value` named-arg slot.  Returns the

// Collapse a beautifyForRanges output of shape
//     for id in S..E {
//       setObjectVisibility(id, V);
//     }
// (already a single DecodedInstr whose body is the multi-line string emitted
// by beautifyForRanges) into a flat `setObjectsVisibleRange(S, E, V);` call.
// Runs after beautifyForRanges.
void beautifySetObjectsVisibleRange(std::vector<DecodedInstr>& stmts,
                                    const std::unordered_set<int>& /*labelOffsets*/) {
    for (auto& stmt : stmts) {
        std::string_view body = stmt.body;
        constexpr std::string_view kPrefix = "for id in ";
        if (body.substr(0, kPrefix.size()) != kPrefix) continue;
        std::size_t dots = body.find("..", kPrefix.size());
        if (dots == std::string_view::npos) continue;
        std::size_t braceOpen = body.find(" {\n", dots);
        if (braceOpen == std::string_view::npos) continue;
        std::string_view s = body.substr(kPrefix.size(), dots - kPrefix.size());
        std::string_view e = body.substr(dots + 2, braceOpen - dots - 2);
        std::size_t inner = braceOpen + 3;  // past " {\n"
        // Skip the body-line indent.
        while (inner < body.size() && (body[inner] == ' ' || body[inner] == '\t')) ++inner;
        std::size_t lineEnd = body.find(";\n", inner);
        if (lineEnd == std::string_view::npos) continue;
        std::string_view callExpr = body.substr(inner, lineEnd - inner);
        // Trailing line must be the closer (allow any indent + "}").
        std::size_t after = lineEnd + 2;
        while (after < body.size() && (body[after] == ' ' || body[after] == '\t')) ++after;
        if (after >= body.size() || body[after] != '}') continue;
        // The inner call must be exactly `setObjectVisibility(id, V)`.
        auto inner_call = parseSimpleCall(callExpr);
        if (!inner_call) continue;
        if (inner_call->mnemonic != "setObjectVisibility") continue;
        if (inner_call->args.size() != 2) continue;
        if (inner_call->args[0] != "id") continue;
        std::string rewritten = "setObjectsVisibleRange(";
        rewritten.append(s); rewritten += ", ";
        rewritten.append(e); rewritten += ", ";
        rewritten.append(inner_call->args[1]);
        rewritten += ')';
        stmt.body = std::move(rewritten);
    }
}

// Collapse consecutive `learnMove(Move.X);` runs into `learnMoves([...]);`.
// Threshold: 2 or more in a row with no label between.
void beautifyLearnMoves(std::vector<DecodedInstr>& stmts,
                        const std::unordered_set<int>& labelOffsets) {
    std::vector<DecodedInstr> out;
    out.reserve(stmts.size());
    std::size_t i = 0;
    while (i < stmts.size()) {
        auto c0 = parseSimpleCall(stmts[i].body);
        if (!c0 || c0->mnemonic != "learnMove" || c0->args.size() != 1) {
            out.push_back(stmts[i]);
            ++i;
            continue;
        }
        std::size_t runEnd = i;
        for (std::size_t j = i + 1; j < stmts.size(); ++j) {
            if (labelOffsets.count(static_cast<int>(stmts[j].offset))) break;
            auto cj = parseSimpleCall(stmts[j].body);
            if (!cj || cj->mnemonic != "learnMove" || cj->args.size() != 1) break;
            runEnd = j;
        }
        std::size_t runLen = runEnd - i + 1;
        if (runLen >= 2) {
            auto fmtMove = [](std::string_view a) -> std::string {
                if (a.size() > 5 && a.substr(0, 5) == "Move.") {
                    std::string s = ":";
                    s.append(a.substr(5));
                    return s;
                }
                return std::string{a};
            };
            std::string body;
            // Multi-line emission for long runs.  4-per-line groups read
            // best in practice; the 8-cutoff keeps small lists single-line.
            if (runLen >= 8) {
                body = "learnMoves([\n";
                for (std::size_t k = i; k <= runEnd; ++k) {
                    auto ck = parseSimpleCall(stmts[k].body);
                    const std::size_t inGroup = (k - i) % 4;
                    if (inGroup == 0) body += "    ";
                    body += fmtMove(ck->args[0]);
                    if (k != runEnd) body += ",";
                    if (inGroup == 3 || k == runEnd) body += "\n";
                    else body += " ";
                }
                body += "    ])";
            } else {
                body = "learnMoves([";
                for (std::size_t k = i; k <= runEnd; ++k) {
                    if (k > i) body += ", ";
                    auto ck = parseSimpleCall(stmts[k].body);
                    body += fmtMove(ck->args[0]);
                }
                body += "])";
            }
            std::size_t consumed = 0;
            for (std::size_t k = i; k <= runEnd; ++k) consumed += stmts[k].consumed;
            out.push_back({stmts[i].offset, consumed, std::move(body)});
            i = runEnd + 1;
            continue;
        }
        out.push_back(stmts[i]);
        ++i;
    }
    stmts = std::move(out);
}

bool isAsciiIdentCont(char c) {
    return c == '_' || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

// Pull every same-section `L_<4hex>` label reference out of `body` (in source
// order).  Skips matches preceded by `<ident>.` (those are cross-section
// references like `OtherSec.L_0042`) and matches inside identifier runs.
void collectSameSecLabelRefs(std::string_view body, std::vector<int>& out) {
    std::size_t i = 0;
    while (i + 6 <= body.size()) {
        if (body[i] != 'L' || body[i + 1] != '_') { ++i; continue; }
        if (i >= 1 && body[i - 1] == '.') { i += 6; continue; }
        if (i >= 1 && isAsciiIdentCont(body[i - 1])) { ++i; continue; }
        bool ok = true;
        int off = 0;
        for (int k = 0; k < 4; ++k) {
            char c = body[i + 2 + k];
            if (c >= '0' && c <= '9') off = off * 16 + (c - '0');
            else if (c >= 'a' && c <= 'f') off = off * 16 + (c - 'a' + 10);
            else { ok = false; break; }
        }
        if (!ok) { ++i; continue; }
        if (i + 6 < body.size() && isAsciiIdentCont(body[i + 6])) { i += 6; continue; }
        out.push_back(off);
        i += 6;
    }
}

// Body is exactly `goto L_<4hex>` (no semicolon -- the serializer adds it),
// and the hex value matches targetOff.
bool isUnconditionalGotoTo(std::string_view body, int targetOff) {
    if (body.size() != 11) return false;
    if (body.compare(0, 7, "goto L_") != 0) return false;
    int v = 0;
    for (int k = 0; k < 4; ++k) {
        char c = body[7 + k];
        if (c >= '0' && c <= '9') v = v * 16 + (c - '0');
        else if (c >= 'a' && c <= 'f') v = v * 16 + (c - 'a' + 10);
        else return false;
    }
    return v == targetOff;
}

// Replace every `goto L_<4hex>` token in `body` (with the given target hex)
// by `kw`.  String-aware; word-boundary aware on both sides.
std::string rewriteGotoToKeyword(std::string_view body, int targetOff,
                                 std::string_view kw) {
    char hex[5];
    for (int k = 0; k < 4; ++k) {
        int d = (targetOff >> ((3 - k) * 4)) & 0xf;
        hex[k] = static_cast<char>(d < 10 ? '0' + d : 'a' + d - 10);
    }
    hex[4] = '\0';
    std::string out;
    out.reserve(body.size());
    bool inStr = false;
    std::size_t i = 0;
    while (i < body.size()) {
        char c = body[i];
        if (inStr) {
            out += c;
            if (c == '\\' && i + 1 < body.size()) { out += body[i + 1]; i += 2; continue; }
            if (c == '"') inStr = false;
            ++i;
            continue;
        }
        if (c == '"') { inStr = true; out += c; ++i; continue; }
        if (i + 11 <= body.size()
            && body.compare(i, 7, "goto L_") == 0
            && (i == 0 || !isAsciiIdentCont(body[i - 1]))
            && body[i + 7] == hex[0] && body[i + 8] == hex[1]
            && body[i + 9] == hex[2] && body[i + 10] == hex[3]
            && (i + 11 == body.size() || !isAsciiIdentCont(body[i + 11]))) {
            out.append(kw);
            i += 11;
            continue;
        }
        out += c;
        ++i;
    }
    return out;
}

// Recognize the classic `Lx: ...; goto Lx; Ly:` (or `; goto Lx;` with no
// successor label) pattern and rewrite it as `loop { ... }` with `break;` /
// `continue;` in place of the internal `goto Ly;` and mid-body `goto Lx;`.
// Conservative: when a label is referenced from outside the recognized block
// (same-section out-of-range OR cross-section), the label is preserved
// rather than dropped, and the loop wraps around it -- still byte-identical
// on reassembly because the synthetic loop labels resolve to the same
// in-section offset as the user-visible label.
//
// Returns true when at least one loop was rewritten.
bool beautifyLoopsOnce(std::vector<DecodedInstr>& stmts,
                       std::unordered_set<int>& secLabels,
                       const std::unordered_set<int>& crossSecRefs) {
    std::unordered_map<int, std::vector<std::size_t>> sameSecRefs;
    for (std::size_t k = 0; k < stmts.size(); ++k) {
        std::vector<int> refs;
        collectSameSecLabelRefs(stmts[k].body, refs);
        for (int off : refs) sameSecRefs[off].push_back(k);
    }

    std::vector<DecodedInstr> out;
    out.reserve(stmts.size() + 4);
    bool changed = false;
    std::size_t i = 0;
    while (i < stmts.size()) {
        int oxOff = static_cast<int>(stmts[i].offset);

        std::size_t backEdge = SIZE_MAX;
        if (oxOff != 0 && secLabels.count(oxOff)) {
            auto refsIt = sameSecRefs.find(oxOff);
            if (refsIt != sameSecRefs.end()) {
                for (auto k : refsIt->second) {
                    if (k > i && isUnconditionalGotoTo(stmts[k].body, oxOff)) {
                        backEdge = k;
                    }
                }
            }
        }

        if (backEdge != SIZE_MAX) {
            // External-ref test for the loop head.
            bool oxExternal = crossSecRefs.count(oxOff) > 0;
            if (!oxExternal) {
                for (auto k : sameSecRefs[oxOff]) {
                    if (k < i || k > backEdge) { oxExternal = true; break; }
                }
            }

            int oyOff = -1;
            if (backEdge + 1 < stmts.size()) {
                int next = static_cast<int>(stmts[backEdge + 1].offset);
                if (secLabels.count(next)) oyOff = next;
            }
            bool oyExternal = false;
            if (oyOff != -1) {
                oyExternal = crossSecRefs.count(oyOff) > 0;
                if (!oyExternal) {
                    auto oyRefsIt = sameSecRefs.find(oyOff);
                    if (oyRefsIt != sameSecRefs.end()) {
                        for (auto k : oyRefsIt->second) {
                            if (k < i || k > backEdge) { oyExternal = true; break; }
                        }
                    }
                }
            }

            // Emit the rewritten block.
            out.push_back({stmts[i].offset, 0, "loop {"});
            for (std::size_t k = i; k < backEdge; ++k) {
                std::string nb = rewriteGotoToKeyword(stmts[k].body, oxOff, "continue");
                if (oyOff != -1) {
                    nb = rewriteGotoToKeyword(nb, oyOff, "break");
                }
                out.push_back({stmts[k].offset, stmts[k].consumed, std::move(nb)});
            }
            out.push_back({stmts[backEdge].offset, stmts[backEdge].consumed, "}"});

            if (!oxExternal) secLabels.erase(oxOff);
            if (oyOff != -1 && !oyExternal) secLabels.erase(oyOff);

            changed = true;
            i = backEdge + 1;
            continue;
        }

        out.push_back(stmts[i]);
        ++i;
    }
    stmts = std::move(out);
    return changed;
}

// Collapse the canonical two-way-jump if/else shape:
//   stmts[i]:     if (<cond>) goto Lthen; else goto Lelse
//   stmts[i+1]:   Lthen attached, body_then[0]
//   ...
//   stmts[i+m]:   goto L_<hex_end>    (the join goto; closes the then-body)
//   stmts[i+m+1]: Lelse attached, body_else[0]
//   ...
//   stmts[j_end]: Lend attached      (first stmt after the if/else)
// into `if (<cond>) { body_then } else { body_else }`.  No predicate negation
// needed -- both branches jump unconditionally.
//
// Conservative -- bail unless every guarantee holds:
//   - Three labels Lthen, Lelse, Lend in this section with no cross-section refs.
//   - Each label referenced exactly once: Lthen via stmts[i], Lelse via stmts[i],
//     Lend via stmts[i+m] (the join goto).
//   - Lthen.offset == stmts[i+1].offset (fall-through label).
//   - Join goto exists immediately before Lelse and is exactly `goto L_<4hex>`.
//
// On success: replace stmts[i] with `if (cond) {` (consumed unchanged),
// keep body_then[0..m-1] unchanged, splice `} else {` at the join-goto's
// offset (consumed = join-goto's bytes so totals match), keep body_else
// unchanged, and splice `}` at Lend.offset (consumed = 0).  Erase all
// three labels from secLabels.
bool beautifyIfElseOnce(std::vector<DecodedInstr>& stmts,
                        std::unordered_set<int>& secLabels,
                        const std::unordered_set<int>& crossSecRefs) {
    std::unordered_map<int, int> refCount;
    for (const auto& s : stmts) {
        std::vector<int> refs;
        collectSameSecLabelRefs(s.body, refs);
        for (int off : refs) ++refCount[off];
    }

    auto parseHex4 = [](std::string_view s, std::size_t at, int& out) {
        out = 0;
        for (int k = 0; k < 4; ++k) {
            char c = s[at + k];
            if (c >= '0' && c <= '9') out = out * 16 + (c - '0');
            else if (c >= 'a' && c <= 'f') out = out * 16 + (c - 'a' + 10);
            else return false;
        }
        return true;
    };

    std::vector<DecodedInstr> out;
    out.reserve(stmts.size() + 6);
    bool changed = false;
    std::size_t i = 0;
    while (i < stmts.size()) {
        bool matched = false;
        do {
            std::string_view body = stmts[i].body;
            if (!startsWith(body, "if (")) break;
            std::size_t elseMark = body.find("; else goto L_");
            if (elseMark == std::string_view::npos) break;
            if (elseMark + 14 + 4 != body.size()) break;
            int else_off = 0;
            if (!parseHex4(body, elseMark + 14, else_off)) break;
            std::string_view prefix = body.substr(0, elseMark);
            std::size_t thenGoto = prefix.rfind(") goto L_");
            if (thenGoto == std::string_view::npos) break;
            if (thenGoto + 9 + 4 != prefix.size()) break;
            int then_off = 0;
            if (!parseHex4(prefix, thenGoto + 9, then_off)) break;

            std::string_view cond = body.substr(4, thenGoto - 4);

            if (i + 1 >= stmts.size()) break;
            if (static_cast<int>(stmts[i + 1].offset) != then_off) break;

            std::size_t j_else = SIZE_MAX;
            for (std::size_t k = i + 2; k < stmts.size(); ++k) {
                if (static_cast<int>(stmts[k].offset) == else_off) { j_else = k; break; }
            }
            if (j_else == SIZE_MAX || j_else <= i + 1) break;

            std::string_view joinBody = stmts[j_else - 1].body;
            if (joinBody.size() != 11) break;
            if (!startsWith(joinBody, "goto L_")) break;
            int end_off = 0;
            if (!parseHex4(joinBody, 7, end_off)) break;

            std::size_t j_end = SIZE_MAX;
            for (std::size_t k = j_else + 1; k < stmts.size(); ++k) {
                if (static_cast<int>(stmts[k].offset) == end_off) { j_end = k; break; }
            }
            if (j_end == SIZE_MAX) break;

            if (!secLabels.count(then_off) || !secLabels.count(else_off) || !secLabels.count(end_off)) break;
            if (crossSecRefs.count(then_off) || crossSecRefs.count(else_off) || crossSecRefs.count(end_off)) break;
            auto rc = [&](int off) {
                auto it = refCount.find(off);
                return it == refCount.end() ? 0 : it->second;
            };
            if (rc(then_off) != 1 || rc(else_off) != 1 || rc(end_off) != 1) break;

            std::string openLine = "if (";
            openLine.append(cond);
            openLine += ") {";
            out.push_back({stmts[i].offset, stmts[i].consumed, std::move(openLine)});
            for (std::size_t k = i + 1; k < j_else - 1; ++k) out.push_back(stmts[k]);
            out.push_back({stmts[j_else - 1].offset, stmts[j_else - 1].consumed, "} else {"});
            for (std::size_t k = j_else; k < j_end; ++k) out.push_back(stmts[k]);
            out.push_back({static_cast<std::size_t>(end_off), 0, "}"});

            secLabels.erase(then_off);
            secLabels.erase(else_off);
            secLabels.erase(end_off);

            changed = true;
            i = j_end;
            matched = true;
        } while (false);

        if (!matched) {
            out.push_back(stmts[i]);
            ++i;
        }
    }
    stmts = std::move(out);
    return changed;
}

// Cosmetic pass: collapse the nested form `} else { if (X) { ... } }` (with
// the inner-if's matching close immediately followed by the outer close) into
// `} else if (X) { ... }`.  No bytes change -- the inner-if's open had its
// own consumed-bytes count, which gets absorbed into the merged marker.
//
// `elsif` is accepted as input by the parser but NEVER emitted here; the
// canonical disasm output is always `else if`.
//
// Bail unless:
//   - stmts[k].body == "} else {"
//   - stmts[k+1].body starts with "if (" and ends with "{"
//   - The inner-if's matching close is a plain `}` at some index K (treating
//     `} else {` as net-zero so an inner with-else still has a single matching
//     close at its eventual `}`).
//   - stmts[K+1].body == "}" -- the outer if/else's close immediately follows.
bool beautifyElseIfChainOnce(std::vector<DecodedInstr>& stmts) {
    std::vector<DecodedInstr> out;
    out.reserve(stmts.size());
    bool changed = false;
    std::size_t i = 0;
    while (i < stmts.size()) {
        bool matched = false;
        do {
            if (stmts[i].body != "} else {") break;
            if (i + 1 >= stmts.size()) break;
            std::string_view innerOpen = stmts[i + 1].body;
            if (!startsWith(innerOpen, "if (")) break;
            if (innerOpen.back() != '{') break;

            // Find K: matching `}` close of the inner-if at depth 0 (relative
            // to inner).  `} else {` inside is net-zero, never a match.
            std::size_t K = SIZE_MAX;
            int depth = 1;
            for (std::size_t j = i + 2; j < stmts.size(); ++j) {
                std::string_view b = stmts[j].body;
                if (b == "}") {
                    --depth;
                    if (depth == 0) { K = j; break; }
                } else if (b == "} else {") {
                    // Net zero: close + reopen at same level.  Doesn't match.
                    continue;
                } else if (!b.empty() && b.back() == '{') {
                    ++depth;
                }
            }
            if (K == SIZE_MAX) break;
            if (K + 1 >= stmts.size()) break;
            if (stmts[K + 1].body != "}") break;

            // Build the merged marker: "} else if (X) {".  Absorb the inner
            // open's consumed bytes (the inner if-opcode) into stmts[i]'s
            // consumed so totals balance after dropping it.
            std::string merged = "} else if (";
            merged.append(innerOpen.substr(4, innerOpen.size() - 4 - 2));  // strip "if (" / ") {"
            merged += ") {";

            out.push_back({stmts[i].offset,
                           stmts[i].consumed + stmts[i + 1].consumed,
                           std::move(merged)});
            // body between inner-open (i+1) and inner-close (K) unchanged.
            for (std::size_t k = i + 2; k < K; ++k) {
                out.push_back(stmts[k]);
            }
            // Drop stmts[K] (inner close) -- consumed=0, no byte loss.
            // Keep stmts[K+1] (the outer close `}`) as the merged close.
            out.push_back(stmts[K + 1]);

            changed = true;
            i = K + 2;
            matched = true;
        } while (false);

        if (!matched) {
            out.push_back(stmts[i]);
            ++i;
        }
    }
    stmts = std::move(out);
    return changed;
}

// Post-v1 pass: take a single-arm `if (X) { body; goto Lend; }` followed by
// `body_else; Lend:` and rewrite as `if (X) { body } else { body_else }`.
//
// The original engine compiles source-level if/else into the single-branch
// shape (`if (negated) goto Lelse; body_then; goto Lend; Lelse: body_else; Lend:`),
// not the two-way-jump opcode shape — so the v1 pass already half-collapsed
// it into a single-arm block; this pass recovers the rest.
//
// Conservative -- bail unless:
//   - stmts[i] is `if (X) {` (post-v1 open), matched close `}` (not `} else {`).
//   - Last body stmt (just before the close) is exactly `goto L_<4hex>`.
//   - body_else spans up to that label, with balanced braces (no escape past
//     the enclosing scope).
//   - Lend in-section, no cross-section refs, exactly one same-section ref
//     (the trailing goto we're dropping).
bool beautifyIfElseFromSingleArmOnce(std::vector<DecodedInstr>& stmts,
                                     std::unordered_set<int>& secLabels,
                                     const std::unordered_set<int>& crossSecRefs) {
    std::unordered_map<int, int> refCount;
    for (const auto& s : stmts) {
        std::vector<int> refs;
        collectSameSecLabelRefs(s.body, refs);
        for (int off : refs) ++refCount[off];
    }

    std::vector<DecodedInstr> out;
    out.reserve(stmts.size() + 4);
    bool changed = false;
    std::size_t i = 0;
    while (i < stmts.size()) {
        bool matched = false;
        do {
            std::string_view body = stmts[i].body;
            if (body.size() < 5) break;
            if (!startsWith(body, "if (")) break;
            if (body.back() != '{') break;

            // Find matching close `}` (NOT `} else {` — that's already if/else).
            std::size_t j_close = SIZE_MAX;
            int depth = 1;
            bool alreadyElse = false;
            for (std::size_t k = i + 1; k < stmts.size(); ++k) {
                std::string_view b = stmts[k].body;
                if (b == "} else {") {
                    --depth;
                    if (depth == 0) { alreadyElse = true; break; }
                    ++depth;
                    continue;
                }
                if (b == "}") {
                    --depth;
                    if (depth == 0) { j_close = k; break; }
                    continue;
                }
                if (!b.empty() && b.back() == '{') ++depth;
            }
            if (alreadyElse || j_close == SIZE_MAX) break;
            if (j_close <= i + 1) break;

            std::string_view tailBody = stmts[j_close - 1].body;
            if (tailBody.size() != 11) break;
            if (!startsWith(tailBody, "goto L_")) break;
            int end_off = 0;
            bool ok = true;
            for (int k = 0; k < 4; ++k) {
                char c = tailBody[7 + k];
                if (c >= '0' && c <= '9') end_off = end_off * 16 + (c - '0');
                else if (c >= 'a' && c <= 'f') end_off = end_off * 16 + (c - 'a' + 10);
                else { ok = false; break; }
            }
            if (!ok) break;

            std::size_t j_end = SIZE_MAX;
            for (std::size_t k = j_close + 1; k < stmts.size(); ++k) {
                if (static_cast<int>(stmts[k].offset) == end_off) { j_end = k; break; }
            }
            if (j_end == SIZE_MAX) break;

            // body_else span (j_close+1 .. j_end-1) must have balanced braces
            // so it doesn't escape the enclosing scope.
            int d = 0;
            bool escapes = false;
            for (std::size_t k = j_close + 1; k < j_end; ++k) {
                std::string_view b = stmts[k].body;
                if (b == "}") {
                    --d;
                    if (d < 0) { escapes = true; break; }
                } else if (b == "} else {") {
                    --d;
                    if (d < 0) { escapes = true; break; }
                    ++d;
                } else if (!b.empty() && b.back() == '{') {
                    ++d;
                }
            }
            if (escapes || d != 0) break;

            if (!secLabels.count(end_off)) break;
            if (crossSecRefs.count(end_off)) break;
            auto it = refCount.find(end_off);
            if (it == refCount.end() || it->second != 1) break;

            // Collapse.  Open unchanged, body_then minus trailing goto, then
            // `} else {` absorbs the goto's bytes, body_else unchanged, new
            // close `}` at end_off (consumed=0).
            out.push_back(stmts[i]);
            for (std::size_t k = i + 1; k < j_close - 1; ++k) out.push_back(stmts[k]);
            out.push_back({stmts[j_close - 1].offset, stmts[j_close - 1].consumed, "} else {"});
            for (std::size_t k = j_close + 1; k < j_end; ++k) out.push_back(stmts[k]);
            out.push_back({static_cast<std::size_t>(end_off), 0, "}"});

            secLabels.erase(end_off);
            changed = true;
            i = j_end;
            matched = true;
        } while (false);

        if (!matched) {
            out.push_back(stmts[i]);
            ++i;
        }
    }
    stmts = std::move(out);
    return changed;
}

// Collapse `if (<cond>) goto Lx; <body>; Lx:` (the canonical engine shape:
// skip-when-cond) back to the source-level block form `if (<negated>) { <body> }`.
//
// Conservative -- bail unless EVERY guarantee holds, since the negator has
// to produce a string the assembler re-encodes to identical bytes:
//   - Body matches exactly `if (<cond>) goto L_<4hex>` (no else, no tail).
//   - L_<4hex> is in this section's labels and has NO cross-section refs.
//   - In-section refs to L_<4hex> total exactly one (this goto).  No other
//     code reaches the close label; dropping it can't strand any branch.
//   - A stmt exists at offset L_<4hex> (the close anchor).
//   - The negator accepts every atom in <cond> (rejects `hasTech` / `(cond&...)`).
//
// Multi-predecessor merge labels (refCount > 1) are intentionally LEFT
// alone here -- relaxing the single-arm wrap to fire greedily on multi-pred
// labels was tried and regressed total label count: `beautifyBlocksOnce`
// later in the pipeline produces strictly tighter `{ break; ... }` wraps
// for those cases, and a greedy single-arm pre-wrap preempts that.
//
// On success: replace stmts[i] with `if (<negate(cond)>) {` keeping the
// original `consumed` (these bytes are still the same `if` opcode), keep
// the body stmts unchanged, splice a synthetic `}` (consumed=0) at the
// close anchor, and erase the close label from secLabels.
bool beautifyIfBlocksOnce(std::vector<DecodedInstr>& stmts,
                          std::unordered_set<int>& secLabels,
                          const std::unordered_set<int>& crossSecRefs) {
    std::unordered_map<int, int> sameSecRefCount;
    for (const auto& s : stmts) {
        std::vector<int> refs;
        collectSameSecLabelRefs(s.body, refs);
        for (int off : refs) ++sameSecRefCount[off];
    }

    std::vector<DecodedInstr> out;
    out.reserve(stmts.size() + 4);
    bool changed = false;
    std::size_t i = 0;
    while (i < stmts.size()) {
        std::string_view body = stmts[i].body;
        bool matched = false;
        do {
            if (body.size() < 4) break;
            if (body[0] != 'i' || body[1] != 'f' || body[2] != ' ' || body[3] != '(') break;
            // Reject if-then-else form: it has `; else goto` in the body.
            if (body.find("; else goto") != std::string_view::npos) break;

            std::size_t suffix = body.rfind(") goto L_");
            if (suffix == std::string_view::npos) break;
            // Body must END with `) goto L_<4hex>` -- exactly 9+4 chars after suffix.
            if (suffix + 9 + 4 != body.size()) break;

            int targetOff = 0;
            bool okHex = true;
            for (int k = 0; k < 4; ++k) {
                char c = body[suffix + 9 + k];
                if (c >= '0' && c <= '9') targetOff = targetOff * 16 + (c - '0');
                else if (c >= 'a' && c <= 'f') targetOff = targetOff * 16 + (c - 'a' + 10);
                else { okHex = false; break; }
            }
            if (!okHex) break;

            if (!secLabels.count(targetOff)) break;
            if (crossSecRefs.count(targetOff)) break;
            auto rcIt = sameSecRefCount.find(targetOff);
            if (rcIt == sameSecRefCount.end() || rcIt->second != 1) break;

            std::size_t j = SIZE_MAX;
            for (std::size_t k = i + 1; k < stmts.size(); ++k) {
                if (static_cast<int>(stmts[k].offset) == targetOff) { j = k; break; }
            }
            if (j == SIZE_MAX) break;

            std::string_view cond = body.substr(4, suffix - 4);
            std::string negCond;
            try {
                negCond = predneg::negatePredicate(cond);
            } catch (...) {
                break;
            }

            std::string open = "if (";
            open += negCond;
            open += ") {";
            out.push_back({stmts[i].offset, stmts[i].consumed, std::move(open)});
            for (std::size_t k = i + 1; k < j; ++k) {
                out.push_back(stmts[k]);
            }
            out.push_back({static_cast<std::size_t>(targetOff), 0, "}"});
            secLabels.erase(targetOff);
            changed = true;
            i = j;
            matched = true;
        } while (false);

        if (!matched) {
            out.push_back(stmts[i]);
            ++i;
        }
    }
    stmts = std::move(out);
    return changed;
}

// Fold runs of `if (pstat[X] == K_i) { body }` bodied-ifs (same X, distinct
// K_i, >=2 arms) into a single `switch pstat[X] { K => { body } ... }`.
// Optionally absorbs a trailing inverse-encoded arm
// `if (pstat[X] != K_else) goto L; body; L:` as `else K_else => { body }`
// when the body span between the if and L contains no labels.
//
// Byte-faithful: the assembler re-emits `K => { body }` as the same single
// 0x19 (`if (pstat[X] != K) goto __end; body; __end:`) it would emit for a
// hand-written eq-chain.  The `else K =>` form lowers identically -- its
// bypass label naturally coincides with whatever label sits at the
// post-switch byte position in the original.
bool beautifySwitchOnce(std::vector<DecodedInstr>& stmts,
                        const std::unordered_set<int>& secLabels) {
    auto braceDelta = [](std::string_view b) {
        int d = 0;
        if (!b.empty() && b.front() == '}') --d;
        if (!b.empty() && b.back()  == '{') ++d;
        return d;
    };

    // Find the closer (depth=0) for an opener at `i`.  Assumes stmts[i]'s
    // body ends in `{` (i.e. it really is an opener).  Returns SIZE_MAX if no
    // matching closer exists in the current scope.
    auto matchCloser = [&](std::size_t i) -> std::size_t {
        int depth = 1;
        for (std::size_t k = i + 1; k < stmts.size(); ++k) {
            int d = braceDelta(stmts[k].body);
            // Apply close part first (so `} else {` at depth=1 stays in scope).
            std::string_view b = stmts[k].body;
            if (!b.empty() && b.front() == '}') {
                --depth;
                if (depth == 0) return k;
            }
            if (!b.empty() && b.back() == '{') ++depth;
            (void)d;
        }
        return SIZE_MAX;
    };

    // Parse an `if (pstat[X] == K) {` opener.  Returns {xExpr, K} on match.
    auto tryParseEqOpener = [](std::string_view body) -> std::optional<std::pair<std::string, long long>> {
        if (!startsWith(body, "if (pstat[")) return std::nullopt;
        if (body.empty() || body.back() != '{') return std::nullopt;
        std::size_t rb = body.find(']', 10);
        if (rb == std::string_view::npos) return std::nullopt;
        std::string_view xExpr = body.substr(10, rb - 10);
        if (rb + 5 > body.size()) return std::nullopt;
        if (body.compare(rb + 1, 4, " == ") != 0) return std::nullopt;
        std::size_t kStart = rb + 5;
        std::size_t kEnd = body.find(')', kStart);
        if (kEnd == std::string_view::npos) return std::nullopt;
        // After `)` must be ` {` (the opener suffix).
        if (kEnd + 2 >= body.size()) return std::nullopt;
        if (body[kEnd + 1] != ' ' || body[kEnd + 2] != '{') return std::nullopt;
        // No further chars after ` {`.
        if (kEnd + 3 != body.size()) return std::nullopt;
        // Parse K as a signed decimal.
        std::string_view kStr = body.substr(kStart, kEnd - kStart);
        if (kStr.empty()) return std::nullopt;
        long long sign = 1;
        std::size_t p = 0;
        if (kStr[0] == '-') { sign = -1; p = 1; }
        if (p == kStr.size()) return std::nullopt;
        long long K = 0;
        for (; p < kStr.size(); ++p) {
            char c = kStr[p];
            if (c < '0' || c > '9') return std::nullopt;
            K = K * 10 + (c - '0');
        }
        return std::make_pair(std::string{xExpr}, sign * K);
    };

    // Parse a non-bodied trailing `if (pstat[X] != K) goto L_xxxx`.
    // Returns {xExpr, K, targetOff}.
    auto tryParseNeqGoto = [](std::string_view body) -> std::optional<std::tuple<std::string, long long, int>> {
        if (!startsWith(body, "if (pstat[")) return std::nullopt;
        std::size_t suffix = body.rfind(") goto L_");
        if (suffix == std::string_view::npos) return std::nullopt;
        if (suffix + 9 + 4 != body.size()) return std::nullopt;
        int targetOff = 0;
        for (int q = 0; q < 4; ++q) {
            char c = body[suffix + 9 + q];
            if      (c >= '0' && c <= '9') targetOff = targetOff * 16 + (c - '0');
            else if (c >= 'a' && c <= 'f') targetOff = targetOff * 16 + (c - 'a' + 10);
            else return std::nullopt;
        }
        std::size_t rb = body.find(']', 10);
        if (rb == std::string_view::npos || rb >= suffix) return std::nullopt;
        std::string_view xExpr = body.substr(10, rb - 10);
        if (rb + 5 > body.size()) return std::nullopt;
        if (body.compare(rb + 1, 4, " != ") != 0) return std::nullopt;
        std::size_t kStart = rb + 5;
        if (kStart >= suffix) return std::nullopt;
        std::string_view kStr = body.substr(kStart, suffix - kStart);
        if (kStr.empty()) return std::nullopt;
        long long sign = 1;
        std::size_t p = 0;
        if (kStr[0] == '-') { sign = -1; p = 1; }
        if (p == kStr.size()) return std::nullopt;
        long long K = 0;
        for (; p < kStr.size(); ++p) {
            char c = kStr[p];
            if (c < '0' || c > '9') return std::nullopt;
            K = K * 10 + (c - '0');
        }
        return std::make_tuple(std::string{xExpr}, sign * K, targetOff);
    };

    struct Arm { long long K; std::size_t openerIdx; std::size_t closerIdx; };

    std::vector<DecodedInstr> out;
    out.reserve(stmts.size());
    bool changed = false;
    std::size_t i = 0;
    while (i < stmts.size()) {
        auto first = tryParseEqOpener(stmts[i].body);
        if (!first) { out.push_back(stmts[i]); ++i; continue; }
        std::size_t firstCloser = matchCloser(i);
        if (firstCloser == SIZE_MAX) { out.push_back(stmts[i]); ++i; continue; }

        std::string xExpr = first->first;
        std::vector<Arm> arms;
        arms.push_back({first->second, i, firstCloser});

        // Greedily collect contiguous `if (pstat[X] == K') { body }` arms.
        std::size_t cursor = firstCloser + 1;
        while (cursor < stmts.size()) {
            auto p = tryParseEqOpener(stmts[cursor].body);
            if (!p || p->first != xExpr) break;
            bool dupKey = false;
            for (const auto& a : arms) if (a.K == p->second) { dupKey = true; break; }
            if (dupKey) break;
            std::size_t cIdx = matchCloser(cursor);
            if (cIdx == SIZE_MAX) break;
            arms.push_back({p->second, cursor, cIdx});
            cursor = cIdx + 1;
        }

        if (arms.size() < 2) { out.push_back(stmts[i]); ++i; continue; }

        // Optional trailing inverse arm: `if (pstat[X] != K_else) goto L; body...; L:`.
        bool hasElse = false;
        long long elseK = 0;
        std::size_t elseIfIdx = SIZE_MAX;
        std::size_t elseBodyEnd = SIZE_MAX;   // exclusive: last body stmt index + 1
        if (cursor < stmts.size()) {
            auto neq = tryParseNeqGoto(stmts[cursor].body);
            if (neq && std::get<0>(*neq) == xExpr) {
                bool dupKey = false;
                for (const auto& a : arms) if (a.K == std::get<1>(*neq)) { dupKey = true; break; }
                if (!dupKey) {
                    int targetOff = std::get<2>(*neq);
                    // Walk forward until we find a stmt whose offset equals targetOff.
                    // Bail if any body item has a non-zero brace delta (we don't
                    // want to absorb a block that opens but doesn't close inside
                    // the else body), or if any intermediate offset is itself a
                    // label (would mean a goto from outside lands in the else
                    // body -- unsafe to fold).
                    int depth = 0;
                    std::size_t k;
                    bool labelInBody = false;
                    for (k = cursor + 1; k < stmts.size(); ++k) {
                        if (static_cast<int>(stmts[k].offset) == targetOff && depth == 0) break;
                        if (depth == 0 && secLabels.count(static_cast<int>(stmts[k].offset))) {
                            labelInBody = true;
                            break;
                        }
                        depth += braceDelta(stmts[k].body);
                        if (depth < 0) { labelInBody = true; break; }
                    }
                    if (!labelInBody && k < stmts.size() && depth == 0) {
                        hasElse = true;
                        elseK = std::get<1>(*neq);
                        elseIfIdx = cursor;
                        elseBodyEnd = k;
                    }
                }
            }
        }

        // Emit the switch DecodedInstrs.
        std::string sw = "switch pstat[";
        sw += xExpr;
        sw += "] {";
        out.push_back({stmts[i].offset, 0, std::move(sw)});

        for (const auto& a : arms) {
            std::string armOpen = toDec(a.K);
            armOpen += " => {";
            out.push_back({stmts[a.openerIdx].offset, 0, std::move(armOpen)});
            for (std::size_t k = a.openerIdx + 1; k < a.closerIdx; ++k) {
                out.push_back(stmts[k]);
            }
            out.push_back({stmts[a.closerIdx].offset, 0, "}"});
        }

        if (hasElse) {
            std::string armOpen = "else ";
            armOpen += toDec(elseK);
            armOpen += " => {";
            out.push_back({stmts[elseIfIdx].offset, 0, std::move(armOpen)});
            for (std::size_t k = elseIfIdx + 1; k < elseBodyEnd; ++k) {
                out.push_back(stmts[k]);
            }
            // Closer's offset must NOT equal stmts[elseBodyEnd].offset --
            // that offset is L12 (still a label, since it has other refs we
            // can't absorb).  Using the inverse-if's own offset is safe:
            // it's an instruction-start offset, not a label target.
            out.push_back({stmts[elseIfIdx].offset, 0, "}"});
        }

        out.push_back({hasElse ? stmts[elseIfIdx].offset
                               : stmts[arms.back().closerIdx].offset,
                       0, "}"});

        changed = true;
        i = hasElse ? elseBodyEnd : (arms.back().closerIdx + 1);
    }

    stmts = std::move(out);
    return changed;
}

// Catch the do-while shape that beautifyLoopsOnce misses: a single-entry
// label L whose only back-edge lives INSIDE an if-block (rather than at the
// scope's top level).  Pattern:
//
//   L:
//     body          ← runs every iteration
//     if (cond) {
//       body2       ← runs only when cond was true
//       goto L
//     }
//
// Rewrite to the natural form:
//
//   loop {
//     body
//     if (negate(cond)) break;
//     body2
//   }
//
// Byte-identical: `if (X) break;` inside `loop {}` substitutes break to
// goto __loop_end_N and encodes as ONE 0x19 opcode (two-target conditional
// jump with elseLabel=sentinel).  Original encoded the same way -- one 0x19
// for the if-skip, then body2, then the back-edge goto -- and our rewrite
// keeps the same opcode sequence: one 0x19 + body2 + implicit back-edge from
// the loop close.
bool beautifyDoWhileOnce(std::vector<DecodedInstr>& stmts,
                         std::unordered_set<int>& secLabels,
                         const std::unordered_set<int>& crossSecRefs) {
    std::unordered_map<int, std::vector<std::size_t>> sameSecRefs;
    for (std::size_t k = 0; k < stmts.size(); ++k) {
        std::vector<int> refs;
        collectSameSecLabelRefs(stmts[k].body, refs);
        for (int off : refs) sameSecRefs[off].push_back(k);
    }

    std::vector<DecodedInstr> out;
    out.reserve(stmts.size() + 4);
    bool changed = false;
    std::size_t i = 0;
    while (i < stmts.size()) {
        bool matched = false;
        do {
            int oxOff = static_cast<int>(stmts[i].offset);
            if (oxOff == 0) break;
            if (!secLabels.count(oxOff)) break;

            auto refsIt = sameSecRefs.find(oxOff);
            if (refsIt == sameSecRefs.end()) break;

            // Find the unique back-edge: exactly one ref at index > i.
            // Forward refs (k < i) and cross-section refs are fine -- we
            // preserve the label for them; only the back-edge needs to
            // disappear into the loop close.
            std::size_t B = SIZE_MAX;
            for (auto k : refsIt->second) {
                if (k <= i) continue;
                if (B != SIZE_MAX) { B = SIZE_MAX - 1; break; }
                B = k;
            }
            if (B == SIZE_MAX || B == SIZE_MAX - 1) break;
            if (B + 1 >= stmts.size()) break;
            if (!isUnconditionalGotoTo(stmts[B].body, oxOff)) break;

            // Walk i..B-1 tracking brace depth; find the if-block opener
            // at depth 0 that immediately encloses B.
            int depth = 0;
            std::size_t O = SIZE_MAX;
            for (std::size_t k = i; k < B; ++k) {
                std::string_view body = stmts[k].body;
                if (body == "}") {
                    --depth;
                } else if (body == "} else {") {
                    // net zero
                } else if (!body.empty() && body.back() == '{') {
                    if (depth == 0 && startsWith(body, "if (")) {
                        O = k;
                    }
                    ++depth;
                }
            }
            if (depth != 1) break;        // B must be inside exactly one open brace
            if (O == SIZE_MAX) break;     // and that brace must be an if-opener

            // Back-edge must be the LAST stmt before the if-close.
            if (stmts[B + 1].body != "}") break;

            // Extract cond from "if (<cond>) {".
            std::string_view opener = stmts[O].body;
            if (opener.size() < 7) break;
            if (opener.compare(opener.size() - 2, 2, " {") != 0) break;
            if (opener[opener.size() - 3] != ')') break;
            std::string_view cond = opener.substr(4, opener.size() - 3 - 4);

            std::string negCond;
            try {
                negCond = predneg::negatePredicate(cond);
            } catch (...) {
                break;
            }

            out.push_back({stmts[i].offset, 0, "loop {"});
            for (std::size_t k = i; k < O; ++k) out.push_back(stmts[k]);
            std::string brkLine = "if (";
            brkLine += negCond;
            brkLine += ") break";
            out.push_back({stmts[O].offset, stmts[O].consumed, std::move(brkLine)});
            for (std::size_t k = O + 1; k < B; ++k) out.push_back(stmts[k]);
            out.push_back({stmts[B].offset, stmts[B].consumed, "}"});
            // Skip stmts[B+1] (the if-close, consumed=0) -- the loop `}` replaces it.

            // Erase the label only if the back-edge B was its sole ref AND it
            // has no cross-section refs.  Otherwise keep it: forward entries
            // need it to resolve, and they'll render as `L<n>:` immediately
            // before `loop {`.
            bool otherRefs = crossSecRefs.count(oxOff) > 0;
            if (!otherRefs) {
                for (auto k : refsIt->second) {
                    if (k != B) { otherRefs = true; break; }
                }
            }
            if (!otherRefs) secLabels.erase(oxOff);
            changed = true;
            i = B + 2;
            matched = true;
        } while (false);

        if (!matched) {
            out.push_back(stmts[i]);
            ++i;
        }
    }
    stmts = std::move(out);
    return changed;
}

// For every goto-form stmt body that targets a label at the INNERMOST
// enclosing break-scope's close offset, rewrite the `goto L_<hex>` to
// `break`.  The bytes are identical because `break;` lowers to
// `goto __scope_end__;` (same byte target).  This captures the "break
// out of enclosing loop/block" pattern that the multi-pred block wrap
// recognizer misses (it tries to introduce a NEW wrap instead of
// reusing the existing one).
//
// Each opener stmt (`loop {` or bare `{`) walks forward to find its
// matching closer; the closer's offset is the scope's "break target."
// Non-break-scope braces (`if (...) {`, `for ... {`, `choice {`, etc.)
// are transparent.
//
// After substitution, any label that loses all same-section refs and
// has no cross-section refs is dropped from `secLabels`.
bool beautifyImpliedBreaksOnce(std::vector<DecodedInstr>& stmts,
                               std::unordered_set<int>& secLabels,
                               const std::unordered_set<int>& crossSecRefs) {
    // Precompute: for each opener stmt at index k, the offset of its
    // matching closer (= stmts[matchingIdx].offset).
    // Only `loop {` and bare `{` count as break-scope openers.
    std::vector<int> closeOff(stmts.size(), -1);
    {
        std::vector<std::pair<std::size_t, bool>> stack; // (idx, isBreakScope)
        for (std::size_t k = 0; k < stmts.size(); ++k) {
            std::string_view bod = stmts[k].body;
            bool isCloser = !bod.empty() && bod.front() == '}';
            bool isOpener = !bod.empty() && bod.back() == '{';
            if (isCloser) {
                if (!stack.empty()) {
                    auto [openIdx, isBreak] = stack.back();
                    stack.pop_back();
                    if (isBreak) {
                        closeOff[openIdx] = static_cast<int>(stmts[k].offset);
                    }
                }
            }
            if (isOpener) {
                bool isBreak = (bod == "loop {" || bod == "{");
                stack.emplace_back(k, isBreak);
            }
        }
    }

    // Substitute: walk stmts, track stack of enclosing break-scope close offsets.
    // For each stmt with a goto-form body, if the goto target equals the top of
    // the stack, rewrite to `break`.
    bool changed = false;
    std::vector<int> breakStack;
    auto sameSecGotoTargetOf = [](std::string_view body) -> int {
        // Match body exactly "goto L_<4hex>" anywhere -- but easiest: just match
        // the exact pattern at body content.  Handles both `goto L_<hex>` and
        // `if (X) goto L_<hex>`.
        std::size_t pos = body.rfind("goto L_");
        if (pos == std::string_view::npos) return -1;
        if (pos + 11 > body.size()) return -1;
        // Boundary: char after the 4-hex must NOT be ident-cont.
        if (pos + 11 < body.size() && isAsciiIdentCont(body[pos + 11])) return -1;
        // Boundary: `L_` mustn't be preceded by `.` or ident-cont.
        if (pos > 0 && (body[pos - 1 + 5] == '.')) return -1; // 'goto L_' — pos+5='L', body[pos+4] is space
        // Parse 4 hex.
        int off = 0;
        for (int q = 0; q < 4; ++q) {
            char c = body[pos + 7 + q];
            if (c >= '0' && c <= '9') off = off * 16 + (c - '0');
            else if (c >= 'a' && c <= 'f') off = off * 16 + (c - 'a' + 10);
            else return -1;
        }
        return off;
    };
    for (std::size_t k = 0; k < stmts.size(); ++k) {
        std::string_view bod = stmts[k].body;
        bool isCloser = !bod.empty() && bod.front() == '}';
        bool isOpener = !bod.empty() && bod.back() == '{';
        if (isCloser) {
            if (!breakStack.empty()) breakStack.pop_back();
        }
        // Check goto-form
        if (!isCloser && !isOpener && !breakStack.empty()) {
            int target = sameSecGotoTargetOf(stmts[k].body);
            if (target != -1 && target == breakStack.back()) {
                // Substitute `goto L_<hex>` -> `break` in this body.
                char hexBuf[5];
                std::snprintf(hexBuf, sizeof(hexBuf), "%04x", target);
                std::string needle = "goto L_";
                needle += hexBuf;
                std::string newBody;
                newBody.reserve(stmts[k].body.size());
                std::size_t i = 0;
                const auto& s = stmts[k].body;
                while (i < s.size()) {
                    if (i + needle.size() <= s.size()
                        && s.compare(i, needle.size(), needle) == 0
                        && (i + needle.size() == s.size()
                            || !isAsciiIdentCont(s[i + needle.size()]))) {
                        newBody += "break";
                        i += needle.size();
                    } else {
                        newBody += s[i++];
                    }
                }
                if (newBody != stmts[k].body) {
                    stmts[k].body = std::move(newBody);
                    changed = true;
                }
            }
        }
        if (isOpener) {
            int c = closeOff[k];
            if (c != -1) breakStack.push_back(c);
        }
    }

    // Recount refs per label.  Drop labels that now have zero same-section refs
    // AND no cross-section refs.
    if (changed) {
        std::unordered_map<int, int> refCount;
        for (const auto& s : stmts) {
            std::vector<int> refs;
            collectSameSecLabelRefs(s.body, refs);
            for (int off : refs) ++refCount[off];
        }
        std::vector<int> toErase;
        for (int lbl : secLabels) {
            if (crossSecRefs.count(lbl)) continue;
            if (refCount[lbl] == 0) toErase.push_back(lbl);
        }
        for (int lbl : toErase) secLabels.erase(lbl);
    }
    return changed;
}

// Collapse the corpus's 4-instruction "if-else-goto" pattern back into a
// single source statement.  The post-`beautifyIfBlocksOnce` shape is:
//
//   if (X) {
//     goto A;
//     goto B;
//   }
//   goto B;
//
// (where the second body goto's target matches the trailing goto's target.)
// We rewrite this five-stmt span into a single stmt:
//
//   if (X) goto A; else goto B;
//
// The assembler's pull-loop expander lowers `; else goto` back to the same
// 4-instruction byte sequence we recognized here.  No new keyword; reuses
// the existing `; else goto` grammar that was previously unreachable in
// the corpus.
bool beautifyIfElseGotoOnce(std::vector<DecodedInstr>& stmts) {
    if (stmts.size() < 5) return false;
    bool changed = false;
    std::vector<DecodedInstr> out;
    out.reserve(stmts.size());
    std::size_t i = 0;
    while (i < stmts.size()) {
        bool matched = false;
        do {
            if (i + 4 >= stmts.size()) break;
            std::string_view ifBody = stmts[i].body;
            if (ifBody.size() < 6 || !startsWith(ifBody, "if (") || ifBody.back() != '{') break;
            // body[0]: goto A
            std::string_view b0 = stmts[i + 1].body;
            if (b0.size() != 11 || !startsWith(b0, "goto L_")) break;
            // body[1]: goto B
            std::string_view b1 = stmts[i + 2].body;
            if (b1.size() != 11 || !startsWith(b1, "goto L_")) break;
            // close `}`
            if (stmts[i + 3].body != "}") break;
            // following stmt: goto B (matching target)
            std::string_view tail = stmts[i + 4].body;
            if (tail.size() != 11 || !startsWith(tail, "goto L_")) break;
            if (b1 != tail) break;   // inner-second target must match outer target

            // Build the merged source: `if (X) goto A; else goto B;`.
            // Strip leading "if (" (4 chars) and trailing ") {" (3 chars).
            std::string cond{ifBody.substr(4, ifBody.size() - 4 - 3)};
            std::string newBody = "if (";
            newBody += cond;
            newBody += ") ";
            newBody += std::string{b0};   // "goto L_<hex>"
            newBody += "; else ";
            newBody += std::string{tail}; // "goto L_<hex>"

            std::size_t totalConsumed = stmts[i].consumed
                                      + stmts[i + 1].consumed
                                      + stmts[i + 2].consumed
                                      + stmts[i + 3].consumed
                                      + stmts[i + 4].consumed;
            out.push_back({stmts[i].offset, totalConsumed, std::move(newBody)});
            i += 5;
            matched = true;
            changed = true;
        } while (false);
        if (!matched) {
            out.push_back(stmts[i]);
            ++i;
        }
    }
    stmts = std::move(out);
    return changed;
}

// Collapse multi-predecessor forward-merge labels into bare `{ ... break; ... }`
// blocks.  The recognizer:
//   - Finds label Lend with refCount >= 2 (multi-predecessor).
//   - Verifies all refs are at stmt indices < decl_idx (forward jumps only).
//   - Verifies no cross-section refs (we're going to drop the label).
//   - Picks scope_start_idx: the stmt index of the nearest label decl
//     PRIOR to the earliest ref, or 0 if none.  This bounds the block.
//   - Wraps [scope_start_idx, decl_idx) in synthetic `{`/`}` markers.
//   - Rewrites in-range body refs of the form `goto L_<hex>` (for Lend) to
//     `break` -- the assembler's bare-`{}` machinery re-emits `goto Lend`
//     bytes via `__block_end_<id>` substitution.
//
// Returns true on the first match.  Caller loops until false to iterate.
bool beautifyBlocksOnce(std::vector<DecodedInstr>& stmts,
                        std::unordered_set<int>& secLabels,
                        const std::unordered_set<int>& crossSecRefs) {
    if (stmts.empty()) return false;

    // refIndices[label_off] -> list of stmts indices referencing that label.
    std::unordered_map<int, std::vector<std::size_t>> refIndices;
    for (std::size_t i = 0; i < stmts.size(); ++i) {
        std::vector<int> refs;
        collectSameSecLabelRefs(stmts[i].body, refs);
        for (int off : refs) refIndices[off].push_back(i);
    }

    // Try each labeled offset (smallest first -- inner blocks before outer).
    std::vector<int> labelOffs(secLabels.begin(), secLabels.end());
    std::sort(labelOffs.begin(), labelOffs.end());

    // Track which offsets have already been wrapped via a synthetic `}`
    // marker.  Skip them on subsequent passes -- a kept-due-to-unsafe-refs
    // label would otherwise re-trigger forever.
    std::unordered_set<int> alreadyWrapped;
    for (const auto& s : stmts) {
        if (s.body == "}") alreadyWrapped.insert(static_cast<int>(s.offset));
    }

    for (int lend_off : labelOffs) {
        if (crossSecRefs.count(lend_off)) continue;
        if (alreadyWrapped.count(lend_off)) continue;
        auto rit = refIndices.find(lend_off);
        if (rit == refIndices.end() || rit->second.size() < 2) continue;
        const auto& refs = rit->second;

        // decl_idx: stmts index where stmt.offset == lend_off.
        std::size_t decl_idx = SIZE_MAX;
        for (std::size_t k = 0; k < stmts.size(); ++k) {
            if (static_cast<int>(stmts[k].offset) == lend_off) {
                decl_idx = k;
                break;
            }
        }
        if (decl_idx == SIZE_MAX) continue;

        // Forward-only: every ref idx < decl_idx.
        bool all_forward = true;
        for (std::size_t r : refs) if (r >= decl_idx) { all_forward = false; break; }
        if (!all_forward) continue;

        std::size_t min_ref = *std::min_element(refs.begin(), refs.end());

        // scope_start_idx: walk backward from min_ref, respecting block
        // markers (synthetic `{` / `}` from prior wraps) as structural
        // boundaries.  Stop at:
        //   (a) a `{` open at our depth -- new block starts inside this open
        //   (b) a `}` close at our depth -- new block starts AFTER the close
        //   (c) a label-hosting stmt at our depth (the new block hosts here)
        //   (d) section start (scope_start_idx = 0)
        std::size_t scope_start_idx = 0;
        int depth = 0;
        for (std::size_t k = min_ref; k > 0; --k) {
            std::string_view bod = stmts[k - 1].body;
            bool isCloser = !bod.empty() && bod.front() == '}';
            bool isOpener = !bod.empty() && bod.back() == '{';
            if (isCloser && depth == 0) {
                // Prior block's close at our level -- new block starts here.
                scope_start_idx = k;
                break;
            }
            if (isCloser) ++depth;
            if (isOpener) {
                if (depth == 0) {
                    // min_ref sits INSIDE this opener's scope.  Start the new
                    // wrap AT the opener itself so the wrap encloses the inner
                    // scope cleanly (well-nested).
                    scope_start_idx = k - 1;
                    break;
                }
                --depth;
            }
            // Label boundary at depth 0 (don't fire for the merge label itself).
            int o = static_cast<int>(stmts[k - 1].offset);
            if (depth == 0 && !isCloser && !isOpener
                && secLabels.count(o) && o != lend_off) {
                scope_start_idx = k - 1;
                break;
            }
        }

        // Verify well-nested braces across the wrap range AND classify each
        // ref's break-scope depth.  Refs at depth 0 can safely become
        // `break;` (lowers to `goto __block_end__` = goto lend_off).  Refs
        // inside a nested loop or bare block (depth > 0) must STAY as raw
        // gotos -- substituting them would target the wrong scope.  If any
        // ref is "unsafe," we KEEP the merge label visible so the un-substituted
        // gotos still resolve; this loses some reduction but is still progress
        // (the safe refs are still converted).
        std::unordered_set<std::size_t> safeRefs;
        bool anyUnsafe = false;
        {
            std::vector<bool> stack;   // true = break-scope, false = transparent
            int fd = 0;
            bool wellNested = true;
            std::unordered_set<std::size_t> refSet(refs.begin(), refs.end());
            for (std::size_t k = scope_start_idx; k < decl_idx; ++k) {
                std::string_view bod = stmts[k].body;
                bool isCloser = !bod.empty() && bod.front() == '}';
                bool isOpener = !bod.empty() && bod.back() == '{';
                if (isCloser) {
                    --fd;
                    if (fd < 0) { wellNested = false; break; }
                    if (!stack.empty()) stack.pop_back();
                }
                int curBreakDepth = 0;
                for (bool b : stack) if (b) ++curBreakDepth;
                if (refSet.count(k)) {
                    if (curBreakDepth == 0) safeRefs.insert(k);
                    else                    anyUnsafe = true;
                }
                if (isOpener) {
                    bool isBreakScope = (bod == "loop {" || bod == "{");
                    stack.push_back(isBreakScope);
                    ++fd;
                }
            }
            if (!wellNested || fd != 0) continue;
            // Must have at least one safe ref to be worth wrapping.
            if (safeRefs.empty()) continue;
        }

        // Don't fire if the scope would be the entire section AND there's no
        // prior label -- that's the whole section body, not a real "block".
        // Still allow scope_start_idx == 0 when the section's first stmt is
        // labelled (rare but seen).
        // Heuristic: require scope_start_idx > 0 OR an explicit label at
        // stmt 0.  In practice we just allow both; the wrap is harmless.

        // Substitution: search for `L_<4hex of lend_off>` in body text and
        // replace `goto L_<hex>` with `break`.  Only fires on safe refs
        // (innermost-scope depth 0); unsafe refs stay as raw gotos and the
        // merge label is preserved so they resolve correctly.
        char hexBuf[5];
        std::snprintf(hexBuf, sizeof(hexBuf), "%04x", lend_off);
        std::string labelName = std::string{"L_"} + hexBuf;
        std::string gotoForm = "goto " + labelName;

        auto subInBody = [&](std::string body) -> std::string {
            std::string out;
            out.reserve(body.size());
            std::size_t i = 0;
            while (i < body.size()) {
                if (i + gotoForm.size() <= body.size()
                    && body.compare(i, gotoForm.size(), gotoForm) == 0) {
                    std::size_t after = i + gotoForm.size();
                    bool rightOk = (after == body.size()) || !isAsciiIdentCont(body[after]);
                    if (rightOk) {
                        out += "break";
                        i = after;
                        continue;
                    }
                }
                out += body[i++];
            }
            return out;
        };

        // Build new stmts vector.  Only safe refs get goto→break substitution;
        // unsafe refs (inside nested break-scopes) keep their goto, and we
        // preserve the merge label so they resolve correctly.
        std::vector<DecodedInstr> rebuilt;
        rebuilt.reserve(stmts.size() + 2);
        for (std::size_t k = 0; k < scope_start_idx; ++k) {
            rebuilt.push_back(stmts[k]);
        }
        // Synthetic `{` -- offset is the scope start's offset, consumed=0.
        rebuilt.push_back({stmts[scope_start_idx].offset, 0, "{"});
        for (std::size_t k = scope_start_idx; k < decl_idx; ++k) {
            DecodedInstr cp = stmts[k];
            if (safeRefs.count(k)) {
                cp.body = subInBody(std::move(cp.body));
            }
            rebuilt.push_back(std::move(cp));
        }
        // Synthetic `}` -- at lend_off, consumed=0.
        rebuilt.push_back({static_cast<std::size_t>(lend_off), 0, "}"});
        for (std::size_t k = decl_idx; k < stmts.size(); ++k) {
            rebuilt.push_back(stmts[k]);
        }

        stmts = std::move(rebuilt);
        // Only drop the merge label when ALL refs were safely converted;
        // otherwise unsafe gotos still need to resolve it.  The label
        // renders BEFORE the synthetic `}` at the same offset (serializer's
        // label-then-stmt order), giving a tidy `Lk:\n}` close.
        if (!anyUnsafe) secLabels.erase(lend_off);
        return true;
    }
    return false;
}

// Pull the value of named arg `name:` from a parsed call's arg list, e.g.
// `move(entity: 5, to: (0, 0), sprint: 1)` -> getNamedArg(args, "entity") == "5".
// Returns an empty view if the arg isn't present.  String/bracket-aware so
// inner colons or commas don't confuse the split.
std::string_view getNamedArg(const std::vector<std::string_view>& args,
                             std::string_view name) {
    for (auto a : args) {
        std::size_t colon = std::string_view::npos;
        int depth = 0;
        bool inStr = false;
        for (std::size_t k = 0; k < a.size(); ++k) {
            char c = a[k];
            if (inStr) {
                if (c == '\\' && k + 1 < a.size()) { ++k; continue; }
                if (c == '"') inStr = false;
                continue;
            }
            if (c == '"') { inStr = true; continue; }
            if (c == '(' || c == '[' || c == '{') ++depth;
            else if (c == ')' || c == ']' || c == '}') --depth;
            else if (depth == 0 && c == ':') { colon = k; break; }
        }
        if (colon == std::string_view::npos) continue;
        auto n = a.substr(0, colon);
        while (!n.empty() && (n.front() == ' ' || n.front() == '\t')) n.remove_prefix(1);
        while (!n.empty() && (n.back()  == ' ' || n.back()  == '\t')) n.remove_suffix(1);
        if (n != name) continue;
        auto v = a.substr(colon + 1);
        while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) v.remove_prefix(1);
        while (!v.empty() && (v.back()  == ' ' || v.back()  == '\t')) v.remove_suffix(1);
        return v;
    }
    return {};
}

// Match `(X, Y)`.  Returns (X, Y) trimmed; both empty on mismatch.
std::pair<std::string_view, std::string_view> matchPairLiteral(std::string_view v) {
    if (v.size() < 2 || v.front() != '(' || v.back() != ')') return {};
    auto inner = v.substr(1, v.size() - 2);
    std::size_t comma = std::string_view::npos;
    int depth = 0;
    bool inStr = false;
    for (std::size_t k = 0; k < inner.size(); ++k) {
        char c = inner[k];
        if (inStr) { if (c == '"') inStr = false; continue; }
        if (c == '"') { inStr = true; continue; }
        if (c == '(' || c == '[') ++depth;
        else if (c == ')' || c == ']') --depth;
        else if (depth == 0 && c == ',') { comma = k; break; }
    }
    if (comma == std::string_view::npos) return {};
    auto x = inner.substr(0, comma);
    auto y = inner.substr(comma + 1);
    while (!x.empty() && (x.front() == ' ' || x.front() == '\t')) x.remove_prefix(1);
    while (!x.empty() && (x.back()  == ' ' || x.back()  == '\t')) x.remove_suffix(1);
    while (!y.empty() && (y.front() == ' ' || y.front() == '\t')) y.remove_prefix(1);
    while (!y.empty() && (y.back()  == ' ' || y.back()  == '\t')) y.remove_suffix(1);
    return {x, y};
}

// Collapse the canonical NPC-approach routine into `approach(...)`.
// The 11-stmt window:
//   [0]  loop {
//   [1]  move(entity: W, to: (X, Y), sprint: 1)
//   [2]  if (pstat[101] >= TRIES) break
//   [3]  addPStat(101, 1)
//   [4]  delay(WAIT)
//   [5]  look(entity: Entity.Player, at: W)
//   [6]  look(entity: Entity.Partner, at: W)
//   [7]  }
//   [8]  waitForEntity(W)
//   [9]  unloadEntity(W)
//   [10] setPStat(101, 0)
// Same W in 5 positions; sprint must be 1.  Variants (sprint:0, compound
// break conditions, ...) stay as raw loops.  No label may sit inside the
// collapsed window past the loop head -- its offset is shared with stmt[0]
// and stays attached on serialization.
void beautifyApproach(std::vector<DecodedInstr>& stmts,
                      const std::unordered_set<int>& labelOffsets) {
    constexpr std::size_t N = 11;
    std::vector<DecodedInstr> out;
    out.reserve(stmts.size());
    std::size_t i = 0;
    while (i < stmts.size()) {
        bool matched = false;
        do {
            if (i + N > stmts.size()) break;
            if (stmts[i].body     != "loop {")              break;
            if (stmts[i + 7].body != "}")                   break;
            // pstat[101] is sometimes bound symbolically in the project's
            // symbol table (e.g. PStat.LoopIterator), so addPStat/setPStat
            // can render either form.
            const auto& incBody = stmts[i + 3].body;
            if (incBody != "addPStat(101, 1)" &&
                incBody != "addPStat(PStat.LoopIterator, 1)") break;
            const auto& rstBody = stmts[i + 10].body;
            if (rstBody != "setPStat(101, 0)" &&
                rstBody != "setPStat(PStat.LoopIterator, 0)") break;

            // Bail if any internal stmt has its own label (would be lost
            // on collapse).  stmt[i+1] shares offset with the loop-open
            // marker and is already covered by stmt[i]'s rendering.
            bool labelInMiddle = false;
            for (std::size_t k = i + 2; k <= i + 10; ++k) {
                if (labelOffsets.count(static_cast<int>(stmts[k].offset))) {
                    labelInMiddle = true; break;
                }
            }
            if (labelInMiddle) break;

            auto cMove = parseSimpleCall(stmts[i + 1].body);
            if (!cMove || cMove->mnemonic != "move") break;
            auto whoMove = getNamedArg(cMove->args, "entity");
            auto toMove  = getNamedArg(cMove->args, "to");
            auto sprMove = getNamedArg(cMove->args, "sprint");
            if (whoMove.empty() || toMove.empty() || sprMove != "1") break;
            auto xy = matchPairLiteral(toMove);
            if (xy.first.empty() || xy.second.empty()) break;

            std::string_view ifb = stmts[i + 2].body;
            constexpr std::string_view ifPre = "if (pstat[101] >= ";
            constexpr std::string_view ifSuf = ") break";
            if (ifb.size() <= ifPre.size() + ifSuf.size()) break;
            if (ifb.compare(0, ifPre.size(), ifPre) != 0) break;
            if (ifb.compare(ifb.size() - ifSuf.size(), ifSuf.size(), ifSuf) != 0) break;
            auto triesVal = ifb.substr(ifPre.size(),
                                       ifb.size() - ifPre.size() - ifSuf.size());

            auto cDelay = parseSimpleCall(stmts[i + 4].body);
            if (!cDelay || cDelay->mnemonic != "delay" || cDelay->args.size() != 1) break;
            auto waitVal = cDelay->args[0];

            auto cLookP = parseSimpleCall(stmts[i + 5].body);
            if (!cLookP || cLookP->mnemonic != "look") break;
            if (getNamedArg(cLookP->args, "entity") != "Entity.Player") break;
            if (getNamedArg(cLookP->args, "at") != whoMove) break;

            auto cLookQ = parseSimpleCall(stmts[i + 6].body);
            if (!cLookQ || cLookQ->mnemonic != "look") break;
            if (getNamedArg(cLookQ->args, "entity") != "Entity.Partner") break;
            if (getNamedArg(cLookQ->args, "at") != whoMove) break;

            auto cWait = parseSimpleCall(stmts[i + 8].body);
            if (!cWait || cWait->mnemonic != "waitForEntity" || cWait->args.size() != 1) break;
            if (cWait->args[0] != whoMove) break;

            auto cUnload = parseSimpleCall(stmts[i + 9].body);
            if (!cUnload || cUnload->mnemonic != "unloadEntity" || cUnload->args.size() != 1) break;
            if (cUnload->args[0] != whoMove) break;

            // Build the collapsed `approach(...)` call.  String views are
            // into stmts[i..i+10]; copy now since we're about to replace
            // those stmts.
            std::string body = "approach(who: ";
            body.append(whoMove);
            body += ", x: ";  body.append(xy.first);
            body += ", y: ";  body.append(xy.second);
            body += ", tries: "; body.append(triesVal);
            body += ", wait: ";  body.append(waitVal);
            body += ')';

            std::size_t consumed = 0;
            for (std::size_t k = i; k < i + N; ++k) consumed += stmts[k].consumed;
            out.push_back({stmts[i].offset, consumed, std::move(body)});
            i += N;
            matched = true;
        } while (false);
        if (matched) continue;
        out.push_back(stmts[i]);
        ++i;
    }
    stmts = std::move(out);
}

// True when `body` contains a top-level named-arg form (`key: value`).
bool bodyHasNamedArg(std::string_view body) {
    auto cb = parseSimpleCall(body);
    if (!cb) return false;
    for (auto a : cb->args) {
        // Find ':' at depth 0 outside strings; if it's preceded by an
        // identifier, this is a named arg.
        int d = 0;
        bool inStr = false;
        for (std::size_t i = 0; i < a.size(); ++i) {
            char c = a[i];
            if (inStr) {
                if (c == '\\' && i + 1 < a.size()) { ++i; continue; }
                if (c == '"') inStr = false;
                continue;
            }
            if (c == '"') { inStr = true; continue; }
            if (c == '(' || c == '[') ++d;
            else if (c == ')' || c == ']') --d;
            else if (d == 0 && c == ':' && i > 0) {
                char prev = a[i - 1];
                if ((prev >= 'a' && prev <= 'z') || (prev >= 'A' && prev <= 'Z')
                 || (prev >= '0' && prev <= '9') || prev == '_') {
                    return true;
                }
            }
        }
    }
    return false;
}

// Per-section label rename map: in-section offset -> new name (e.g. "L1").
using LabelRename = std::unordered_map<int, std::string>;

// Walk `body` and rewrite every `L_<4hex>` token using the rename maps.
// Bare `L_<hex>` resolves against the current section.  When the token is
// preceded by `<ident>.`, the ident is looked up in `sectionByName` to pick
// the target section's rename map.
std::string renameLabelsInBody(std::string_view body,
                               std::size_t curSecIdx,
                               const std::vector<LabelRename>& rename,
                               const std::unordered_map<std::string, std::size_t>& sectionByName) {
    std::string out;
    out.reserve(body.size());
    std::size_t i = 0;
    while (i < body.size()) {
        if (i + 6 <= body.size() && body[i] == 'L' && body[i + 1] == '_') {
            bool hexOk = true;
            for (int k = 0; k < 4; ++k) {
                char c = body[i + 2 + k];
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) { hexOk = false; break; }
            }
            bool rightBound = (i + 6 == body.size()) || !isAsciiIdentCont(body[i + 6]);
            if (hexOk && rightBound) {
                int off = 0;
                for (int k = 0; k < 4; ++k) {
                    char c = body[i + 2 + k];
                    int d = (c >= '0' && c <= '9') ? (c - '0') : (c - 'a' + 10);
                    off = off * 16 + d;
                }
                std::size_t targetIdx = curSecIdx;
                if (i >= 1 && body[i - 1] == '.') {
                    std::size_t end = i - 1;
                    std::size_t start = end;
                    while (start > 0 && isAsciiIdentCont(body[start - 1])) --start;
                    auto it = sectionByName.find(std::string{body.substr(start, end - start)});
                    if (it != sectionByName.end()) targetIdx = it->second;
                }
                if (targetIdx < rename.size()) {
                    auto rit = rename[targetIdx].find(off);
                    if (rit != rename[targetIdx].end()) {
                        out += rit->second;
                        i += 6;
                        continue;
                    }
                }
            }
        }
        out += body[i++];
    }
    return out;
}

// Serialize a section: header line, label-interleaved body, closing brace.
// `labelOffsets` is the set of in-section offsets that need label decls.
// `rename` and `sectionByName` drive label renaming inside body strings.
void serializeSection(std::vector<std::string>& out,
                      const Script& script,
                      const Section& sec,
                      std::size_t secIdx,
                      const std::vector<DecodedInstr>& stmts,
                      const std::unordered_set<int>& labelOffsets,
                      const std::vector<LabelRename>& rename,
                      const std::unordered_map<std::string, std::size_t>& sectionByName) {
    out.push_back(sectionHeaderLine(script, sec));
    if (sec.bytes.empty()) {
        out.emplace_back("    // (empty)");
        out.emplace_back("}");
        return;
    }
    bool firstStmt = true;
    int  lastLabelOff = -1;
    int  blockDepth = 0;   // # of open synthetic block markers (`loop {`, `if (..) {`)
    auto extraIndent = [&]() -> std::string {
        std::string s;
        for (int q = 0; q < blockDepth; ++q) s += INDENT;
        return s;
    };
    auto isBlockOpener = [](std::string_view body) {
        // Synthetic block openers emitted as standalone DecodedInstrs end in `{`.
        // (For-range / choice / etc. emit single multi-line strings ending in `}`,
        // so they don't trigger here.)
        return !body.empty() && body.back() == '{';
    };
    auto isBlockCloser = [](std::string_view body) {
        // Any body that starts with `}` decrements depth: plain `}`, the
        // close-and-reopen `} else {`, or the chain merge `} else if (X) {`.
        // The opener check (body ends with `{`) handles the reopen half.
        return !body.empty() && body.front() == '}';
    };
    for (const auto& instr : stmts) {
        const int curOff = static_cast<int>(instr.offset);
        // Dedup labels: synthetic block-opener markers share their offset with
        // the first body instruction, but the label belongs to one place.
        const bool isLabelHere = labelOffsets.count(curOff) && curOff != lastLabelOff;

        // Decrement depth BEFORE rendering a synthetic close-shaped marker
        // so the `}` (or `} else {`) aligns with its matching opener.
        if (isBlockCloser(instr.body) && blockDepth > 0) --blockDepth;

        if (isLabelHere) {
            // Blank line before label to visually separate flow chunks
            // (skip if this is the very first statement in the section).
            if (!firstStmt) out.emplace_back("");
            std::string lab;
            auto rit = rename[secIdx].find(curOff);
            lab = (rit != rename[secIdx].end()) ? rit->second
                                                : labelInSection(curOff);
            lab += ':';
            out.push_back(std::move(lab));   // labels stay at column 0
            lastLabelOff = curOff;
        }
        std::string text = extraIndent();
        text += INDENT;
        text += renameLabelsInBody(instr.body, secIdx, rename, sectionByName);
        // Block-bodied statements already carry their own brace -- appending
        // `;` produces noise like `};` or `loop {;`.  Plain calls always need
        // the terminator.
        if (text.empty() || (text.back() != '}' && text.back() != '{')) text += ';';
        // Multi-line bodies: split on `\n`.  First line already carries the
        // outer indent; subsequent lines have their own *relative* indent
        // baked into the body string, so we shift them by the loop-depth
        // prefix to keep them aligned with the first line.
        std::size_t start = 0;
        bool firstLine = true;
        const std::string shift = extraIndent();
        for (std::size_t k = 0; k <= text.size(); ++k) {
            if (k == text.size() || text[k] == '\n') {
                std::string line = text.substr(start, k - start);
                if (!firstLine && !shift.empty()) line = shift + line;
                out.push_back(std::move(line));
                start = k + 1;
                firstLine = false;
            }
        }

        // Increment AFTER rendering the synthetic block-open marker so the
        // body sits one level deeper than the opener itself.
        if (isBlockOpener(instr.body)) ++blockDepth;

        firstStmt = false;
    }
    out.emplace_back("}");
}

} // namespace

ScriptDisasm disasmScript(const Script& script) {
    ScriptDisasm result;
    result.perSection.resize(script.sections.size());

    // Pass 1: decode every section, collecting label offsets script-wide.
    LabelMap labels;
    std::vector<std::vector<DecodedInstr>> stmts(script.sections.size());
    for (std::size_t i = 0; i < script.sections.size(); ++i) {
        stmts[i] = decodeSectionStmts(script.sections[i], script, labels, i);
    }

    // Pass 1.5: surface engine-dispatched jump-table entry points by adding
    // labels at the head-run of consecutive unconditional terminators.
    for (std::size_t i = 0; i < script.sections.size(); ++i) {
        addJumpTableHeadLabels(labels[i], stmts[i]);
    }

    // Pass 1.6: beautification -- collapse repetitive / paired patterns
    // into compact forms.  Every transformation preserves byte semantics:
    // the parser re-expands them back to the exact instruction sequence.
    for (std::size_t i = 0; i < script.sections.size(); ++i) {
        const auto labIt = labels.find(i);
        const std::unordered_set<int> empty;
        const auto& secLabels = (labIt == labels.end()) ? empty : labIt->second;
        beautifyChoice(stmts[i], secLabels);       // selection+textbox+wait -> choice (custom syntax; not in functions.dgs)
        // Structural passes -- they recognise stream patterns (runs, ranges,
        // arrays) that don't fit the "fixed window + literal/hole" model of
        // genericBeautifyComposites.  They must run before the generic sweep
        // below so the generic sweep can see the for-loops they produce.
        beautifyStatsList(stmts[i], secLabels);    // addStats/reduceStats/setStats runs
        beautifyLearnMoves(stmts[i], secLabels);   // learnMove runs -> learnMoves([...])
        beautifyRemoveItems(stmts[i], secLabels);  // removeItem runs (uniform count)
        beautifyForRanges(stmts[i], secLabels);    // stride-1 same-mnemonic runs
        // Named loop-composites (setDigimonAt, loadDigimonBatch, setDigimonBatch)
        // run BEFORE the bare for-loop fold so a function-named form wins over
        // an anonymous `for x in [...]` when both could apply.
        beautifyPairLoopComposites(stmts[i], secLabels);  // for-loop composites: 1-iter Kind[] OR 2-iter (K,K)[]
        beautifyForArray(stmts[i], secLabels);     // varying-one-slot >=3 -> for x in [list]
        // Composite folding happens in the final sweep, after beautifyApproach
        // has had a chance to see its unfolded look-pair / waitForEntity body.
    }

    // Pass 1.65: rewrite `Lx: ...; goto Lx; Ly:` goto-cycles as `loop {} break`.
    // Needs a cross-section refs index so we know when a label is reachable
    // from outside the candidate block (and therefore can't be dropped).
    std::vector<std::unordered_set<int>> crossSecRefs(script.sections.size());
    {
        std::unordered_map<std::string, std::size_t> nameToIdx;
        for (std::size_t s = 0; s < script.sections.size(); ++s) {
            nameToIdx[sectionName(script, script.sections[s])] = s;
        }
        for (std::size_t s = 0; s < script.sections.size(); ++s) {
            for (const auto& instr : stmts[s]) {
                std::string_view body = instr.body;
                std::size_t i = 0;
                while (i + 6 <= body.size()) {
                    if (body[i] != 'L' || body[i + 1] != '_') { ++i; continue; }
                    if (i >= 1 && isAsciiIdentCont(body[i - 1]) && body[i - 1] != '.') {
                        ++i; continue;
                    }
                    bool ok = true;
                    int off = 0;
                    for (int k = 0; k < 4; ++k) {
                        char c = body[i + 2 + k];
                        if (c >= '0' && c <= '9') off = off * 16 + (c - '0');
                        else if (c >= 'a' && c <= 'f') off = off * 16 + (c - 'a' + 10);
                        else { ok = false; break; }
                    }
                    if (!ok) { ++i; continue; }
                    if (i + 6 < body.size() && isAsciiIdentCont(body[i + 6])) { i += 6; continue; }
                    // Cross-section if preceded by `<ident>.` with ident found in nameToIdx.
                    if (i >= 1 && body[i - 1] == '.') {
                        std::size_t e = i - 1, st = e;
                        while (st > 0 && isAsciiIdentCont(body[st - 1])) --st;
                        auto it = nameToIdx.find(std::string{body.substr(st, e - st)});
                        if (it != nameToIdx.end() && it->second != s) {
                            crossSecRefs[it->second].insert(off);
                        }
                    }
                    i += 6;
                }
            }
        }
    }
    for (std::size_t i = 0; i < script.sections.size(); ++i) {
        auto& secLabels = labels[i];  // mutable; beautifyLoops may erase entries
        // Single pass: process sequential outermost loops only.  Iterating
        // would let a later pass cross the boundary of an already-rewritten
        // loop (when an internal label has a back-edge from outside that
        // earlier rewrite), producing tangled overlapping `loop {}` blocks.
        beautifyLoopsOnce(stmts[i], secLabels, crossSecRefs[i]);
    }

    // Pass 1.7: fold the canonical NPC-approach routine (loop + trailing
    // wait/unload/reset triple) into `approach(...)`.  Runs after the loop
    // beautifier since it pattern-matches against `loop {` / `}` markers.
    for (std::size_t i = 0; i < script.sections.size(); ++i) {
        // Need mutable access for beautifyIfBlocksOnce, which erases the
        // closing-label entry on every successful collapse.  Sections with
        // no labels get a temporary empty set (still valid for the const
        // beautifies that look at it, since none of them mutate either).
        auto& secLabels = labels[i];
        beautifyApproach(stmts[i], secLabels);
        // Composite folding must run AFTER approach so we don't pre-consume the
        // look-pair / waitForEntity / delay statements that the approach
        // matcher depends on inside its 11-stmt window.
        beautifySetObjectsVisibleRange(stmts[i], secLabels);  // for-id {setObjectVisibility} -> setObjectsVisibleRange (control-flow; bespoke)
        // If-block collapses BEFORE composites: composites can now contain
        // block-form `if (cond) { body }` in their function bodies, and the
        // matcher needs to see the corpus stmts already in block form to match.
        //
        //   1. beautifyIfElseOnce — two-way-jump opcode form (no corpus matches
        //      today; future authored sources may use it).
        //   2. beautifyIfBlocksOnce — single-arm `if (cond) goto Lx; body; Lx:`.
        //   3. beautifyIfElseFromSingleArmOnce — post-v1: turn `if (X) { body;
        //      goto Lend; }; body_else; Lend:` back into if/else.
        while (beautifyIfElseOnce(stmts[i], secLabels, crossSecRefs[i])) {}
        while (beautifyIfBlocksOnce(stmts[i], secLabels, crossSecRefs[i])) {}
        // Fold runs of `if (pstat[X] == K_i) { body }` arms into a single
        // `switch pstat[X] { K => { body } ... }`.  Runs AFTER the if-block
        // collapse so the arms are already in bodied form.
        while (beautifySwitchOnce(stmts[i], secLabels)) {}
        // do-while: conditional back-edge inside an if-block.  Runs AFTER
        // beautifyIfBlocksOnce so the enclosing `if (cond) { ... goto L; }`
        // shape exists.
        while (beautifyDoWhileOnce(stmts[i], secLabels, crossSecRefs[i])) {}
        while (beautifyIfElseFromSingleArmOnce(stmts[i], secLabels, crossSecRefs[i])) {}
        // Collapse 4-instr if-else-goto pattern: `if (X) { goto A; goto B; } goto B;`
        // -> `if (X) goto A; else goto B;`.  Runs AFTER the if-block beautify
        // (which produces the post-collapse shape) and BEFORE the block recognizer
        // (which would otherwise wrap goto B's merge label).
        while (beautifyIfElseGotoOnce(stmts[i])) {}
        // Multi-predecessor forward-merge labels become bare `{ ... break; ... }`
        // blocks.  Runs AFTER the simple if-block collapses so the merge labels
        // we're left with are genuine multi-pred merges (not just single-arm
        // closes the if-block recognizer skipped).
        while (beautifyBlocksOnce(stmts[i], secLabels, crossSecRefs[i])) {}
        genericBeautifyComposites(stmts[i], secLabels);  // functions.dgs-driven: anim, sfx, speak, startBattle, finishEncounter, etc.
        // Cosmetic chain merge: `} else { if (X) {...} }` -> `} else if (X) {...}`.
        // Runs LAST so that any pattern composites might have consumed is already
        // accounted for; pure rendering reshape (no byte change).
        while (beautifyElseIfChainOnce(stmts[i])) {}
    }

    // Pass 1.75: assign sequential per-section label names (L1, L2, ...) in
    // ascending offset order.  Cosmetic -- body strings are rewritten in pass 2.
    std::vector<LabelRename> rename(script.sections.size());
    for (std::size_t i = 0; i < script.sections.size(); ++i) {
        auto labIt = labels.find(i);
        if (labIt == labels.end()) continue;
        std::vector<int> offs(labIt->second.begin(), labIt->second.end());
        std::sort(offs.begin(), offs.end());
        for (std::size_t k = 0; k < offs.size(); ++k) {
            rename[i][offs[k]] = std::string{"L"} + toDec(static_cast<long long>(k + 1));
        }
    }
    std::unordered_map<std::string, std::size_t> sectionByName;
    for (std::size_t i = 0; i < script.sections.size(); ++i) {
        sectionByName[sectionName(script, script.sections[i])] = i;
    }

    // Pass 2: serialize.
    for (std::size_t i = 0; i < script.sections.size(); ++i) {
        const auto& sec = script.sections[i];
        const auto labIt = labels.find(i);
        const std::unordered_set<int> empty;
        const auto& secLabels = (labIt == labels.end()) ? empty : labIt->second;
        serializeSection(result.perSection[i], script, sec, i, stmts[i], secLabels, rename, sectionByName);
    }

    return result;
}

} // namespace dd
