#include "disasm.hpp"
#include "char-map.hpp"
#include "custom-ops.hpp"
#include "opcodes.hpp"
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
                text = toDec(static_cast<long long>(val));
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
            auto va = tryParseInt(cPrev->args[d]);
            auto vb = tryParseInt(cj->args[d]);
            if (!va || !vb || *vb - *va != 1) break;
            if (diffPos == -1) diffPos = d;
            else if (diffPos != d) break;
            runEnd = j;
        }
        std::size_t runLen = runEnd - i + 1;
        if (runLen >= 3 && diffPos != -1) {
            auto cEnd = parseSimpleCall(stmts[runEnd].body);
            auto vS = tryParseInt(c0->args[diffPos]);
            auto vE = tryParseInt(cEnd->args[diffPos]);
            // Build the loop-body call with `id` replacing the iterator slot.
            std::string call{c0->mnemonic};
            call += '(';
            for (std::size_t k = 0; k < c0->args.size(); ++k) {
                if (k) call += ", ";
                if (static_cast<int>(k) == diffPos) call += "id";
                else call.append(c0->args[k]);
            }
            call += ')';
            std::string forBody = "for id in ";
            forBody += toDec(static_cast<long long>(*vS));
            forBody += "..";
            forBody += toDec(static_cast<long long>(*vE));
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

// Collapse `fadeOutHUD(); delay(1); startBattle(...);` triples into a single
// `startBattle(...);` -- the prelude is universal in the shipping corpus and
// the parser re-adds it via sugar.
void beautifyStartBattle(std::vector<DecodedInstr>& stmts,
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
            if (c0 && c0->mnemonic == "fadeOutHUD" && c0->args.empty()
                && c1 && c1->mnemonic == "delay" && c1->args.size() == 1 && c1->args[0] == "1"
                && c2 && c2->mnemonic == "startBattle") {
                std::size_t consumed = stmts[i].consumed
                                     + stmts[i + 1].consumed
                                     + stmts[i + 2].consumed;
                out.push_back({stmts[i].offset, consumed, stmts[i + 2].body});
                i += 3;
                continue;
            }
        }
        out.push_back(stmts[i]);
        ++i;
    }
    stmts = std::move(out);
}

// Collapse `loadDigimon(D); setDigimon(D, E, A);` (same digimon ID in both
// slots) into a single `loadAndSetDigimon(D, E, A);` call.  Matching
// macro lives in functions.dgs and expands back to the two opcodes.
void beautifyLoadAndSetDigimon(std::vector<DecodedInstr>& stmts,
                               const std::unordered_set<int>& labelOffsets) {
    std::vector<DecodedInstr> out;
    out.reserve(stmts.size());
    std::size_t i = 0;
    while (i < stmts.size()) {
        if (i + 1 < stmts.size()
            && !labelOffsets.count(static_cast<int>(stmts[i + 1].offset))) {
            auto c0 = parseSimpleCall(stmts[i].body);
            auto c1 = parseSimpleCall(stmts[i + 1].body);
            if (c0 && c1
                && c0->mnemonic == "loadDigimon" && c0->args.size() == 1
                && c1->mnemonic == "setDigimon"  && c1->args.size() == 3
                && c0->args[0] == c1->args[0]) {
                std::string body = "loadAndSetDigimon(";
                body.append(c0->args[0]);
                body += ", ";
                body.append(c1->args[1]);
                body += ", ";
                body.append(c1->args[2]);
                body += ')';
                std::size_t consumed = stmts[i].consumed + stmts[i + 1].consumed;
                out.push_back({stmts[i].offset, consumed, std::move(body)});
                i += 2;
                continue;
            }
        }
        out.push_back(stmts[i]);
        ++i;
    }
    stmts = std::move(out);
}

// Collapse the "section preamble" -- `setScript(S, M); setPStat(245, V);
// setBGM(B);` -- into a single `switchToMap(S, M, V, B)` call.  The 245
// slot is the canonical current-map pstat.  Matching macro in functions.dgs
// expands back to the three underlying opcodes.
void beautifySwitchToMap(std::vector<DecodedInstr>& stmts,
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
            if (c0 && c1 && c2
                && c0->mnemonic == "setScript" && c0->args.size() == 2
                && c1->mnemonic == "setPStat"  && c1->args.size() == 2
                && c1->args[0] == "245"
                && c2->mnemonic == "setBGM"    && c2->args.size() == 1) {
                std::string body = "switchToMap(";
                body.append(c0->args[0]); body += ", ";
                body.append(c0->args[1]); body += ", ";
                body.append(c1->args[1]); body += ", ";
                body.append(c2->args[0]);
                body += ')';
                std::size_t consumed = stmts[i].consumed
                                     + stmts[i + 1].consumed
                                     + stmts[i + 2].consumed;
                out.push_back({stmts[i].offset, consumed, std::move(body)});
                i += 3;
                continue;
            }
        }
        out.push_back(stmts[i]);
        ++i;
    }
    stmts = std::move(out);
}

// Collapse `sectionOnExit(T); callDigimonSubroutine(R); waitForEntity(Entity.System);`
// into a single `runDigimonRoutine(T, R)` call.  The third stmt's arg is
// always the System entity in the shipping corpus; if it ever isn't, the
// pattern stays uncollapsed.
void beautifyRunDigimonRoutine(std::vector<DecodedInstr>& stmts,
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
            if (c0 && c1 && c2
                && c0->mnemonic == "sectionOnExit"          && c0->args.size() == 1
                && c1->mnemonic == "callDigimonSubroutine"  && c1->args.size() == 1
                && c2->mnemonic == "waitForEntity"          && c2->args.size() == 1
                && (c2->args[0] == "Entity.System" || c2->args[0] == "255")) {
                std::string body = "runDigimonRoutine(";
                body.append(c0->args[0]); body += ", ";
                body.append(c1->args[0]);
                body += ')';
                std::size_t consumed = stmts[i].consumed
                                     + stmts[i + 1].consumed
                                     + stmts[i + 2].consumed;
                out.push_back({stmts[i].offset, consumed, std::move(body)});
                i += 3;
                continue;
            }
        }
        out.push_back(stmts[i]);
        ++i;
    }
    stmts = std::move(out);
}

void beautifySpeak(std::vector<DecodedInstr>& stmts,
                   const std::unordered_set<int>& labelOffsets) {
    std::vector<DecodedInstr> out;
    out.reserve(stmts.size());
    std::size_t i = 0;
    while (i < stmts.size()) {
        if (i + 1 < stmts.size()
            && !labelOffsets.count(static_cast<int>(stmts[i + 1].offset))) {
            auto c0 = parseSimpleCall(stmts[i].body);
            auto c1 = parseSimpleCall(stmts[i + 1].body);
            if (c0 && c1
                && c0->mnemonic == "setDialogOwner" && c0->args.size() == 1
                && c1->mnemonic == "showTextbox"    && c1->args.size() == 1) {
                std::string body = "speak(";
                body.append(c0->args[0]);
                body += ", ";
                body.append(c1->args[0]);
                body += ')';
                std::size_t consumed = stmts[i].consumed + stmts[i + 1].consumed;
                out.push_back({stmts[i].offset, consumed, std::move(body)});
                i += 2;
                continue;
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

bool isAsciiIdentCont(char c) {
    return c == '_' || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

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
    for (const auto& instr : stmts) {
        const bool isLabelHere = labelOffsets.count(static_cast<int>(instr.offset));
        if (isLabelHere) {
            // Blank line before label to visually separate flow chunks
            // (skip if this is the very first statement in the section).
            if (!firstStmt) out.emplace_back("");
            std::string lab;
            auto rit = rename[secIdx].find(static_cast<int>(instr.offset));
            lab = (rit != rename[secIdx].end()) ? rit->second
                                                : labelInSection(static_cast<int>(instr.offset));
            lab += ':';
            out.push_back(std::move(lab));
        }
        std::string text{INDENT};
        text += renameLabelsInBody(instr.body, secIdx, rename, sectionByName);
        // Block-bodied statements (e.g. `for { ... }`) already end with `}` --
        // appending `;` produces noise like `};`.  Plain calls always need
        // the terminator.
        if (text.empty() || text.back() != '}') text += ';';
        // Multi-line bodies: split on `\n`.  First line keeps the INDENT
        // prefix from above; subsequent lines come through verbatim and
        // are expected to carry their own indentation in the body string.
        std::size_t start = 0;
        for (std::size_t k = 0; k <= text.size(); ++k) {
            if (k == text.size() || text[k] == '\n') {
                out.push_back(text.substr(start, k - start));
                start = k + 1;
            }
        }
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
        beautifyChoice(stmts[i], secLabels);       // selection+textbox+wait -> choice
        beautifySwitchToMap(stmts[i], secLabels);  // setScript+setPStat(245,_)+setBGM -> switchToMap
        beautifyRunDigimonRoutine(stmts[i], secLabels);  // sectionOnExit+callDigimonSubroutine+waitForEntity(System) -> runDigimonRoutine
        beautifyLoadAndSetDigimon(stmts[i], secLabels);  // loadDigimon+setDigimon (same D) -> loadAndSetDigimon
        beautifySpeak(stmts[i], secLabels);        // (setDialogOwner+showTextbox) -> speak
        beautifyStartBattle(stmts[i], secLabels);  // fadeOutHUD+delay+startBattle -> startBattle
        beautifyStatsList(stmts[i], secLabels);    // addStats/reduceStats/setStats runs
        beautifyLearnMoves(stmts[i], secLabels);   // learnMove runs -> learnMoves([...])
        beautifyRemoveItems(stmts[i], secLabels);  // removeItem runs (uniform count) -> removeItems([...], n)
        beautifyForRanges(stmts[i], secLabels);    // stride-1 same-mnemonic runs
        beautifyForArray(stmts[i], secLabels);     // any varying-one-slot >=3 -> for x in [list]
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
