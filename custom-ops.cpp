#include "custom-ops.hpp"
#include "char-map.hpp"
#include "symbols.hpp"
#include "targets.hpp"

#include <stdexcept>
#include <string>
#include <unordered_map>

namespace dd {

namespace {

// 0x10  setSelection
// u8 numOptions, then u16[numOptions] script-offsets (each a s16 label).
// Source form: `setSelection(L_NNNN, section_X.L_NNNN, ...)`.
Decoded decodeSetSelection(std::span<const u8> b, std::size_t after,
                           std::size_t /*sectionEnd*/, const Script* script,
                           const Section* currentSec, LabelMap* labels) {
    if (after >= b.size()) throw std::runtime_error("setSelection truncated");
    const u8 numOptions = b[after];
    const std::size_t need = 1 + 1 + std::size_t{numOptions} * 2;
    if (after - 1 + need > b.size()) throw std::runtime_error("setSelection truncated");

    std::string text = "setSelection(";
    for (std::size_t i = 0; i < numOptions; ++i) {
        if (i) text += ", ";
        i16 off = readI16(b, after + 1 + i * 2);
        text += resolveLabel(*script, currentSec,off, labels);
    }
    text += ')';
    return { std::move(text), need };
}

// 0x18  switch
// u8 pstat, u16 count, then u16[count] script-offsets (s16 labels).
// Source form: `switch (pstat[N]) { case 0: goto L; case 1: goto L; }`.
Decoded decodeSwitch(std::span<const u8> b, std::size_t after,
                     std::size_t /*sectionEnd*/, const Script* script,
                     const Section* currentSec, LabelMap* labels) {
    if (after + 3 > b.size()) throw std::runtime_error("switch truncated");
    const u8  pstat = b[after];
    const i16 count = readI16(b, after + 1);
    if (count < 0) throw std::runtime_error("switch negative count");
    const std::size_t need = 1 + 1 + 2 + static_cast<std::size_t>(count) * 2;
    if (after - 1 + need > b.size()) throw std::runtime_error("switch truncated");

    std::string text = "switch (pstat[";
    text += toDec(pstat);
    text += "]) { ";
    for (std::size_t i = 0; i < static_cast<std::size_t>(count); ++i) {
        text += "case ";
        text += toDec(static_cast<long long>(i));
        text += ": goto ";
        text += resolveLabel(*script, currentSec,readI16(b, after + 3 + i * 2), labels);
        text += "; ";
    }
    text += '}';
    return { std::move(text), need };
}

// 0x19  if
// u8 pad; sequence of {u16 cmp; payload[opSize]}; terminator u16==0x0018;
// u16 thenTarget; u16 endIf (sentinel 0x19 means "no else").

const std::unordered_map<u8, std::size_t>& ifOpSizes() {
    static const std::unordered_map<u8, std::size_t> m = {
        {0x00, 2}, {0x01, 2}, {0x08, 2}, {0x09, 2}, {0x0a, 2}, {0x0b, 2}, {0x0c, 2}, {0x0d, 2},
        {0x20, 4}, {0x21, 4}, {0x22, 2}, {0x23, 2}, {0x24, 4}, {0x25, 6},
    };
    return m;
}

const char* cmpSign(u8 v) {
    switch (v) {
        case 0: return "!=";
        case 1: return "==";
        case 2: return "<";
        case 3: return ">";
        case 4: return "<=";
        case 5: return ">=";
        default: return nullptr;
    }
}

// 0x08..0x0D embed the comparison directly in the opcode kind.
const char* pstatSign(u8 op) {
    switch (op) {
        case 0x08: return "!=";
        case 0x09: return "==";
        case 0x0a: return "<";
        case 0x0b: return ">";
        case 0x0c: return "<=";
        case 0x0d: return ">=";
        default: return "?";
    }
}

const char* linkSym(u8 link) {
    if (link == 0x40) return "&&";
    if (link == 0x80) return "||";
    return "??";
}

std::string renderSign(u8 v) {
    if (auto* s = cmpSign(v)) return s;
    std::string out = "?cmp";
    out += toDec(v);
    return out;
}

// Render a value as "Kind.Name" if it has a known symbolic binding;
// otherwise as a decimal integer.
std::string renderSym(SymKind k, int val) {
    std::string nm = symbolTable().lookupName(k, val);
    if (nm.empty()) return toDec(static_cast<long long>(val));
    std::string out{symKindLabel(k)};
    out += '.';
    out += nm;
    return out;
}

std::string renderPredicate(u8 op, std::span<const u8> payload) {
    std::string out;
    switch (op) {
        case 0x00: {
            out = "!trigger("; out += toDec(readU16(payload, 0)); out += ")";
            return out;
        }
        case 0x01: {
            out = "trigger("; out += toDec(readU16(payload, 0)); out += ")";
            return out;
        }
        case 0x08: case 0x09: case 0x0a: case 0x0b: case 0x0c: case 0x0d: {
            out = "pstat[";
            out += toDec(payload[0]);
            out += "] ";
            out += pstatSign(op);
            out += ' ';
            out += toDec(payload[1]);
            return out;
        }
        case 0x20: {
            out = "stat["; out += renderSym(SymKind::Stat, payload[0]); out += "] ";
            out += renderSign(payload[1]); out += ' ';
            out += toDec(readI16(payload, 2));
            return out;
        }
        case 0x21: {
            out = "card["; out += toDec(payload[0]); out += "] ";
            out += renderSign(payload[1]); out += ' ';
            out += toDec(readI16(payload, 2));
            return out;
        }
        case 0x22: {
            out = "hasTech("; out += renderSym(SymKind::Move, payload[0]); out += ") == ";
            out += toDec(payload[1]);
            return out;
        }
        case 0x23: {
            out = "(cond & 0x"; out += toHexPadded(payload[0], 2);
            out += ") == 0x"; out += toHexPadded(payload[1], 2);
            return out;
        }
        case 0x24: {
            out = "item["; out += renderSym(SymKind::Item, payload[0]); out += "] ";
            out += renderSign(payload[1]); out += ' ';
            out += toDec(readI16(payload, 2));
            return out;
        }
        case 0x25: {
            out = "money "; out += renderSign(payload[1]); out += ' ';
            out += toDec(readI32(payload, 2));
            return out;
        }
        default: {
            std::string hex;
            for (auto byte : payload) hex += toHexPadded(byte, 2);
            out = "op"; out += toHex(op);
            out += '('; out += hex; out += ')';
            return out;
        }
    }
}

struct Term { u8 link; std::string pred; };

// Left-to-right, paren-wrap on link change.  Uniform &&/|| chains stay paren-free.
std::string buildExpr(const std::vector<Term>& terms) {
    if (terms.empty()) return "true";
    std::string expr = terms[0].pred;
    const char* curLink = nullptr;
    for (std::size_t i = 1; i < terms.size(); ++i) {
        const char* link = linkSym(terms[i].link);
        if (curLink && std::string_view{link} != curLink) {
            expr = std::string{"("} + expr + ")";
        }
        expr += ' ';
        expr += link;
        expr += ' ';
        expr += terms[i].pred;
        curLink = link;
    }
    return expr;
}

// Split `<lhs> OP <rhs>` (where OP is one of >=, <=, ==, !=, >, <) at the
// rightmost top-level OP.  Returns the three pieces (trimmed views into
// `s`).  Used to detect range-predicate canonical forms.
struct CmpSplit { std::string_view lhs; std::string_view op; std::string_view rhs; };
std::optional<CmpSplit> splitCmp(std::string_view s) {
    static const std::string_view ops[] = {">=", "<=", "==", "!=", ">", "<"};
    int depth = 0;
    bool inStr = false;
    for (std::size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (inStr) {
            if (c == '\\' && i + 1 < s.size()) { ++i; continue; }
            if (c == '"') inStr = false;
            continue;
        }
        if (c == '"') { inStr = true; continue; }
        if (c == '(' || c == '[') ++depth;
        else if (c == ')' || c == ']') --depth;
        if (depth != 0) continue;
        for (auto op : ops) {
            if (s.size() - i >= op.size() && s.substr(i, op.size()) == op) {
                CmpSplit r;
                r.lhs = trim(s.substr(0, i));
                r.op  = op;
                r.rhs = trim(s.substr(i + op.size()));
                return r;
            }
        }
    }
    return std::nullopt;
}

// When the term list is exactly two `&&`-linked comparisons on the same
// LHS, with operators `(>=, <)` or `(>=, <=)`, render as `<lhs> in S..E`
// (half-open) or `<lhs> in S..=E` (inclusive).  Mirror for `||`-linked
// `(<, >=)` / `(<, >)` -> `<lhs> not in S..E` / `<lhs> not in S..=E`.
std::optional<std::string> tryRangeForm(const std::vector<Term>& terms) {
    if (terms.size() != 2) return std::nullopt;
    if (terms[0].link != 0) return std::nullopt;
    auto t0 = splitCmp(terms[0].pred);
    auto t1 = splitCmp(terms[1].pred);
    if (!t0 || !t1) return std::nullopt;
    if (t0->lhs != t1->lhs) return std::nullopt;
    const std::string_view lhs = t0->lhs;
    const std::string_view S = t0->rhs;
    const std::string_view E = t1->rhs;

    if (terms[1].link == 0x40) {                       // && chain
        if (t0->op == ">=" && (t1->op == "<" || t1->op == "<=")) {
            std::string out{lhs};
            out += " in ";
            out += S;
            out += "..";
            if (t1->op == "<=") out += "=";
            out += E;
            return out;
        }
    } else if (terms[1].link == 0x80) {                // || chain
        if (t0->op == "<" && (t1->op == ">=" || t1->op == ">")) {
            std::string out{lhs};
            out += " not in ";
            out += S;
            out += "..";
            if (t1->op == ">") out += "=";
            out += E;
            return out;
        }
    }
    return std::nullopt;
}

// Source form:
//   if (<expr>) goto <thenLabel>;
//   if (<expr>) goto <thenLabel>; else goto <elseLabel>;
Decoded decodeIf(std::span<const u8> b, std::size_t after,
                 std::size_t sectionEnd, const Script* script,
                 const Section* currentSec, LabelMap* labels) {
    std::size_t cursor = after + 1; // skip pad
    std::vector<Term> terms;
    bool sawTerminator = false;

    while (cursor + 2 <= sectionEnd) {
        u16 cmp = readU16(b, cursor);
        if (cmp == 0x0018) { sawTerminator = true; break; }
        u8 opKind = static_cast<u8>(cmp & 0x3f);
        const auto& sizes = ifOpSizes();
        auto it = sizes.find(opKind);
        if (it == sizes.end()) {
            throw std::runtime_error(std::string{"unknown if sub-op 0x"} + toHex(cmp));
        }
        std::size_t payloadSize = it->second;
        if (cursor + 2 + payloadSize > sectionEnd) {
            throw std::runtime_error("if predicate truncated");
        }
        auto payload = b.subspan(cursor + 2, payloadSize);
        terms.push_back({ static_cast<u8>(cmp & 0xc0), renderPredicate(opKind, payload) });
        cursor += 2 + payloadSize;
    }
    if (!sawTerminator || cursor + 6 > sectionEnd) {
        throw std::runtime_error("if tail truncated");
    }
    cursor += 2; // terminator 0x0018
    std::string thenLabel = resolveLabel(*script, currentSec,readI16(b, cursor), labels);
    cursor += 2;
    i16 endIfRaw = readI16(b, cursor); cursor += 2;
    // endIf == 0x19 is the compiler's "no else scope" sentinel.  Omit the
    // else clause entirely so the disasm reflects real control flow; the
    // assembler re-inserts the sentinel when the source has no `else`.
    std::string text = "if (";
    if (auto range = tryRangeForm(terms)) text += *range;
    else                                  text += buildExpr(terms);
    text += ") goto ";
    text += thenLabel;
    if (endIfRaw != 0x19) {
        text += "; else goto ";
        text += resolveLabel(*script, currentSec,endIfRaw, labels);
    }
    return { std::move(text), cursor - after + 1 };
}

// 0x1A  showTextbox
// u8 pad, then u16 chars until u16 == 0.
Decoded decodeShowTextbox(std::span<const u8> b, std::size_t after,
                          std::size_t sectionEnd, const Script* /*script*/,
                          const Section* /*currentSec*/, LabelMap* /*labels*/) {
    std::size_t cursor = after + 1; // skip pad
    std::string text;
    while (cursor + 2 <= sectionEnd) {
        u16 c = readU16(b, cursor);
        cursor += 2;
        if (c == 0) break;
        text += gameCharacterRT(c);
    }
    std::string out = "showTextbox(";
    out += quoteString(text);
    out += ')';
    return { std::move(out), cursor - after + 1 };
}

// 0x3A  clearInventory
Decoded decodeClearInventory(std::span<const u8> /*b*/, std::size_t /*after*/,
                             std::size_t /*sectionEnd*/, const Script* /*script*/,
                             const Section* /*currentSec*/, LabelMap* /*labels*/) {
    return { "clearInventory()", 1 };
}

// 0x6B  tournamentData
// u8 empty, then u8 values until 0xFF sentinel.
// Source form: `tournamentData(0, 1, 2, 255)` -- decimal byte list.
Decoded decodeTournamentData(std::span<const u8> b, std::size_t after,
                             std::size_t sectionEnd, const Script* /*script*/,
                             const Section* /*currentSec*/, LabelMap* /*labels*/) {
    std::size_t cursor = after + 1;
    std::string text = "tournamentData(";
    bool first = true;
    while (cursor < sectionEnd) {
        u8 v = b[cursor];
        cursor++;
        if (!first) text += ", ";
        text += toDec(v);
        first = false;
        if (v == 0xff) break;
    }
    text += ')';
    return { std::move(text), cursor - after + 1 };
}

// 0xFF  garbage
// u8 empty, then filler to end of section.
// Source form: `garbage { 14 00 fe 00 ... }` -- space-separated hex bytes.
Decoded decodeGarbage(std::span<const u8> b, std::size_t after,
                      std::size_t sectionEnd, const Script* /*script*/,
                      const Section* /*currentSec*/, LabelMap* /*labels*/) {
    std::string out = "garbage {";
    if (after + 1 < sectionEnd) {
        out += ' ';
        for (std::size_t i = after + 1; i < sectionEnd; ++i) {
            if (i > after + 1) out += ' ';
            out += toHexPadded(b[i], 2);
        }
        out += ' ';
    }
    out += '}';
    // Match TS: consumed = sectionEnd - (after - 1) = sectionEnd - after + 1
    return { std::move(out), sectionEnd - (after - 1) };
}

} // namespace

const std::unordered_map<u8, Decoder>& customDecoders() {
    static const std::unordered_map<u8, Decoder> m = {
        { 0x10, decodeSetSelection },
        { 0x18, decodeSwitch },
        { 0x19, decodeIf },
        { 0x1a, decodeShowTextbox },
        { 0x3a, decodeClearInventory },
        { 0x6b, decodeTournamentData },
        { 0xff, decodeGarbage },
    };
    return m;
}

} // namespace dd
