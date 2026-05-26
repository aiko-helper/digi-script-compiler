#include "assemble.hpp"
#include "char-map.hpp"
#include "opcodes.hpp"
#include "predicate_neg.hpp"
#include "symbols.hpp"
#include "targets.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <deque>
#include <functional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

namespace dd {

// DG.SCN's 224th u32 pointer is actually the literal bytes `\SCN` -- the
// trailing signature of each 32-byte filename-table entry, one entry
// earlier than the nominal table start.  Constant of the format.
static constexpr u32 DG_END_POINTER = 0x4e43535c;

// Low-level helpers

namespace {

int parseNum(std::string_view s);

// Current per-script local symbol table -- set via LocalSymsScope around
// every encode pass for a script.  Single-threaded; null when no locals.
const SymbolTable* g_localSyms = nullptr;

struct LocalSymsScope {
    const SymbolTable* prev;
    explicit LocalSymsScope(const SymbolTable* s) : prev(g_localSyms) { g_localSyms = s; }
    ~LocalSymsScope() { g_localSyms = prev; }
};

// Accept decimal/hex, `<Kind>.<Name>` qualified refs, `:Name` shorthand
// resolved in the `expectedKind` scope, `<Kind>(N)` explicit-cast literals
// (parses to the integer N; round-trip emission for unnamed typed slots),
// or -- when `expectedKind` is provided -- a bare name resolved in that
// kind via the current local-then-global symbol scope.
int parseNumOrSym(std::string_view s,
                  std::optional<SymKind> expectedKind = std::nullopt) {
    s = trim(s);
    if (!s.empty()) {
        char c0 = s[0];
        if (c0 == ':' && expectedKind) {
            int v;
            if (lookupBareNameInScope(g_localSyms, *expectedKind, s.substr(1), v)) {
                return v;
            }
            throw std::runtime_error(std::string{"unknown :"} + std::string{s.substr(1)}
                + " in kind `" + std::string{symKindLabel(*expectedKind)} + "`");
        }
        if ((c0 >= 'A' && c0 <= 'Z') && s.back() == ')') {
            std::size_t lp = s.find('(');
            if (lp != std::string_view::npos) {
                std::string_view kindTok = trim(s.substr(0, lp));
                std::string_view inner   = trim(s.substr(lp + 1, s.size() - lp - 2));
                if (auto k = symKindFromLabel(kindTok)) {
                    if (expectedKind && *k != *expectedKind) {
                        throw std::runtime_error(
                            std::string{"kind mismatch: expected `"}
                            + std::string{symKindLabel(*expectedKind)}
                            + "`, got `" + std::string{symKindLabel(*k)} + "(...)`");
                    }
                    return parseNumOrSym(inner, k);
                }
            }
        }
        if ((c0 >= 'a' && c0 <= 'z') || (c0 >= 'A' && c0 <= 'Z') || c0 == '_') {
            int v;
            if (s.find('.') != std::string_view::npos) {
                if (resolveQualifiedInScope(g_localSyms, s, v)) return v;
            }
            if (expectedKind && lookupBareNameInScope(g_localSyms, *expectedKind, s, v)) {
                return v;
            }
        }
    }
    return parseNum(s);
}

int parseNum(std::string_view s) {
    s = trim(s);
    if (s == "true") return 1;
    if (s == "false") return 0;
    if (startsWith(s, "0x") || startsWith(s, "0X")) {
        std::string_view rest = s.substr(2);
        bool neg = false;
        if (!rest.empty() && rest[0] == '-') { neg = true; rest.remove_prefix(1); }
        unsigned v = 0;
        for (char c : rest) {
            v <<= 4;
            if      (c >= '0' && c <= '9') v |= (c - '0');
            else if (c >= 'a' && c <= 'f') v |= (c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') v |= (c - 'A' + 10);
            else throw std::runtime_error(std::string{"bad hex: "} + std::string{s});
        }
        int iv = static_cast<int>(v);
        return neg ? -iv : iv;
    }
    bool neg = false;
    std::size_t i = 0;
    if (i < s.size() && s[i] == '-') { neg = true; i++; }
    long long v = 0;
    for (; i < s.size(); ++i) {
        if (s[i] < '0' || s[i] > '9') throw std::runtime_error(std::string{"bad dec: "} + std::string{s});
        v = v * 10 + (s[i] - '0');
    }
    return static_cast<int>(neg ? -v : v);
}

std::unordered_map<std::string, std::string> parseKV(std::string_view rest) {
    std::unordered_map<std::string, std::string> kv;
    for (auto tok : splitWhitespace(trim(rest))) {
        std::size_t eq = tok.find('=');
        if (eq == std::string_view::npos) continue;
        kv.emplace(std::string{tok.substr(0, eq)}, std::string{tok.substr(eq + 1)});
    }
    return kv;
}

void appendU16LE(std::vector<u8>& dst, u16 v) {
    dst.push_back(static_cast<u8>(v & 0xff));
    dst.push_back(static_cast<u8>((v >> 8) & 0xff));
}

// Strip a `// ...` line comment, respecting quoted strings.
std::string_view stripLineComment(std::string_view line) {
    bool inStr = false;
    for (std::size_t i = 0; i + 1 < line.size(); ++i) {
        char c = line[i];
        if (inStr) {
            if (c == '\\') { ++i; continue; }
            if (c == '"') inStr = false;
            continue;
        }
        if (c == '"') { inStr = true; continue; }
        if (c == '/' && line[i + 1] == '/') {
            return line.substr(0, i);
        }
    }
    return line;
}

// Walk `s` left-to-right, tracking nesting depth across (), [], {} and
// strings.  Returns the position of the first top-level occurrence of
// any character in `chars`, or npos.
std::size_t findTopLevelAny(std::string_view s, std::string_view chars,
                            std::size_t start = 0) {
    int depth = 0;
    bool inStr = false;
    for (std::size_t i = start; i < s.size(); ++i) {
        char c = s[i];
        if (inStr) {
            if (c == '\\') { ++i; continue; }
            if (c == '"') inStr = false;
            continue;
        }
        if (c == '"') { inStr = true; continue; }
        if (c == '(' || c == '[' || c == '{') depth++;
        else if (c == ')' || c == ']' || c == '}') depth--;
        else if (depth == 0 && chars.find(c) != std::string_view::npos) return i;
    }
    return std::string_view::npos;
}

// Find the index of the matching `)` for an opening `(` at `lparen`.
// `lparen` must point to a `(`.  Returns npos if no match.
std::size_t findMatchingRparen(std::string_view s, std::size_t lparen) {
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

// Split a string by top-level commas, respecting nesting.  Trims each piece.
std::vector<std::string_view> splitTopCommas(std::string_view s) {
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

// Split by top-level `;`s, respecting nesting.  Trims; drops empties.
std::vector<std::string_view> splitTopSemis(std::string_view s) {
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

bool isIdentStart(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}
bool isIdentCont(char c) {
    return isIdentStart(c) || (c >= '0' && c <= '9');
}

// Extract a leading identifier from `s`.  Returns empty when `s` doesn't
// start with one.
std::string_view leadingIdent(std::string_view s) {
    if (s.empty() || !isIdentStart(s[0])) return {};
    std::size_t n = 1;
    while (n < s.size() && isIdentCont(s[n])) ++n;
    return s.substr(0, n);
}

std::string unquoteString(std::string_view s) {
    s = trim(s);
    if (s.size() < 2 || s.front() != '"' || s.back() != '"') {
        throw std::runtime_error(std::string{"not quoted: "} + std::string{s});
    }
    return std::string{s.substr(1, s.size() - 2)};
}

// `name: value` -- leading identifier followed by `:` at top level.
// Used to detect named-argument mode in call sites.
bool isNamedArgPiece(std::string_view p) {
    p = trim(p);
    if (p.empty() || !isIdentStart(p[0])) return false;
    std::size_t i = 0;
    while (i < p.size() && isIdentCont(p[i])) i++;
    if (i == 0) return false;
    while (i < p.size() && (p[i] == ' ' || p[i] == '\t')) i++;
    return i < p.size() && p[i] == ':';
}

std::pair<std::string_view, std::string_view> splitNamedArg(std::string_view p) {
    p = trim(p);
    std::size_t colon = p.find(':');
    return { trim(p.substr(0, colon)), trim(p.substr(colon + 1)) };
}

} // namespace

// parseSource

namespace {

// Reorder parsed section blocks to match the `#pragma sections` directive.
// Labels in the directive are the canonical "section_<id>[_at_<4hex>]" form.
void reorderSectionsByLabels(std::vector<SecAST>& secs,
                             const std::vector<std::string>& labels) {
    if (secs.empty() || labels.empty()) return;

    std::unordered_map<int, std::vector<SecAST*>> byId;
    for (auto& s : secs) byId[s.id].push_back(&s);

    std::vector<SecAST*> out;
    out.reserve(secs.size());
    std::unordered_set<SecAST*> taken;

    auto takeFrom = [&](std::vector<SecAST*>* pool,
                        std::function<bool(const SecAST&)> match) -> bool {
        if (!pool) return false;
        for (auto* s : *pool) {
            if (taken.count(s)) continue;
            if (!match(*s)) continue;
            taken.insert(s);
            out.push_back(s);
            return true;
        }
        return false;
    };

    for (const auto& label : labels) {
        if (!startsWith(label, "section_")) {
            throw std::runtime_error(std::string{"bad label in #pragma sections: "} + label);
        }
        std::string_view rest{label};
        rest.remove_prefix(8);
        std::size_t i = 0;
        while (i < rest.size() && rest[i] >= '0' && rest[i] <= '9') ++i;
        if (i == 0) throw std::runtime_error(std::string{"bad label in #pragma sections: "} + label);
        int id = 0;
        for (std::size_t k = 0; k < i; ++k) id = id * 10 + (rest[k] - '0');
        std::string_view after = rest.substr(i);
        bool hasDis = false;
        u16 dis = 0;
        if (startsWith(after, "_at_")) {
            std::string_view hex = after.substr(4);
            unsigned v = 0;
            for (char c : hex) {
                v <<= 4;
                if      (c >= '0' && c <= '9') v |= (c - '0');
                else if (c >= 'a' && c <= 'f') v |= (c - 'a' + 10);
                else if (c >= 'A' && c <= 'F') v |= (c - 'A' + 10);
                else throw std::runtime_error(std::string{"bad hex in label: "} + label);
            }
            hasDis = true;
            dis = static_cast<u16>(v);
        }
        auto it = byId.find(id);
        auto* pool = (it == byId.end()) ? nullptr : &it->second;
        if (hasDis) {
            if (!takeFrom(pool, [dis](const SecAST& s){ return s.hasDisambig && s.disambig == dis; })) {
                throw std::runtime_error(std::string{"no section matches "} + label);
            }
        } else {
            if (!takeFrom(pool, [](const SecAST&){ return true; })) {
                throw std::runtime_error(std::string{"no section matches "} + label);
            }
        }
    }
    std::vector<SecAST> reordered;
    reordered.reserve(secs.size());
    for (auto* p : out) reordered.push_back(std::move(*p));
    for (auto& s : secs) {
        bool was = false;
        for (auto* p : out) if (p == &s) { was = true; break; }
        if (!was) reordered.push_back(std::move(s));
    }
    secs = std::move(reordered);
}

// Match `section <name>(<id>[, 0x<dis>]) {` -- returns true on success.
bool matchSectionHeader(std::string_view line, std::string& outName,
                        int& outId, bool& outHasDis, u16& outDis) {
    if (!startsWith(line, "section")) return false;
    std::string_view rest = line.substr(7);

    // Two header shapes:
    //   `section(<id>[, 0x<dis>]) { ... }`              -- anonymous (default name)
    //   `section <name>(<id>[, 0x<dis>]) { ... }`       -- named
    std::string_view name;
    if (!rest.empty() && (rest[0] == ' ' || rest[0] == '\t')) {
        while (!rest.empty() && (rest[0] == ' ' || rest[0] == '\t')) rest.remove_prefix(1);
        name = leadingIdent(rest);
        if (!name.empty()) rest.remove_prefix(name.size());
        while (!rest.empty() && (rest[0] == ' ' || rest[0] == '\t')) rest.remove_prefix(1);
    }
    if (rest.empty() || rest[0] != '(') return false;
    std::size_t rp = findMatchingRparen(rest, 0);
    if (rp == std::string_view::npos) return false;
    std::string_view inside = rest.substr(1, rp - 1);
    rest = rest.substr(rp + 1);

    auto pieces = splitTopCommas(inside);
    if (pieces.empty()) return false;
    outId = parseNum(pieces[0]);
    if (pieces.size() == 1) {
        outHasDis = false;
        outDis = 0;
    } else if (pieces.size() == 2) {
        outHasDis = true;
        outDis = static_cast<u16>(parseNum(pieces[1]));
    } else {
        return false;
    }

    while (!rest.empty() && (rest[0] == ' ' || rest[0] == '\t')) rest.remove_prefix(1);
    if (rest.empty() || rest[0] != '{') return false;

    outName.assign(name);
    return true;
}

// Parse one `<kind> { <bindings> }` sub-block into `out`.  `body` is the
// content inside the kind's braces (no outer braces).  Bindings are
// comma- or semicolon-separated; values are integers or `"GlobalName"`
// indirections into the global symbol table for the same kind.
void parseKindBlock(SymKind kind, std::string_view body, SymbolTable& out) {
    auto isWS = [](char c){ return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
    std::size_t i = 0;
    while (i < body.size()) {
        while (i < body.size() && (isWS(body[i]) || body[i] == ';' || body[i] == ',')) ++i;
        if (i >= body.size()) break;
        // // line comment
        if (i + 1 < body.size() && body[i] == '/' && body[i + 1] == '/') {
            while (i < body.size() && body[i] != '\n') ++i;
            continue;
        }
        // /* block comment */
        if (i + 1 < body.size() && body[i] == '/' && body[i + 1] == '*') {
            i += 2;
            while (i + 1 < body.size() && !(body[i] == '*' && body[i + 1] == '/')) ++i;
            if (i + 1 < body.size()) i += 2;
            continue;
        }
        // Identifier
        if (!isIdentStart(body[i])) {
            throw std::runtime_error(std::string{"symbols: expected identifier, got '"} + body[i] + "'");
        }
        std::size_t nameStart = i;
        while (i < body.size() && isIdentCont(body[i])) ++i;
        std::string name{body.substr(nameStart, i - nameStart)};
        while (i < body.size() && isWS(body[i])) ++i;
        if (i >= body.size() || body[i] != '=') {
            throw std::runtime_error(std::string{"symbols: expected '=' after "} + name);
        }
        ++i;
        while (i < body.size() && isWS(body[i])) ++i;
        int value = 0;
        if (i < body.size() && body[i] == '"') {
            ++i;
            std::size_t q = i;
            while (i < body.size() && body[i] != '"') ++i;
            std::string_view qName = body.substr(q, i - q);
            if (i < body.size()) ++i;
            if (!symbolTable().tryLookupBareName(kind, qName, value)) {
                throw std::runtime_error(std::string{"symbols: unknown global "} + std::string{symKindLabel(kind)} +
                                         "." + std::string{qName});
            }
        } else {
            std::size_t v = i;
            while (i < body.size() && body[i] != ';' && body[i] != ',' && body[i] != '\n' && body[i] != '/') ++i;
            value = parseNum(trim(body.substr(v, i - v)));
        }
        out.bind(kind, std::move(name), value);
    }
}

// Parse the inner content of a `symbols { ... }` block (without the outer
// braces).  Inner content is a series of `<kind> { <bindings> }` sub-blocks.
void parseSymbolsBlockInner(std::string_view inner, SymbolTable& out) {
    auto isWS = [](char c){ return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
    std::size_t i = 0;
    while (i < inner.size()) {
        while (i < inner.size() && isWS(inner[i])) ++i;
        if (i >= inner.size()) break;
        // Skip comments
        if (i + 1 < inner.size() && inner[i] == '/' && inner[i + 1] == '/') {
            while (i < inner.size() && inner[i] != '\n') ++i;
            continue;
        }
        if (i + 1 < inner.size() && inner[i] == '/' && inner[i + 1] == '*') {
            i += 2;
            while (i + 1 < inner.size() && !(inner[i] == '*' && inner[i + 1] == '/')) ++i;
            if (i + 1 < inner.size()) i += 2;
            continue;
        }
        if (!isIdentStart(inner[i])) {
            throw std::runtime_error(std::string{"symbols: expected kind identifier"});
        }
        std::size_t s = i;
        while (i < inner.size() && isIdentCont(inner[i])) ++i;
        std::string_view kindStr = inner.substr(s, i - s);
        auto kind = symKindFromSection(kindStr);
        if (!kind) {
            throw std::runtime_error(std::string{"symbols: unknown kind '"} + std::string{kindStr} + "'");
        }
        while (i < inner.size() && isWS(inner[i])) ++i;
        if (i >= inner.size() || inner[i] != '{') {
            throw std::runtime_error(std::string{"symbols: expected '{' after kind "} + std::string{kindStr});
        }
        ++i;
        int depth = 1;
        std::size_t bodyStart = i;
        while (i < inner.size() && depth > 0) {
            char c = inner[i];
            if (c == '{') ++depth;
            else if (c == '}') {
                --depth;
                if (depth == 0) break;
            }
            ++i;
        }
        std::string_view body = inner.substr(bodyStart, i - bodyStart);
        if (i < inner.size()) ++i; // skip `}`
        parseKindBlock(*kind, body, out);
    }
}

// `<ident>:` on its own line is a label declaration.  Records position
// in the enclosing section's labelMap during pass 1.  The legacy
// `L_<hex>:` form is just an identifier shape too -- it lands in the map
// alongside named labels.
bool isLabelDecl(std::string_view line, std::string& outName) {
    if (line.empty() || !isIdentStart(line[0])) return false;
    std::size_t i = 1;
    while (i < line.size() && isIdentCont(line[i])) ++i;
    if (i >= line.size() || line[i] != ':') return false;
    if (!trim(line.substr(i + 1)).empty()) return false;
    outName.assign(line.substr(0, i));
    return true;
}

// Compile-time integer expression evaluator.  Supports `+ - * / %`, parens,
// unary `+/-`, decimal and 0xHEX literals, and identifiers resolved via the
// given map (typically the per-script `const` table).  Used for the RHS of
// `const NAME = ...;` declarations.  Operands inside opcode calls are NOT
// routed through this -- they continue to use the existing per-opcode parsers,
// which see the post-substitution literal form.
struct ExprParser {
    std::string_view s;
    std::size_t p = 0;
    const std::unordered_map<std::string, int>* consts;

    void skipWS() { while (p < s.size() && (s[p]==' '||s[p]=='\t')) ++p; }

    int parseExpr() {
        int left = parseTerm();
        for (;;) {
            skipWS();
            if (p < s.size() && (s[p]=='+' || s[p]=='-')) {
                char op = s[p++];
                int right = parseTerm();
                left = (op == '+') ? left + right : left - right;
            } else break;
        }
        return left;
    }
    int parseTerm() {
        int left = parseFactor();
        for (;;) {
            skipWS();
            if (p < s.size() && (s[p]=='*' || s[p]=='/' || s[p]=='%')) {
                char op = s[p++];
                int right = parseFactor();
                if (op == '*') left = left * right;
                else if (op == '/') {
                    if (right == 0) throw std::runtime_error("const expr: division by zero");
                    left = left / right;
                } else {
                    if (right == 0) throw std::runtime_error("const expr: modulo by zero");
                    left = left % right;
                }
            } else break;
        }
        return left;
    }
    int parseFactor() {
        skipWS();
        if (p >= s.size()) throw std::runtime_error("const expr: expected term");
        char c = s[p];
        if (c == '-') { ++p; return -parseFactor(); }
        if (c == '+') { ++p; return parseFactor(); }
        if (c == '(') {
            ++p;
            int v = parseExpr();
            skipWS();
            if (p >= s.size() || s[p] != ')') throw std::runtime_error("const expr: expected `)`");
            ++p;
            return v;
        }
        if (c == '0' && p + 1 < s.size() && (s[p+1]=='x' || s[p+1]=='X')) {
            p += 2;
            int v = 0;
            std::size_t st = p;
            while (p < s.size()) {
                char d = s[p];
                if (d>='0'&&d<='9')      v = v * 16 + (d - '0');
                else if (d>='a'&&d<='f') v = v * 16 + (d - 'a' + 10);
                else if (d>='A'&&d<='F') v = v * 16 + (d - 'A' + 10);
                else break;
                ++p;
            }
            if (p == st) throw std::runtime_error("const expr: bad hex literal");
            return v;
        }
        if (c >= '0' && c <= '9') {
            int v = 0;
            while (p < s.size() && s[p] >= '0' && s[p] <= '9') {
                v = v * 10 + (s[p] - '0');
                ++p;
            }
            return v;
        }
        if (isIdentStart(c)) {
            std::size_t st = p++;
            while (p < s.size() && isIdentCont(s[p])) ++p;
            std::string_view ident = s.substr(st, p - st);

            // `Kind.Name` -- resolve via the global symbol table.
            if (p < s.size() && s[p] == '.') {
                std::size_t nst = ++p;
                while (p < s.size() && isIdentCont(s[p])) ++p;
                std::string_view nm = s.substr(nst, p - nst);
                auto k = symKindFromLabel(ident);
                if (!k) {
                    throw std::runtime_error("const expr: unknown kind `"
                        + std::string{ident} + "`");
                }
                int v;
                if (!lookupBareNameInScope(g_localSyms, *k, nm, v)) {
                    throw std::runtime_error("const expr: unknown "
                        + std::string{ident} + "." + std::string{nm});
                }
                return v;
            }
            // `Kind(N)` -- explicit-cast literal; recursively parse the inner
            // expression so `Trigger(707)..Trigger(713)` works as a range and
            // `Trigger(BASE + 1)` works once BASE is a const.
            skipWS();
            if (p < s.size() && s[p] == '(') {
                if (auto k = symKindFromLabel(ident)) {
                    (void)k;
                    ++p;
                    int v = parseExpr();
                    skipWS();
                    if (p >= s.size() || s[p] != ')') {
                        throw std::runtime_error("const expr: expected `)` after `"
                            + std::string{ident} + "(...`");
                    }
                    ++p;
                    return v;
                }
            }

            std::string name{ident};
            auto it = consts->find(name);
            if (it == consts->end()) {
                throw std::runtime_error("const expr: unknown identifier `" + name + "`");
            }
            return it->second;
        }
        throw std::runtime_error("const expr: unexpected character");
    }
};

int evalIntExpr(std::string_view s, const std::unordered_map<std::string, int>& consts) {
    ExprParser ep{s, 0, &consts};
    int v = ep.parseExpr();
    ep.skipWS();
    if (ep.p != s.size()) throw std::runtime_error("const expr: trailing junk in `" + std::string{s} + "`");
    return v;
}

} // namespace

ContainerAST parseSource(std::string_view text) {
    ContainerAST ast;
    ast.kind = AsmKind::Maphead;
    ast.alignment = 0x800;

    ScriptAST* curScript = nullptr;
    std::vector<ScriptAST> scriptsAccum;
    SecAST curSec;
    bool inSection = false;
    std::vector<std::string> curSectionOrder;
    bool hasSectionOrder = false;
    std::vector<std::string> pendingLabels;
    int nextSwitchId = 0;
    int nextLoopId   = 0;
    int nextIfId     = 0;
    int nextBlockId  = 0;

    // File-scope `const NAME = <expr>;` bindings, substituted into every
    // subsequent line at pull time.  `constsStr` caches the value as text
    // so the per-line substitution loop doesn't re-render `to_string`.
    std::unordered_map<std::string, int> consts;
    std::unordered_map<std::string, std::string> constsStr;

    // File-scope `const NAME = [v1, v2, ...];` array bindings.  Used by
    // `for X in NAME { body }` to unroll over a named list.  Different
    // namespace from `consts` (integer scalars) so a name can be either
    // an integer or an array but not both.
    std::unordered_map<std::string, std::vector<std::string>> arrayConsts;

    // User-defined macros: `macro <name>(<params>) { body }`.  Invocation
    // expands the body with positional-arg substitution (word-boundary,
    // string-literal-safe via substituteIdent).  Nested macro calls work
    // because expanded lines re-enter the main pull loop.
    // Params may carry a kind annotation (`name: Kind` or `name: Kind[]`).
    // At invocation, typed scalar args are resolved to a numeric literal in
    // the named kind before body substitution.  Array-typed args (`Kind[]`)
    // must be a `[...]` literal; each element is resolved in `Kind` and the
    // list is reassembled as `[v1, v2, ...]` for the body.
    struct MacroParam {
        std::string name;
        std::optional<SymKind> kind;
        bool isArray = false;
        // When `kind2` is set, this is a pair-array param of type
        // `(kind, kind2)[]`.  The accepted literal form is a `[K=>V, ...]`
        // list; each K resolves in `kind`, each V in `kind2`.  The body
        // sees the array as bracketed `[K=>V, ...]` after resolution, so
        // a destructuring `for a, b in <param>` can pick the pairs apart.
        std::optional<SymKind> kind2;
        // `name: Kind = <expr>` -- omitted call-site args are filled with
        // this raw text, which then flows through the same typed-arg
        // resolution as an explicit literal would.  Once a param has a
        // default, all params after it must also have one (so positional
        // binding stays unambiguous).
        std::optional<std::string> defaultExpr;
    };
    struct MacroDef {
        std::vector<MacroParam> params;
        std::vector<std::string> bodyLines;
    };
    std::unordered_map<std::string, MacroDef> macros;

    // `symbols { ... }` block collection state.  We're line-based; the block
    // may span many lines, so we accumulate raw text and track brace depth
    // until the outer `}` closes it, then sub-parse.
    bool inSymbolsBlock = false;
    int symbolsBraceDepth = 0;
    std::string symbolsBuffer;
    ScriptAST* symbolsTargetScript = nullptr;

    // Pull-based line iteration so macro expansions (for-loop unroll,
    // choice desugar) can push synthesized lines to the front of the queue.
    // Each pending line carries the (file, line) origin so that synthesized
    // lines inherit the location of the macro that produced them.
    struct PendingLine {
        std::string text;
        std::string srcFile;   // empty until first #line directive
        int         srcLine = 0;
    };
    std::deque<PendingLine> pendingLines;
    std::string curFile;       // updated by `#line N "file"` directives
    int curLine = 1;           // 1-based line of the next byte to pull from `text`
    PendingLine current;       // populated by pullLine; valid until next call
    std::size_t pos = 0;
    auto pullLine = [&]() -> bool {
        if (!pendingLines.empty()) {
            current = std::move(pendingLines.front());
            pendingLines.pop_front();
            return true;
        }
        if (pos >= text.size()) return false;
        current.srcFile = curFile;
        current.srcLine = curLine;
        std::size_t nl = text.find('\n', pos);
        if (nl == std::string_view::npos) {
            current.text.assign(text.substr(pos));
            pos = text.size();
        } else {
            current.text.assign(text.substr(pos, nl - pos));
            pos = nl + 1;
        }
        ++curLine;
        return true;
    };

    auto substituteIdent = [](std::string_view src, std::string_view name, std::string_view value) -> std::string {
        std::string out;
        out.reserve(src.size());
        bool inStr = false;
        for (std::size_t i = 0; i < src.size(); ) {
            char c = src[i];
            if (inStr) {
                if (c == '\\' && i + 1 < src.size()) { out += c; out += src[i + 1]; i += 2; continue; }
                if (c == '"') inStr = false;
                out += c; ++i; continue;
            }
            if (c == '"') { inStr = true; out += c; ++i; continue; }
            bool atBoundary = (i == 0 || !isIdentCont(src[i - 1]));
            if (atBoundary
                && src.size() - i >= name.size()
                && std::memcmp(src.data() + i, name.data(), name.size()) == 0
                && (i + name.size() == src.size() || !isIdentCont(src[i + name.size()]))) {
                // Skip when the identifier is in a position where it shouldn't
                // be a value:
                //   * field-name `name:` -- `roll(pstat: slot, max: max)`
                //     uses `max` as both a field name and a value; only the
                //     value side should substitute, else we get `99: 99`.
                //   * call-site `name(...)` -- a param like `delay` would
                //     otherwise shadow the opcode wrapper `delay(...)` in the
                //     body, yielding `<value>(...)`.  This language has no
                //     first-class call values, so call-position never wants
                //     parameter substitution.
                std::size_t afterIdent = i + name.size();
                std::size_t scan = afterIdent;
                while (scan < src.size() && (src[scan] == ' ' || src[scan] == '\t')) ++scan;
                if (scan < src.size() && (src[scan] == ':' || src[scan] == '(')) {
                    out += c; ++i;
                    continue;
                }
                out.append(value);
                i += name.size();
            } else {
                out += c; ++i;
            }
        }
        return out;
    };

    auto finalizeSection = [&]() {
        if (inSection && curScript) {
            // Labels left pending after the last instruction point to section end.
            curSec.trailingLabels = std::move(pendingLabels);
            pendingLabels.clear();
            curScript->sections.push_back(std::move(curSec));
        }
        pendingLabels.clear();
        inSection = false;
        curSec = SecAST{};
    };
    auto finalizeScript = [&]() {
        finalizeSection();
        if (curScript) {
            if (hasSectionOrder) {
                reorderSectionsByLabels(curScript->sections, curSectionOrder);
            }
            scriptsAccum.push_back(std::move(*curScript));
            delete curScript;
            curScript = nullptr;
        }
        hasSectionOrder = false;
        curSectionOrder.clear();
    };

    while (pullLine()) {
        // Apply const substitution before any other parsing.  Skipped inside
        // `symbols { ... }` accumulation since those blocks have their own
        // grammar where bare identifiers are names, not values.
        if (!inSymbolsBlock && !constsStr.empty()) {
            std::string subbed = current.text;
            for (const auto& [name, valStr] : constsStr) {
                subbed = substituteIdent(subbed, name, valStr);
            }
            current.text = std::move(subbed);
        }

        std::string_view raw = current.text;
        if (!raw.empty() && raw.back() == '\r') raw.remove_suffix(1);
        std::string_view stripped = stripLineComment(raw);

        // `#line N "file"` (preprocessor-style) -- resets the location used to
        // stamp subsequent instructions.  Generated by readScriptDir() in main
        // so per-section source paths survive concatenation.
        {
            std::string_view tl0 = trim(stripped);
            if (startsWith(tl0, "#line")) {
                std::string_view r = trim(tl0.substr(5));
                int n = 0;
                while (!r.empty() && r.front() >= '0' && r.front() <= '9') {
                    n = n * 10 + (r.front() - '0');
                    r.remove_prefix(1);
                }
                if (n > 0) curLine = n;
                std::string_view rt = trim(r);
                if (rt.size() >= 2 && rt.front() == '"') {
                    std::size_t q = rt.find('"', 1);
                    if (q != std::string_view::npos) {
                        curFile.assign(rt.substr(1, q - 1));
                    }
                }
                continue;
            }
        }
        // Capture the origin of THIS line for stamping Instrs / synthesized
        // macro expansions.
        const std::string originFile = current.srcFile;
        const int         originLine = current.srcLine;
        int               originCol  = 1;
        for (std::size_t i = 0; i < raw.size(); ++i) {
            if (raw[i] != ' ' && raw[i] != '\t') { originCol = static_cast<int>(i) + 1; break; }
        }

        // Accumulation pass for an ongoing `symbols { ... }` block.
        if (inSymbolsBlock) {
            for (char c : stripped) {
                if (c == '{') symbolsBraceDepth++;
                else if (c == '}') symbolsBraceDepth--;
            }
            symbolsBuffer.append(stripped.data(), stripped.size());
            symbolsBuffer.push_back('\n');
            if (symbolsBraceDepth <= 0) {
                std::size_t lb = symbolsBuffer.find('{');
                std::size_t rb = symbolsBuffer.rfind('}');
                if (lb != std::string::npos && rb != std::string::npos && rb > lb && symbolsTargetScript) {
                    parseSymbolsBlockInner(
                        std::string_view{symbolsBuffer}.substr(lb + 1, rb - lb - 1),
                        symbolsTargetScript->localSymbols);
                }
                inSymbolsBlock = false;
                symbolsBuffer.clear();
                symbolsBraceDepth = 0;
                symbolsTargetScript = nullptr;
            }
            continue;
        }

        std::string_view line = trim(stripped);
        if (line.empty()) continue;

        // `function <name>(<p>, ...) { body }` -- user-defined parse-time
        // macro.  File-scope.  Invocations are detected later in the loop
        // and expand the body with positional argument substitution.
        if (startsWith(line, "function")
            && (line.size() == 8 || line[8] == ' ' || line[8] == '\t')) {
            std::string_view r = trim(line.substr(8));
            std::string_view mnameView = leadingIdent(r);
            if (mnameView.empty()) throw std::runtime_error("function: expected name");
            // Copy out of `current.text` immediately -- pullLine() below
            // mutates that buffer, invalidating any string_views into it.
            std::string mname{mnameView};
            r.remove_prefix(mnameView.size());
            r = trim(r);
            if (r.empty() || r[0] != '(') throw std::runtime_error("function: expected '('");
            std::size_t rp = findMatchingRparen(r, 0);
            if (rp == std::string_view::npos) throw std::runtime_error("function: unmatched '('");
            auto paramTokens = splitTopCommas(r.substr(1, rp - 1));
            std::vector<MacroParam> params;
            for (auto p : paramTokens) {
                std::string_view tp = trim(p);
                if (tp.empty()) continue;
                // `[PreferNamed]` prefix is a disasm-only annotation (emits the
                // arg with `name:` styling at the matched call site).  Stripped
                // here; the assembler treats the param identically either way.
                if (startsWith(tp, "[PreferNamed]")) {
                    tp = trim(tp.substr(std::string_view{"[PreferNamed]"}.size()));
                }
                // Split off `= <default>` at top level (skip `==`, `=>`, and
                // anything nested in `[]`/`()`/`{}`).  The default text is
                // stored raw and substituted at call sites where the param
                // was omitted, then flows through the same resolution as an
                // explicit literal would.
                std::optional<std::string> defaultExpr;
                {
                    int bd = 0, pd = 0, cd = 0;
                    std::size_t eq = std::string_view::npos;
                    for (std::size_t i = 0; i < tp.size(); ++i) {
                        char c = tp[i];
                        if (c == '[') ++bd;
                        else if (c == ']') --bd;
                        else if (c == '(') ++pd;
                        else if (c == ')') --pd;
                        else if (c == '{') ++cd;
                        else if (c == '}') --cd;
                        else if (c == '=' && bd == 0 && pd == 0 && cd == 0) {
                            char nx = (i + 1 < tp.size()) ? tp[i + 1] : '\0';
                            char pv = (i > 0) ? tp[i - 1] : '\0';
                            if (nx == '=' || nx == '>' || pv == '=' || pv == '!' || pv == '<' || pv == '>') continue;
                            eq = i;
                            break;
                        }
                    }
                    if (eq != std::string_view::npos) {
                        defaultExpr = std::string{trim(tp.substr(eq + 1))};
                        tp = trim(tp.substr(0, eq));
                    }
                }
                // `name`            -- untyped pass-through
                // `name: Kind`      -- scalar typed (resolves to numeric)
                // `name: Kind[]`    -- array typed (resolves each element)
                std::size_t colon = tp.find(':');
                if (colon == std::string_view::npos) {
                    params.push_back({std::string{tp}, std::nullopt, false, std::nullopt, defaultExpr});
                } else {
                    std::string_view pn = trim(tp.substr(0, colon));
                    std::string_view kt = trim(tp.substr(colon + 1));
                    bool isArr = false;
                    if (kt.size() >= 2 && kt.substr(kt.size() - 2) == "[]") {
                        isArr = true;
                        kt = trim(kt.substr(0, kt.size() - 2));
                    }
                    // `(K1, K2)` pair type -- requires the `[]` array suffix
                    // (a non-array pair param has no expression form to bind
                    // to, so we reject it).
                    if (!kt.empty() && kt.front() == '(' && kt.back() == ')') {
                        if (!isArr) {
                            throw std::runtime_error(std::string{"function "} + mname
                                + ": pair type `" + std::string{kt}
                                + "` must be array (`(K1, K2)[]`) on param `"
                                + std::string{pn} + "`");
                        }
                        std::string_view inner = trim(kt.substr(1, kt.size() - 2));
                        auto pieces = splitTopCommas(inner);
                        if (pieces.size() != 2) {
                            throw std::runtime_error(std::string{"function "} + mname
                                + ": pair type expects exactly 2 kinds in `("
                                + std::string{inner} + ")`");
                        }
                        std::string_view ka = trim(pieces[0]);
                        std::string_view kb = trim(pieces[1]);
                        auto k1 = symKindFromLabel(ka);
                        auto k2 = symKindFromLabel(kb);
                        if (!k1 || !k2) {
                            throw std::runtime_error(std::string{"function "} + mname
                                + ": unknown kind in pair `(" + std::string{ka}
                                + ", " + std::string{kb} + ")`");
                        }
                        params.push_back({std::string{pn}, k1, true, k2, defaultExpr});
                    } else if (kt == "int") {
                        params.push_back({std::string{pn}, std::nullopt, isArr, std::nullopt, defaultExpr});
                    } else {
                        auto k = symKindFromLabel(kt);
                        if (!k) {
                            throw std::runtime_error(std::string{"function "} + mname
                                + ": unknown kind `" + std::string{kt}
                                + "` on param `" + std::string{pn} + "`");
                        }
                        params.push_back({std::string{pn}, k, isArr, std::nullopt, defaultExpr});
                    }
                }
            }
            // Enforce: once a param has a default, all subsequent params
            // must also have one.  Otherwise positional binding is ambiguous
            // (we'd have to decide whether `foo(1, 2)` skips the defaulted
            // middle param or fills it).
            {
                bool sawDefault = false;
                for (const auto& mp : params) {
                    if (mp.defaultExpr.has_value()) sawDefault = true;
                    else if (sawDefault) {
                        throw std::runtime_error(std::string{"function "} + mname
                            + ": param `" + mp.name
                            + "` has no default but follows a defaulted param");
                    }
                }
            }
            std::string rRest{trim(r.substr(rp + 1))};
            // `{` might be on the same line or a later one.
            while (rRest.empty() || rRest[0] != '{') {
                if (!pullLine()) throw std::runtime_error("function: missing '{'");
                std::string_view raw2 = stripLineComment(current.text);
                if (!raw2.empty() && raw2.back() == '\r') raw2.remove_suffix(1);
                rRest.assign(trim(raw2));
            }
            // Collect body until matching `}`.
            std::string body;
            int depth = 1;
            for (std::size_t i = 1; i < rRest.size(); ++i) {
                char c = rRest[i];
                if (c == '{') ++depth;
                else if (c == '}') { --depth; if (depth == 0) break; }
                body += c;
            }
            while (depth > 0) {
                if (!pullLine()) throw std::runtime_error("function: unterminated body");
                std::string_view raw2 = stripLineComment(current.text);
                if (!raw2.empty() && raw2.back() == '\r') raw2.remove_suffix(1);
                body += '\n';
                for (char c : raw2) {
                    if (c == '{') ++depth;
                    else if (c == '}') { --depth; if (depth == 0) break; }
                    body += c;
                }
            }
            // Split body into lines (drop empties).  Each newline-bounded
            // line is then further split on top-level `;` so single-line
            // bodies like `{ a(); b(); c(); }` produce one statement per
            // entry -- matching what the dispatcher expects (one statement
            // per pulled line).  Top-level `{...}` blocks (e.g. `for x in [...]
            // { ... }`) stay grouped: splitTopSemis honours brace depth.
            std::vector<std::string> bodyLines;
            std::size_t pos2 = 0;
            while (pos2 < body.size()) {
                std::size_t nl = body.find('\n', pos2);
                std::string_view ln = (nl == std::string::npos)
                    ? std::string_view{body}.substr(pos2)
                    : std::string_view{body}.substr(pos2, nl - pos2);
                if (!trim(ln).empty()) {
                    for (auto piece : splitTopSemis(ln)) {
                        std::string_view tp = trim(piece);
                        if (!tp.empty()) bodyLines.emplace_back(tp);
                    }
                }
                if (nl == std::string::npos) break;
                pos2 = nl + 1;
            }
            macros[std::move(mname)] = MacroDef{std::move(params), std::move(bodyLines)};
            continue;
        }

        // `const NAME = <expr>;`        -- file-scope integer constant.
        // `const NAME = [v, v, ...];`     -- file-scope array constant.
        // The array form is consumed by `for X in NAME { body }` for
        // unroll iteration.  Integer constants are substituted textually
        // into subsequent lines as decimal literals.
        if (startsWith(line, "const")
            && (line.size() == 5 || line[5] == ' ' || line[5] == '\t')) {
            std::string_view r = trim(line.substr(5));
            std::string_view name = leadingIdent(r);
            if (name.empty()) throw std::runtime_error("const: expected identifier");
            std::string_view rest = trim(r.substr(name.size()));
            if (rest.empty() || rest[0] != '=') throw std::runtime_error("const: expected `=` after name");
            std::string_view expr = trim(rest.substr(1));
            if (!expr.empty() && expr.back() == ';') { expr.remove_suffix(1); expr = trim(expr); }
            if (expr.empty()) throw std::runtime_error("const: empty RHS");
            if (expr.front() == '[' && expr.back() == ']') {
                auto items = splitTopCommas(expr.substr(1, expr.size() - 2));
                std::vector<std::string> values;
                for (auto v : items) {
                    std::string_view t = trim(v);
                    if (!t.empty()) values.emplace_back(t);
                }
                arrayConsts[std::string{name}] = std::move(values);
            } else {
                int value = evalIntExpr(expr, consts);
                std::string key{name};
                constsStr[key] = std::to_string(value);
                consts[std::move(key)] = value;
            }
            continue;
        }

        // `symbols { ... }` block (file-scope; attaches to current script).
        if (startsWith(line, "symbols")
            && (line.size() == 7 || line[7] == ' ' || line[7] == '\t' || line[7] == '{')) {
            if (!curScript) {
                throw std::runtime_error("symbols block before #pragma script");
            }
            inSymbolsBlock = true;
            symbolsTargetScript = curScript;
            symbolsBraceDepth = 0;
            symbolsBuffer.clear();
            for (char c : stripped) {
                if (c == '{') symbolsBraceDepth++;
                else if (c == '}') symbolsBraceDepth--;
            }
            symbolsBuffer.append(stripped.data(), stripped.size());
            symbolsBuffer.push_back('\n');
            if (symbolsBraceDepth <= 0) {
                std::size_t lb = symbolsBuffer.find('{');
                std::size_t rb = symbolsBuffer.rfind('}');
                if (lb != std::string::npos && rb != std::string::npos && rb > lb) {
                    parseSymbolsBlockInner(
                        std::string_view{symbolsBuffer}.substr(lb + 1, rb - lb - 1),
                        symbolsTargetScript->localSymbols);
                }
                inSymbolsBlock = false;
                symbolsBuffer.clear();
                symbolsBraceDepth = 0;
                symbolsTargetScript = nullptr;
            }
            continue;
        }

        // `#pragma <tag> <rest>` directives.
        if (startsWith(line, "#pragma")) {
            std::string_view body = trim(line.substr(7));
            std::size_t firstSp = body.find(' ');
            std::string_view tag = (firstSp == std::string_view::npos) ? body : body.substr(0, firstSp);
            std::string_view rest = (firstSp == std::string_view::npos) ? std::string_view{} : body.substr(firstSp + 1);

            if (tag == "container") {
                // bare marker
            } else if (tag == "alignment") {
                ast.alignment = static_cast<u32>(parseNum(trim(rest)));
            } else if (tag == "file") {
                ast.kind = AsmKind::DG;
                auto parts = splitWhitespace(trim(rest));
                if (parts.size() < 2) throw std::runtime_error(std::string{"bad #pragma file: "} + std::string{rest});
                ast.files.push_back({ parseNum(parts[0]), std::string{parts[1]} });
            } else if (tag == "script") {
                finalizeScript();
                auto kv = parseKV(rest);
                curScript = new ScriptAST{};
                auto getI = [&](const char* key, int dflt) -> int {
                    auto it = kv.find(key);
                    return it == kv.end() ? dflt : parseNum(it->second);
                };
                curScript->index = getI("index", 0);
                curScript->startOffset = static_cast<std::size_t>(getI("start", 0));
                curScript->endOffset = static_cast<std::size_t>(getI("end", 0));
                curScript->headerU16 = static_cast<u16>(getI("headerU16", 0));
                curScript->sentinelOff = static_cast<u16>(getI("sentinelOff", 0));
            } else if (tag == "sections") {
                curSectionOrder.clear();
                for (auto tok : splitWhitespace(trim(rest))) curSectionOrder.emplace_back(tok);
                hasSectionOrder = true;
            }
            continue;
        }

        // `section <name>(<id>[, 0x<dis>]) {`
        {
            std::string secName;
            int secId; bool hasDis; u16 dis;
            if (matchSectionHeader(line, secName, secId, hasDis, dis)) {
                finalizeSection();
                curSec = SecAST{};
                curSec.id = secId;
                curSec.hasDisambig = hasDis;
                curSec.disambig = dis;
                // Drop default name so we don't store useless overrides.
                if (secName != "section_" + toDec(secId) && secName != ON_ENTER_LABEL) {
                    // For duplicates the default is "section_<id>_at_<4hex>".
                    std::string dupDefault = "section_" + toDec(secId) + "_at_" + toHexPadded(dis, 4);
                    if (!hasDis || secName != dupDefault) {
                        curSec.name = std::move(secName);
                    }
                }
                inSection = true;
                continue;
            }
        }

        // Section close brace.
        if (line == "}") {
            finalizeSection();
            continue;
        }

        // Label decl -- informational only.
        {
            std::string labelName;
            if (isLabelDecl(line, labelName)) {
                if (inSection) pendingLabels.push_back(std::move(labelName));
                continue;
            }
        }

        // `switch <ident> { K -> { body } K -> { body } ... }` -- block-bodied
        // switch with multi-statement case bodies.  Distinguished from the
        // traditional `switch (pstat[X]) { case K: goto L; }` form by the
        // absence of `(` after the `switch` keyword.
        if (inSection && startsWith(line, "switch")
            && (line.size() == 6 || line[6] == ' ' || line[6] == '\t')) {
            std::string_view r0 = trim(line.substr(6));
            if (!r0.empty() && r0[0] != '(') {
                // Scrutinee accepts three forms:
                //   `pstat[<expr>]`  -- explicit (preferred; matches the
                //                       corpus's eq-chain `if (pstat[...])` shape)
                //   `<ident>`        -- wrapped as `pstat[<ident>]`
                //   `<integer>`      -- wrapped as `pstat[<integer>]`
                // The captured value `ident` is the expression *inside* the
                // brackets -- it's interpolated into `pstat[<ident>]` later.
                std::string_view identView = leadingIdent(r0);
                std::size_t consumed = 0;
                if (!identView.empty() && identView == "pstat") {
                    std::size_t i = identView.size();
                    while (i < r0.size() && (r0[i] == ' ' || r0[i] == '\t')) ++i;
                    if (i >= r0.size() || r0[i] != '[') {
                        throw std::runtime_error("switch: expected `[` after `pstat`");
                    }
                    std::size_t lb2 = i;
                    std::size_t rb2 = r0.find(']', lb2);
                    if (rb2 == std::string_view::npos) {
                        throw std::runtime_error("switch: unterminated `pstat[...]`");
                    }
                    identView = trim(r0.substr(lb2 + 1, rb2 - lb2 - 1));
                    if (identView.empty()) {
                        throw std::runtime_error("switch: empty `pstat[]` index");
                    }
                    consumed = rb2 + 1;
                } else if (!identView.empty()) {
                    consumed = identView.size();
                } else {
                    // Bare integer pstat index (e.g. `switch 117 { ... }`).
                    std::size_t n = 0;
                    while (n < r0.size() && r0[n] >= '0' && r0[n] <= '9') ++n;
                    if (n == 0) {
                        throw std::runtime_error("switch: expected `pstat[...]`, identifier, integer, or `(` expression");
                    }
                    identView = r0.substr(0, n);
                    consumed = n;
                }
                // pullLine() below invalidates views into the original line;
                // copy out before any pulls happen.
                std::string ident{identView};
                std::string_view rest = trim(r0.substr(consumed));
                if (rest.empty() || rest[0] != '{') {
                    // `{` might be on the next line.
                    while (rest.empty() || rest[0] != '{') {
                        if (!pullLine()) throw std::runtime_error("switch: missing `{`");
                        std::string_view raw2 = stripLineComment(current.text);
                        if (!raw2.empty() && raw2.back() == '\r') raw2.remove_suffix(1);
                        rest = trim(raw2);
                    }
                }
                // rest starts with `{`. Collect block content until matching `}`.
                std::string blockBody;
                int depth = 1;
                for (std::size_t i = 1; i < rest.size(); ++i) {
                    char c = rest[i];
                    if (c == '{') depth++;
                    else if (c == '}') { depth--; if (depth == 0) break; }
                    blockBody += c;
                }
                while (depth > 0) {
                    if (!pullLine()) throw std::runtime_error("switch: unterminated block");
                    std::string_view raw2 = stripLineComment(current.text);
                    if (!raw2.empty() && raw2.back() == '\r') raw2.remove_suffix(1);
                    blockBody += '\n';
                    for (char c : raw2) {
                        if (c == '{') depth++;
                        else if (c == '}') { depth--; if (depth == 0) break; }
                        blockBody += c;
                    }
                }

                // Parse cases.  Two arrow forms:
                //   `<key> -> { <body> }`  -- 0x18 jumptable (positional 0..N-1)
                //   `<key> => { <body> }`  -- 0x19 eq-chain (arbitrary keys)
                //   `else <key> => { <body> }` -- last-arm marker for eq-chain
                //     (purely visual; emits same bytes as a regular `=>` arm)
                // A single switch must use one arrow type throughout.
                struct Case { std::string key; std::string body; bool isElse; };
                std::vector<Case> cases;
                bool isFatMode = false;
                bool committedArrow = false;
                std::size_t p = 0;
                auto isWS = [](char c){ return c==' '||c=='\t'||c=='\n'||c=='\r'; };
                while (p < blockBody.size()) {
                    while (p < blockBody.size() && (isWS(blockBody[p]) || blockBody[p]==';' || blockBody[p]==',')) ++p;
                    if (p >= blockBody.size()) break;

                    bool isElse = false;
                    if (p + 4 <= blockBody.size()
                        && blockBody.compare(p, 4, "else") == 0
                        && (p + 4 == blockBody.size() || isWS(blockBody[p+4]))) {
                        isElse = true;
                        p += 4;
                        while (p < blockBody.size() && isWS(blockBody[p])) ++p;
                    }

                    std::size_t kStart = p;
                    if (p < blockBody.size() && blockBody[p] == '-') ++p;
                    while (p < blockBody.size() && blockBody[p] >= '0' && blockBody[p] <= '9') ++p;
                    std::string key{blockBody.substr(kStart, p - kStart)};
                    if (key.empty()) throw std::runtime_error("switch: expected case key");
                    while (p < blockBody.size() && isWS(blockBody[p])) ++p;
                    if (p + 1 >= blockBody.size()) {
                        throw std::runtime_error("switch: expected `->` or `=>` after case key");
                    }
                    bool armIsFat;
                    if (blockBody[p] == '-' && blockBody[p+1] == '>') {
                        armIsFat = false;
                    } else if (blockBody[p] == '=' && blockBody[p+1] == '>') {
                        armIsFat = true;
                    } else {
                        throw std::runtime_error("switch: expected `->` or `=>` after case key");
                    }
                    if (!committedArrow) {
                        committedArrow = true;
                        isFatMode = armIsFat;
                    } else if (armIsFat != isFatMode) {
                        throw std::runtime_error("switch: cannot mix `->` and `=>` arrows in one switch");
                    }
                    if (isElse && !armIsFat) {
                        throw std::runtime_error("switch: `else` only allowed with `=>` arrows");
                    }
                    p += 2;
                    while (p < blockBody.size() && isWS(blockBody[p])) ++p;
                    if (p >= blockBody.size() || blockBody[p] != '{') {
                        throw std::runtime_error("switch: expected `{` for case body");
                    }
                    ++p;
                    int d = 1;
                    std::size_t bStart = p;
                    while (p < blockBody.size() && d > 0) {
                        if (blockBody[p] == '{') d++;
                        else if (blockBody[p] == '}') { d--; if (d == 0) break; }
                        ++p;
                    }
                    cases.push_back({ std::move(key), blockBody.substr(bStart, p - bStart), isElse });
                    if (p < blockBody.size()) ++p; // skip `}`
                }

                for (std::size_t k = 0; k + 1 < cases.size(); ++k) {
                    if (cases[k].isElse) throw std::runtime_error("switch: `else` arm must be last");
                }

                int swId = nextSwitchId++;
                std::string idTag = std::to_string(swId);
                std::vector<std::string> expanded;

                if (isFatMode) {
                    // Eq-chain (0x19) lowering: each arm becomes a bodied-if
                    // `if (pstat[ident] == K) { body }`.  The bodied-if parser
                    // takes it from there; bytes match a hand-written eq-chain.
                    // `else K =>` is treated identically -- it's a visual marker
                    // for "this is the catch-all"; bytes are the same because the
                    // last arm's bypass label naturally lands at the section's
                    // post-switch continuation.
                    for (const auto& c : cases) {
                        std::string line = "if (pstat[";
                        line += std::string{ident};
                        line += "] == ";
                        line += c.key;
                        line += ") {";
                        expanded.push_back(std::move(line));
                        for (auto piece : splitTopSemis(c.body)) {
                            std::string_view tp = trim(piece);
                            if (tp.empty()) continue;
                            expanded.emplace_back(std::string{tp} + ";");
                        }
                        expanded.push_back("}");
                    }

                    for (auto it = expanded.rbegin(); it != expanded.rend(); ++it) {
                        pendingLines.push_front(PendingLine{std::move(*it), originFile, originLine});
                    }
                    continue;
                }

                // Jumptable (0x18) lowering -- the original block-bodied form.
                {
                    std::string h = "switch (pstat[";
                    h += std::string{ident};
                    h += "]) { ";
                    for (std::size_t k = 0; k < cases.size(); ++k) {
                        if (k) h += "; ";
                        h += "case "; h += cases[k].key;
                        h += ": goto __sw"; h += idTag;
                        h += "_case"; h += std::to_string(k);
                    }
                    h += " };";
                    expanded.push_back(std::move(h));
                }

                std::string endLabel = "__sw" + idTag + "_end";
                for (std::size_t k = 0; k < cases.size(); ++k) {
                    expanded.push_back("__sw" + idTag + "_case" + std::to_string(k) + ":");
                    for (auto piece : splitTopSemis(cases[k].body)) {
                        std::string_view tp = trim(piece);
                        if (tp.empty()) continue;
                        expanded.emplace_back(std::string{tp} + ";");
                    }
                    expanded.push_back("goto " + endLabel + ";");
                }
                expanded.push_back(endLabel + ":");

                for (auto it = expanded.rbegin(); it != expanded.rend(); ++it) {
                    pendingLines.push_front(PendingLine{std::move(*it), originFile, originLine});
                }
                continue;
            }
            // else: traditional `switch (expr) {...}` -- fall through to statement handler.
        }

        // `loop { <body> }` -- infinite loop expressed via gotos.  `break;`
        // and `continue;` inside the body jump to a synthetic end / start
        // label respectively.  Nested `loop {}`s have their own scope, so
        // substitution skips body content inside any nested `loop {`.  Other
        // block-bodied constructs (`for`, `choice`, `switch`, ...) are NOT
        // skipped: their expansions inherit the enclosing loop's `break` /
        // `continue` once the expanded lines re-enter the line stream.
        if (inSection && startsWith(line, "loop")
            && (line.size() == 4 || line[4] == ' ' || line[4] == '\t' || line[4] == '{')) {
            std::size_t lb = line.find('{');
            std::string body;
            int depth = 1;
            if (lb != std::string_view::npos) {
                for (std::size_t i = lb + 1; i < line.size(); ++i) {
                    char c = line[i];
                    if (c == '{') depth++;
                    else if (c == '}') { depth--; if (depth == 0) break; }
                    body += c;
                }
            } else {
                while (true) {
                    if (!pullLine()) throw std::runtime_error("loop: missing '{'");
                    std::string_view raw2 = stripLineComment(current.text);
                    if (!raw2.empty() && raw2.back() == '\r') raw2.remove_suffix(1);
                    std::size_t b = raw2.find('{');
                    if (b != std::string_view::npos) {
                        for (std::size_t i = b + 1; i < raw2.size(); ++i) {
                            char c = raw2[i];
                            if (c == '{') depth++;
                            else if (c == '}') { depth--; if (depth == 0) break; }
                            body += c;
                        }
                        break;
                    }
                }
            }
            while (depth > 0) {
                if (!pullLine()) throw std::runtime_error("loop: unterminated body");
                std::string_view raw2 = current.text;
                if (!raw2.empty() && raw2.back() == '\r') raw2.remove_suffix(1);
                std::string_view s2 = stripLineComment(raw2);
                body += '\n';
                for (char c : s2) {
                    if (c == '{') depth++;
                    else if (c == '}') { depth--; if (depth == 0) break; }
                    body += c;
                }
            }

            int id = nextLoopId++;
            std::string startLabel = "_loop_start_" + std::to_string(id);
            std::string endLabel   = "_loop_end_"   + std::to_string(id);

            // Substitute `break` / `continue` at our enclosing-loop scope.
            // Brace scoping is two-axis: a nested `loop {` is BOTH a break
            // and a continue scope (intercepts both); a nested bare `{` is
            // a break scope only (intercepts break but lets continue pass
            // through to the outer loop).  Other braces are transparent.
            // String literals and `//` comments are skipped.
            std::string subBody;
            subBody.reserve(body.size());
            // Each entry: bit 0 = break-scope, bit 1 = continue-scope.
            std::vector<unsigned char> braceScope;
            auto inBreakScope = [&]() {
                for (unsigned char b : braceScope) if (b & 1) return true;
                return false;
            };
            auto inContinueScope = [&]() {
                for (unsigned char b : braceScope) if (b & 2) return true;
                return false;
            };
            bool inStr = false;
            for (std::size_t i = 0; i < body.size(); ) {
                char c = body[i];
                if (inStr) {
                    subBody += c;
                    if (c == '\\' && i + 1 < body.size()) { subBody += body[i + 1]; i += 2; continue; }
                    if (c == '"') inStr = false;
                    ++i; continue;
                }
                if (c == '"') { inStr = true; subBody += c; ++i; continue; }
                if (c == '/' && i + 1 < body.size() && body[i + 1] == '/') {
                    while (i < body.size() && body[i] != '\n') { subBody += body[i++]; }
                    continue;
                }
                if (c == '{') {
                    // Classify the brace:
                    //   loop `{`: break-scope AND continue-scope (intercepts both)
                    //   bare `{`: break-scope only (continue passes through)
                    //   other  : transparent
                    std::size_t e = i;
                    while (e > 0 && (body[e - 1] == ' ' || body[e - 1] == '\t')) --e;
                    bool isBareBrace = (e == 0 || body[e - 1] == '\n' || body[e - 1] == '\r');
                    std::size_t e2 = e;
                    while (e2 > 0 && (body[e2 - 1] == '\n' || body[e2 - 1] == '\r')) --e2;
                    bool isLoopBrace = false;
                    if (e2 >= 4 && body.compare(e2 - 4, 4, "loop") == 0
                        && (e2 == 4 || !isIdentCont(body[e2 - 5]))) {
                        isLoopBrace = true;
                    }
                    unsigned char flags = 0;
                    if (isLoopBrace) flags = 3;       // break + continue
                    else if (isBareBrace) flags = 1;  // break only
                    braceScope.push_back(flags);
                    subBody += c;
                    ++i; continue;
                }
                if (c == '}') {
                    if (!braceScope.empty()) braceScope.pop_back();
                    subBody += c;
                    ++i; continue;
                }
                if (isIdentStart(c)) {
                    std::size_t j = i;
                    while (j < body.size() && isIdentCont(body[j])) ++j;
                    std::string_view tok = std::string_view{body}.substr(i, j - i);
                    bool leftOk = (i == 0) || !isIdentCont(body[i - 1]);
                    if (leftOk) {
                        if (tok == "break" && !inBreakScope()) {
                            subBody += "goto ";
                            subBody += endLabel;
                            i = j;
                            continue;
                        }
                        if (tok == "continue" && !inContinueScope()) {
                            subBody += "goto ";
                            subBody += startLabel;
                            i = j;
                            continue;
                        }
                    }
                    subBody.append(tok);
                    i = j;
                    continue;
                }
                subBody += c;
                ++i;
            }

            // Push: start-label, body lines, back-edge goto, end-label.
            // Body lines are split on newlines (one statement per line is the
            // canonical form produced by the beautifier and used everywhere).
            std::vector<std::string> expanded;
            expanded.push_back(startLabel + ":");
            std::size_t st = 0;
            for (std::size_t k = 0; k <= subBody.size(); ++k) {
                if (k == subBody.size() || subBody[k] == '\n') {
                    std::string_view piece = trim(std::string_view{subBody}.substr(st, k - st));
                    if (!piece.empty()) expanded.emplace_back(piece);
                    st = k + 1;
                }
            }
            expanded.push_back("goto " + startLabel + ";");
            expanded.push_back(endLabel + ":");

            for (auto it = expanded.rbegin(); it != expanded.rend(); ++it) {
                pendingLines.push_front(PendingLine{std::move(*it), originFile, originLine});
            }
            continue;
        }

        // `if (X) goto A; else goto B;` -- two-way branch.  The corpus
        // encodes this NOT as the compact 0x19-opcode-with-else-target form,
        // but as a 4-instruction skip pattern:
        //   IF (NEG X) -> Lend; jump A; jump B; Lend: jump B;
        // (where the second `jump B` inside the if-body is a redundant
        // "filler" with target == else target.)  Since the corpus has
        // ZERO uses of the compact form, we always lower `; else goto`
        // to the verbose corpus form.  Expand here at parse time so the
        // encoder sees each instruction separately and offsets compute
        // naturally.  Falls back to encodeIfStmt's compact path if the
        // predicate negator can't handle the expression.
        if (inSection && startsWith(line, "if ")
            && line.find("; else goto ") != std::string_view::npos) {
            std::size_t lp = line.find('(');
            std::size_t rp = (lp != std::string_view::npos)
                                 ? findMatchingRparen(line, lp)
                                 : std::string_view::npos;
            std::size_t semi = (rp != std::string_view::npos)
                                   ? line.find("; else goto ", rp)
                                   : std::string_view::npos;
            if (rp != std::string_view::npos && semi != std::string_view::npos) {
                std::string_view exprPart = trim(line.substr(lp + 1, rp - lp - 1));
                std::string_view thenPart = trim(line.substr(rp + 1, semi - rp - 1));
                std::string_view elsePart = trim(line.substr(semi + 12));  // skip "; else goto "
                while (!elsePart.empty() && (elsePart.back() == ';' || elsePart.back() == ' ' || elsePart.back() == '\t')) {
                    elsePart.remove_suffix(1);
                }
                std::string thenLabel;
                if (startsWith(thenPart, "goto ")) {
                    thenLabel.assign(trim(thenPart.substr(5)));
                    // Strip trailing semicolon if any.
                    while (!thenLabel.empty() && (thenLabel.back() == ';' || thenLabel.back() == ' ' || thenLabel.back() == '\t')) {
                        thenLabel.pop_back();
                    }
                }
                std::string elseLabel{elsePart};
                if (!thenLabel.empty() && !elseLabel.empty()) {
                    std::string negCond;
                    bool negOk = false;
                    try {
                        negCond = predneg::negatePredicate(std::string{exprPart});
                        negOk = true;
                    } catch (...) {}
                    if (negOk) {
                        int id = nextIfId++;
                        std::string endLabel = "__if_else_skip_" + std::to_string(id);
                        std::vector<std::string> expanded;
                        expanded.push_back("if (" + negCond + ") goto " + endLabel + ";");
                        expanded.push_back("goto " + thenLabel + ";");
                        expanded.push_back("goto " + elseLabel + ";");
                        expanded.push_back(endLabel + ":");
                        expanded.push_back("goto " + elseLabel + ";");
                        for (auto it = expanded.rbegin(); it != expanded.rend(); ++it) {
                            pendingLines.push_front(PendingLine{std::move(*it), originFile, originLine});
                        }
                        continue;
                    }
                    // Negation failed: fall through to existing encodeIfStmt
                    // compact-form path.  (Won't match corpus bytes for the
                    // skip pattern, but we never round-trip a non-negatable
                    // predicate through this form anyway.)
                }
            }
        }

        // Bare `{ <body> }` -- break-scope (no looping).  `break;` inside
        // the body becomes `goto __block_end_<id>;` which the close `}`
        // anchors via a synthetic label.  Nested `loop {}` and nested
        // bare `{}` have their own scope, so substitution skips body
        // content inside any such inner break-scope.  Other block-bodied
        // constructs (`if`, `for`, `choice`, `switch`, ...) are
        // transparent -- a `break;` inside `block { if (X) { break; } }`
        // exits the outer block, not the if.
        if (inSection && !line.empty() && line[0] == '{') {
            std::string body;
            int depth = 1;
            for (std::size_t i = 1; i < line.size(); ++i) {
                char c = line[i];
                if (c == '{') depth++;
                else if (c == '}') { depth--; if (depth == 0) break; }
                body += c;
            }
            while (depth > 0) {
                if (!pullLine()) throw std::runtime_error("block: unterminated body");
                std::string_view raw2 = current.text;
                if (!raw2.empty() && raw2.back() == '\r') raw2.remove_suffix(1);
                std::string_view s2 = stripLineComment(raw2);
                body += '\n';
                for (char c : s2) {
                    if (c == '{') depth++;
                    else if (c == '}') { depth--; if (depth == 0) break; }
                    body += c;
                }
            }

            int id = nextBlockId++;
            std::string endLabel = "__block_end_" + std::to_string(id);

            // `break;` substitution mirrors the `loop {}` machinery: skip
            // body content inside any nested break-scope (loop or bare `{`).
            std::string subBody;
            subBody.reserve(body.size());
            std::vector<bool> scopeBraces;
            auto inNestedScope = [&]() {
                for (bool b : scopeBraces) if (b) return true;
                return false;
            };
            bool inStr = false;
            for (std::size_t i = 0; i < body.size(); ) {
                char c = body[i];
                if (inStr) {
                    subBody += c;
                    if (c == '\\' && i + 1 < body.size()) { subBody += body[i + 1]; i += 2; continue; }
                    if (c == '"') inStr = false;
                    ++i; continue;
                }
                if (c == '"') { inStr = true; subBody += c; ++i; continue; }
                if (c == '/' && i + 1 < body.size() && body[i + 1] == '/') {
                    while (i < body.size() && body[i] != '\n') { subBody += body[i++]; }
                    continue;
                }
                if (c == '{') {
                    std::size_t e = i;
                    while (e > 0 && (body[e - 1] == ' ' || body[e - 1] == '\t')) --e;
                    bool isBareBrace = (e == 0 || body[e - 1] == '\n' || body[e - 1] == '\r');
                    std::size_t e2 = e;
                    while (e2 > 0 && (body[e2 - 1] == '\n' || body[e2 - 1] == '\r')) --e2;
                    bool isLoopBrace = false;
                    if (e2 >= 4 && body.compare(e2 - 4, 4, "loop") == 0
                        && (e2 == 4 || !isIdentCont(body[e2 - 5]))) {
                        isLoopBrace = true;
                    }
                    scopeBraces.push_back(isLoopBrace || isBareBrace);
                    subBody += c;
                    ++i; continue;
                }
                if (c == '}') {
                    if (!scopeBraces.empty()) scopeBraces.pop_back();
                    subBody += c;
                    ++i; continue;
                }
                if (isIdentStart(c)) {
                    std::size_t j = i;
                    while (j < body.size() && isIdentCont(body[j])) ++j;
                    std::string_view tok = std::string_view{body}.substr(i, j - i);
                    bool leftOk = (i == 0) || !isIdentCont(body[i - 1]);
                    if (leftOk && !inNestedScope() && tok == "break") {
                        subBody += "goto ";
                        subBody += endLabel;
                        i = j;
                        continue;
                    }
                    subBody.append(tok);
                    i = j;
                    continue;
                }
                subBody += c;
                ++i;
            }

            std::vector<std::string> expanded;
            std::size_t st = 0;
            for (std::size_t k = 0; k <= subBody.size(); ++k) {
                if (k == subBody.size() || subBody[k] == '\n') {
                    std::string_view piece = trim(std::string_view{subBody}.substr(st, k - st));
                    if (!piece.empty()) expanded.emplace_back(piece);
                    st = k + 1;
                }
            }
            expanded.push_back(endLabel + ":");

            for (auto it = expanded.rbegin(); it != expanded.rend(); ++it) {
                pendingLines.push_front(PendingLine{std::move(*it), originFile, originLine});
            }
            continue;
        }

        // `if (<expr>) { <body> }` or `if (<expr>) { <body> } else { <body> }`
        // -- block form.
        //
        //   no-else: lowered to the engine's single-branch-skip shape via
        //            `if (negate(cond)) goto __if_end_N; <body> __if_end_N:`
        //            (no two-way jump).  Negator in predicate_neg.hpp.
        //   with-else: lowered to the two-way jump shape that encodeIfStmt
        //              already handles: `if (cond) goto __if_then_N; else
        //              goto __if_else_N; __if_then_N: <body_then>; goto
        //              __if_end_N; __if_else_N: <body_else>; __if_end_N:`.
        //              No negation needed (both arms jump unconditionally).
        //
        // Disambiguates from the legacy `if (<expr>) goto <label>;` form by
        // requiring `{` after the closing `)`.  `else if` is NOT supported
        // as a shorthand in v2 -- write `else { if (...) {...} }`.
        if (inSection && startsWith(line, "if")
            && line.size() > 2 && (line[2] == ' ' || line[2] == '(')) {
            std::size_t lp = line.find('(');
            std::size_t rp = (lp != std::string_view::npos)
                                ? findMatchingRparen(line, lp)
                                : std::string_view::npos;
            std::string_view tail = (rp != std::string_view::npos)
                                        ? line.substr(rp + 1)
                                        : std::string_view{};
            while (!tail.empty() && (tail.front() == ' ' || tail.front() == '\t')) tail.remove_prefix(1);
            if (!tail.empty() && tail.front() == '{') {
                // Copy cond out -- pullLine() below invalidates the view.
                std::string cond{trim(line.substr(lp + 1, rp - lp - 1))};

                // Helper: collect a brace-delimited body across pulled lines.
                // Body chars accumulated in `out`; `afterClose` receives the
                // remainder of the line that contained the matching `}` (so
                // a same-line `} else {` is detectable without re-pulling).
                auto collectBracedBody = [&](std::string_view startLine,
                                             std::size_t openBraceIdx,
                                             std::string& out,
                                             std::string& afterClose) {
                    int depth = 1;
                    bool done = false;
                    if (openBraceIdx != std::string_view::npos) {
                        for (std::size_t i = openBraceIdx + 1; i < startLine.size(); ++i) {
                            char c = startLine[i];
                            if (c == '{') ++depth;
                            else if (c == '}') {
                                --depth;
                                if (depth == 0) {
                                    afterClose.assign(startLine.substr(i + 1));
                                    done = true;
                                    break;
                                }
                            }
                            out += c;
                        }
                    }
                    while (!done) {
                        if (!pullLine()) throw std::runtime_error("if-block: unterminated body");
                        std::string_view raw2 = current.text;
                        if (!raw2.empty() && raw2.back() == '\r') raw2.remove_suffix(1);
                        std::string_view s2 = stripLineComment(raw2);
                        out += '\n';
                        for (std::size_t i = 0; i < s2.size(); ++i) {
                            char c = s2[i];
                            if (c == '{') ++depth;
                            else if (c == '}') {
                                --depth;
                                if (depth == 0) {
                                    afterClose.assign(s2.substr(i + 1));
                                    done = true;
                                    break;
                                }
                            }
                            out += c;
                        }
                    }
                };

                std::size_t lb = line.find('{', rp + 1);
                std::string body;
                std::string afterClose;
                collectBracedBody(line, lb, body, afterClose);

                // Collect the chain: zero or more `elsif`/`else if (cond) { ... }`
                // branches plus an optional final `else { ... }`.
                //
                //   `elsif (c) { ... }` is Ruby-style sugar -- accepted at parse
                //   time but never emitted by disasm (which always renders the
                //   canonical `else if`).
                std::vector<std::pair<std::string, std::string>> chain;  // (cond, body)
                std::string finalElseBody;
                bool hasFinalElse = false;

                while (true) {
                    // Detect whether the next non-whitespace token is `else`,
                    // `elsif`, or none.  Source may be on the same line as the
                    // just-closed `}` (in afterClose) or on the next pulled line.
                    std::string keywordLine;
                    bool present = false;
                    {
                        std::string_view peek = trim(afterClose);
                        if (startsWith(peek, "else") || startsWith(peek, "elsif")) {
                            keywordLine.assign(afterClose);
                            present = true;
                        } else if (peek.empty()) {
                            if (pullLine()) {
                                std::string_view raw2 = current.text;
                                if (!raw2.empty() && raw2.back() == '\r') raw2.remove_suffix(1);
                                std::string_view s2 = stripLineComment(raw2);
                                if (startsWith(trim(s2), "else") || startsWith(trim(s2), "elsif")) {
                                    keywordLine.assign(s2);
                                    present = true;
                                } else {
                                    // Not ours -- push back verbatim so the pull
                                    // loop sees it next.
                                    pendingLines.push_front(PendingLine{
                                        std::string{current.text},
                                        current.srcFile,
                                        current.srcLine});
                                }
                            }
                        }
                    }
                    if (!present) break;

                    // Strip leading whitespace, then the keyword.  Decide whether
                    // this branch is a chained conditional (`elsif`/`else if`)
                    // or the terminal `else { ... }`.
                    std::string_view rest = trim(std::string_view{keywordLine});
                    bool isChained = false;
                    if (startsWith(rest, "elsif")) {
                        rest.remove_prefix(5);
                        isChained = true;
                    } else {
                        rest.remove_prefix(4);  // "else"
                        std::string_view rt = rest;
                        while (!rt.empty() && (rt.front() == ' ' || rt.front() == '\t')) rt.remove_prefix(1);
                        if (startsWith(rt, "if ") || startsWith(rt, "if(")) {
                            rest = rt;
                            rest.remove_prefix(2);  // "if"
                            isChained = true;
                        }
                    }
                    while (!rest.empty() && (rest.front() == ' ' || rest.front() == '\t')) {
                        rest.remove_prefix(1);
                    }

                    std::string branchCond;
                    if (isChained) {
                        if (rest.empty() || rest.front() != '(') {
                            throw std::runtime_error("else-if: expected '(' after 'elsif'/'else if'");
                        }
                        std::size_t crp = findMatchingRparen(rest, 0);
                        if (crp == std::string_view::npos) {
                            throw std::runtime_error("else-if: unmatched '('");
                        }
                        branchCond.assign(trim(rest.substr(1, crp - 1)));
                        rest = rest.substr(crp + 1);
                        while (!rest.empty() && (rest.front() == ' ' || rest.front() == '\t')) {
                            rest.remove_prefix(1);
                        }
                    }

                    // Expect `{` -- on the same line or on a subsequent line.
                    std::size_t branchLb = std::string_view::npos;
                    if (!rest.empty() && rest.front() == '{') {
                        branchLb = 0;
                    } else {
                        while (branchLb == std::string_view::npos) {
                            if (!pullLine()) {
                                throw std::runtime_error("if-block else/elsif: missing '{'");
                            }
                            std::string_view raw2 = current.text;
                            if (!raw2.empty() && raw2.back() == '\r') raw2.remove_suffix(1);
                            std::string_view s2 = trim(stripLineComment(raw2));
                            if (!s2.empty() && s2.front() == '{') {
                                rest = s2;
                                branchLb = 0;
                            } else if (!s2.empty()) {
                                throw std::runtime_error("if-block else/elsif: expected '{'");
                            }
                        }
                    }
                    std::string branchBody;
                    std::string branchAfter;
                    collectBracedBody(rest, branchLb, branchBody, branchAfter);

                    if (isChained) {
                        chain.emplace_back(std::move(branchCond), std::move(branchBody));
                        afterClose = std::move(branchAfter);
                        // Loop again -- there may be more chain.
                    } else {
                        finalElseBody = std::move(branchBody);
                        hasFinalElse = true;
                        break;
                    }
                }

                int id = nextIfId++;

                // Lower to the engine's single-branch-skip shape (matches the
                // shipping corpus).  Each branch becomes `if (negate(c_k)) goto
                // bypass_k; body_k; goto endLabel; bypass_k:`.  For the LAST
                // branch with no final else, reuse endLabel directly as the
                // bypass -- skips a no-op jump and matches the byte shape of
                // a nested-if encoding (`else { if (...) {...} }`) exactly.
                std::vector<std::pair<std::string, std::string>> branches;
                branches.emplace_back(std::move(cond), std::move(body));
                for (auto& b : chain) branches.push_back(std::move(b));

                std::vector<std::string> expanded;
                auto appendBodyLines = [&](const std::string& src) {
                    std::size_t st = 0;
                    for (std::size_t k = 0; k <= src.size(); ++k) {
                        if (k == src.size() || src[k] == '\n') {
                            std::string_view piece = trim(std::string_view{src}.substr(st, k - st));
                            if (!piece.empty()) expanded.emplace_back(piece);
                            st = k + 1;
                        }
                    }
                };
                std::string endLabel = "__if_end_" + std::to_string(id);

                if (branches.size() == 1 && !hasFinalElse) {
                    // v1: simple single-arm.
                    std::string negated = predneg::negatePredicate(branches[0].first);
                    expanded.push_back("if (" + negated + ") goto " + endLabel + ";");
                    appendBodyLines(branches[0].second);
                    expanded.push_back(endLabel + ":");
                } else {
                    for (std::size_t k = 0; k < branches.size(); ++k) {
                        bool isLast = (k + 1 == branches.size());
                        bool reuseEnd = isLast && !hasFinalElse;
                        std::string bypassLabel = reuseEnd
                            ? endLabel
                            : ("__if_else_" + std::to_string(id) + "_" + std::to_string(k));
                        std::string neg_k = predneg::negatePredicate(branches[k].first);
                        expanded.push_back("if (" + neg_k + ") goto " + bypassLabel + ";");
                        appendBodyLines(branches[k].second);
                        if (!reuseEnd) {
                            expanded.push_back("goto " + endLabel + ";");
                            expanded.push_back(bypassLabel + ":");
                        }
                    }
                    if (hasFinalElse) {
                        appendBodyLines(finalElseBody);
                    }
                    expanded.push_back(endLabel + ":");
                }

                for (auto it = expanded.rbegin(); it != expanded.rend(); ++it) {
                    pendingLines.push_front(PendingLine{std::move(*it), originFile, originLine});
                }
                continue;
            }
            // No `{` after `)`: fall through to the legacy goto-form handler.
        }

        // `for <ident> in [<vals>] { <body> }`   -- explicit list
        // `for <ident> in <start>..<end> { <body> }` -- inclusive integer range
        // `for <a>, <b> in [<k> => <v>, ...] { <body> }` -- pair-destructure
        // All forms unroll at parse time (the VM has no loops).
        if (inSection && startsWith(line, "for ")) {
            std::string_view r = line.substr(4);
            while (!r.empty() && (r[0] == ' ' || r[0] == '\t')) r.remove_prefix(1);
            std::string_view iterView = leadingIdent(r);
            if (iterView.empty()) throw std::runtime_error("for: expected iterator name");
            // Copy out of current.text -- multi-line `[...]` collection below
            // may call pullLine(), invalidating any string_views into it.
            std::string iterName{iterView};
            r.remove_prefix(iterView.size());
            while (!r.empty() && (r[0] == ' ' || r[0] == '\t')) r.remove_prefix(1);
            // Optional second iterator: `for a, b in ...` -- destructures
            // pair-list elements (each `key => value`).
            std::string iterName2;
            if (!r.empty() && r[0] == ',') {
                r.remove_prefix(1);
                while (!r.empty() && (r[0] == ' ' || r[0] == '\t')) r.remove_prefix(1);
                std::string_view i2 = leadingIdent(r);
                if (i2.empty()) throw std::runtime_error("for: expected second iterator name after `,`");
                iterName2.assign(i2);
                r.remove_prefix(i2.size());
                while (!r.empty() && (r[0] == ' ' || r[0] == '\t')) r.remove_prefix(1);
            }
            if (!startsWith(r, "in")) throw std::runtime_error("for: expected 'in'");
            r.remove_prefix(2);
            while (!r.empty() && (r[0] == ' ' || r[0] == '\t')) r.remove_prefix(1);

            std::vector<std::string> values;
            // `for X in NAME { body }` -- look up NAME in array constants.
            // If found, use its values; else fall through to [..] / range.
            std::string_view leadIdent = leadingIdent(r);
            auto arrIt = leadIdent.empty()
                ? arrayConsts.end()
                : arrayConsts.find(std::string{leadIdent});
            if (arrIt != arrayConsts.end()) {
                values = arrIt->second;
                r = r.substr(leadIdent.size());
                while (!r.empty() && (r[0] == ' ' || r[0] == '\t')) r.remove_prefix(1);
            } else if (!r.empty() && r[0] == '[') {
                // Multi-line capable: depth-track `[` until the matching `]`.
                // The remainder after `]` (typically `{ ... }`) becomes the new
                // line we continue parsing -- `r` is a view into current.text
                // and pullLine() invalidates it, so save state into strings.
                std::string listContent;
                int dep = 1;
                std::size_t pos = 1;
                std::string remainder;
                for (; pos < r.size(); ++pos) {
                    char c = r[pos];
                    if (c == '[') ++dep;
                    else if (c == ']') { --dep; if (dep == 0) break; }
                    listContent += c;
                }
                if (dep == 0) {
                    remainder.assign(r.substr(pos + 1));
                } else {
                    while (dep > 0) {
                        if (!pullLine()) throw std::runtime_error("for: unterminated `[...]`");
                        std::string_view raw2 = stripLineComment(current.text);
                        if (!raw2.empty() && raw2.back() == '\r') raw2.remove_suffix(1);
                        listContent += '\n';
                        std::size_t k = 0;
                        for (; k < raw2.size(); ++k) {
                            char c = raw2[k];
                            if (c == '[') ++dep;
                            else if (c == ']') {
                                --dep;
                                if (dep == 0) { remainder.assign(raw2.substr(k + 1)); break; }
                            }
                            listContent += c;
                        }
                        if (dep == 0) break;
                    }
                }
                auto valTokens = splitTopCommas(listContent);
                for (auto& v : valTokens) {
                    std::string_view t = trim(v);
                    if (!t.empty()) values.emplace_back(t);
                }
                // Stash the remainder so the `{ body }` parser uses it as `r`.
                // To keep the same data-flow shape downstream, copy remainder
                // back into a stable buffer and view it.  Same trick as the
                // macro-definition handler.
                std::string_view trimmed = trim(std::string_view{remainder});
                // Replace `r` to point at `remainder`'s lifetime by storing
                // it in a sibling string maintained by the enclosing scope.
                static thread_local std::string forListRemainder;
                forListRemainder = std::string{trimmed};
                r = forListRemainder;
            } else {
                // Range form: <start>..<end> (inclusive).  Both endpoints
                // may be constant expressions (consts already substituted).
                std::size_t dd = r.find("..");
                if (dd == std::string_view::npos) {
                    throw std::runtime_error("for: expected '[' or '<start>..<end>'");
                }
                std::string startExpr{trim(r.substr(0, dd))};
                std::string_view rest = trim(r.substr(dd + 2));
                std::size_t lb = rest.find('{');
                if (lb == std::string_view::npos) throw std::runtime_error("for: expected '{'");
                std::string endExpr{trim(rest.substr(0, lb))};
                int s = evalIntExpr(startExpr, consts);
                int e = evalIntExpr(endExpr, consts);
                if (e < s) throw std::runtime_error("for range: end < start");
                values.reserve(static_cast<std::size_t>(e - s + 1));
                for (int v = s; v <= e; ++v) values.push_back(toDec(static_cast<long long>(v)));
                r = rest.substr(lb);
            }

            while (!r.empty() && (r[0] == ' ' || r[0] == '\t')) r.remove_prefix(1);
            if (r.empty() || r[0] != '{') throw std::runtime_error("for: expected '{'");

            // Collect body until matching `}` (nested braces tracked).
            std::string body;
            int depth = 1;
            std::string_view tail = r.substr(1);
            for (char c : tail) {
                if (c == '{') depth++;
                else if (c == '}') { depth--; if (depth == 0) break; }
                body += c;
            }
            while (depth > 0) {
                if (!pullLine()) throw std::runtime_error("for: unterminated body");
                std::string_view raw2 = current.text;
                if (!raw2.empty() && raw2.back() == '\r') raw2.remove_suffix(1);
                std::string_view s2 = stripLineComment(raw2);
                body += '\n';
                for (char c : s2) {
                    if (c == '{') depth++;
                    else if (c == '}') { depth--; if (depth == 0) break; }
                    body += c;
                }
            }

            // Expand body for each value; push expanded lines back (in order).
            // Statements inside the body may be separated by newlines or by
            // top-level `;`; we normalize to one statement per pending line.
            std::vector<std::string> expanded;
            for (const auto& val : values) {
                std::string subBody;
                if (iterName2.empty()) {
                    subBody = substituteIdent(body, iterName, val);
                } else {
                    // Destructuring: split element on top-level `=>`.
                    auto findArrow = [](std::string_view s) -> std::size_t {
                        int dp = 0;
                        for (std::size_t k = 0; k + 1 < s.size(); ++k) {
                            char c = s[k];
                            if (c == '(' || c == '[' || c == '{') ++dp;
                            else if (c == ')' || c == ']' || c == '}') --dp;
                            else if (dp == 0 && c == '=' && s[k + 1] == '>') return k;
                        }
                        return std::string_view::npos;
                    };
                    std::size_t arrow = findArrow(val);
                    if (arrow == std::string_view::npos) {
                        throw std::runtime_error(
                            "for: pair-destructure expects `key => value`, got `"
                            + val + "`");
                    }
                    std::string lhs{trim(std::string_view{val}.substr(0, arrow))};
                    std::string rhs{trim(std::string_view{val}.substr(arrow + 2))};
                    subBody = substituteIdent(body,    iterName,  lhs);
                    subBody = substituteIdent(subBody, iterName2, rhs);
                }
                for (auto piece : splitTopSemis(subBody)) {
                    std::string_view tp = trim(piece);
                    if (tp.empty()) continue;
                    expanded.emplace_back(std::string{tp} + ";");
                }
            }
            for (auto it = expanded.rbegin(); it != expanded.rend(); ++it) {
                pendingLines.push_front(PendingLine{std::move(*it), originFile, originLine});
            }
            continue;
        }

        // `choice { "label" -> target ... }` -- desugars to setSelection +
        // showTextbox + waitForSelectionChoice.
        if (inSection && startsWith(line, "choice")
            && (line.size() == 6 || line[6] == ' ' || line[6] == '\t' || line[6] == '{')) {
            std::size_t lb = line.find('{');
            std::string body;
            int depth = 1;
            if (lb != std::string_view::npos) {
                for (std::size_t i = lb + 1; i < line.size(); ++i) {
                    char c = line[i];
                    if (c == '{') depth++;
                    else if (c == '}') { depth--; if (depth == 0) break; }
                    body += c;
                }
            } else {
                // `choice` on this line, `{` on a later line.
                while (true) {
                    if (!pullLine()) throw std::runtime_error("choice: missing '{'");
                    std::string_view raw2 = stripLineComment(current.text);
                    std::size_t b = raw2.find('{');
                    if (b != std::string_view::npos) {
                        for (std::size_t i = b + 1; i < raw2.size(); ++i) {
                            char c = raw2[i];
                            if (c == '{') depth++;
                            else if (c == '}') { depth--; if (depth == 0) break; }
                            body += c;
                        }
                        break;
                    }
                }
            }
            while (depth > 0) {
                if (!pullLine()) throw std::runtime_error("choice: unterminated body");
                std::string_view raw2 = stripLineComment(current.text);
                body += '\n';
                for (char c : raw2) {
                    if (c == '{') depth++;
                    else if (c == '}') { depth--; if (depth == 0) break; }
                    body += c;
                }
            }

            // Body entries: "label" -> target  (one per line, ; or , separated).
            // The split is string-aware so a label like `"Okay, I accept"`
            // doesn't get cut on its inner comma.
            std::vector<std::string> labels;
            std::vector<std::string> targets;
            std::size_t i = 0;
            while (i < body.size()) {
                std::size_t end = i;
                bool inStr = false;
                while (end < body.size()) {
                    char c = body[end];
                    if (inStr) {
                        if (c == '\\' && end + 1 < body.size()) { end += 2; continue; }
                        if (c == '"') inStr = false;
                        ++end;
                        continue;
                    }
                    if (c == '"') { inStr = true; ++end; continue; }
                    if (c == ';' || c == ',' || c == '\n') break;
                    ++end;
                }
                std::string_view entry = std::string_view{body}.substr(i, end - i);
                entry = trim(entry);
                if (!entry.empty()) {
                    if (entry[0] != '"') throw std::runtime_error("choice: entry must start with quoted label");
                    std::size_t q2 = 1;
                    while (q2 < entry.size() && entry[q2] != '"') {
                        if (entry[q2] == '\\' && q2 + 1 < entry.size()) q2 += 2;
                        else q2++;
                    }
                    if (q2 >= entry.size()) throw std::runtime_error("choice: unterminated label string");
                    std::string label{entry.substr(1, q2 - 1)};
                    std::string_view rest = trim(entry.substr(q2 + 1));
                    if (!startsWith(rest, "->")) throw std::runtime_error("choice: expected '->'");
                    std::string_view target = trim(rest.substr(2));
                    labels.push_back(std::move(label));
                    targets.emplace_back(target);
                }
                if (end >= body.size()) break;
                i = end + 1;
            }

            // Build the three synthesized statements.
            std::string ss = "setSelection(";
            for (std::size_t k = 0; k < targets.size(); ++k) {
                if (k) ss += ", ";
                ss += targets[k];
            }
            ss += ");";

            std::string st = "showTextbox(\"";
            for (const auto& l : labels) { st += l; st += "\\n"; }
            st += "\");";

            std::string sw = "waitForSelectionChoice();";

            pendingLines.push_front(PendingLine{std::move(sw), originFile, originLine});
            pendingLines.push_front(PendingLine{std::move(st), originFile, originLine});
            pendingLines.push_front(PendingLine{std::move(ss), originFile, originLine});
            continue;
        }

        // `pstat[<idx>] = date();` -- sugar for `storeDate(<idx>)`.  The
        // <idx> token (numeric, `:Name`, `PStat.Name`, or bare `Name`) is
        // passed through; the existing field-arg resolver handles all four.
        if (inSection && startsWith(line, "pstat[")) {
            std::size_t rb = line.find(']', 6);
            if (rb != std::string_view::npos) {
                std::string_view rest = trim(line.substr(rb + 1));
                if (!rest.empty() && rest.front() == '=') {
                    std::string_view rhs = trim(rest.substr(1));
                    if (!rhs.empty() && rhs.back() == ';') rhs.remove_suffix(1);
                    rhs = trim(rhs);
                    if (rhs == "time()") {
                        std::string_view idx = trim(line.substr(6, rb - 6));
                        std::string call = "storeDate(";
                        call.append(idx);
                        call += ");";
                        pendingLines.push_front(PendingLine{std::move(call), originFile, originLine});
                        continue;
                    }
                }
            }
        }

        // `removeItems([<i1>, <i2>, ...], count);` -- accepts multi-line list.
        // Each element expands to one `removeItem(<i>, count);`.
        if (inSection && startsWith(line, "removeItems")
            && line.size() > 11 && line[11] == '(') {
            std::string buf;
            int depth = 1;
            for (std::size_t i = 12; i < line.size(); ++i) {
                char c = line[i];
                if (c == '(') ++depth;
                else if (c == ')') { --depth; if (depth == 0) break; }
                buf += c;
            }
            while (depth > 0) {
                if (!pullLine()) throw std::runtime_error("removeItems: unterminated");
                std::string_view raw2 = stripLineComment(current.text);
                if (!raw2.empty() && raw2.back() == '\r') raw2.remove_suffix(1);
                buf += '\n';
                for (char c : raw2) {
                    if (c == '(') ++depth;
                    else if (c == ')') { --depth; if (depth == 0) break; }
                    buf += c;
                }
            }
            // Two accepted shapes:
            //   removeItems([:A, :B, :C], count)        -- shared count
            //   removeItems([:A => v, :B => w, ...])      -- per-item counts
            auto topArgs = splitTopCommas(buf);
            if (topArgs.empty()) throw std::runtime_error("removeItems: empty");
            std::string_view itemsList = trim(topArgs[0]);
            if (itemsList.empty() || itemsList.front() != '[' || itemsList.back() != ']') {
                throw std::runtime_error("removeItems: first arg must be `[...]`");
            }
            auto items = splitTopCommas(itemsList.substr(1, itemsList.size() - 2));
            std::vector<std::string> expanded;
            if (topArgs.size() >= 2) {
                // Shared-count form.
                std::string_view countExpr = trim(topArgs[1]);
                for (auto item : items) {
                    std::string_view ti = trim(item);
                    if (ti.empty()) continue;
                    std::string stmt = "removeItem(";
                    stmt += std::string{ti};
                    stmt += ", ";
                    stmt += std::string{countExpr};
                    stmt += ");";
                    expanded.push_back(std::move(stmt));
                }
            } else {
                // Hash form: each entry is `<item> => <count>`.
                for (auto entry : items) {
                    std::string_view te = trim(entry);
                    if (te.empty()) continue;
                    std::size_t arrow = te.find("=>");
                    if (arrow == std::string_view::npos) {
                        throw std::runtime_error(
                            "removeItems hash form: entry missing `=>` in `"
                            + std::string{te} + "`");
                    }
                    std::string_view item  = trim(te.substr(0, arrow));
                    std::string_view count = trim(te.substr(arrow + 2));
                    std::string stmt = "removeItem(";
                    stmt += std::string{item};
                    stmt += ", ";
                    stmt += std::string{count};
                    stmt += ");";
                    expanded.push_back(std::move(stmt));
                }
            }
            for (auto it = expanded.rbegin(); it != expanded.rend(); ++it) {
                pendingLines.push_front(PendingLine{std::move(*it), originFile, originLine});
            }
            continue;
        }

        // `addStats(key: val, key: val, ...);` / `reduceStats(...)` / `setStats(...)`
        //  -- named-arg list form expanding to one opcode per pair.  Each key
        // must resolve as a Stat symbol (case-folded on first letter, so
        // `currentMP` -> `CurrentMP`); otherwise we fall through.  Runs BEFORE
        // macro lookup so a user-defined macro `setStats(stat: Stat, value)`
        // doesn't snag the variadic form first and throw on the unknown
        // parameter names.
        if (inSection) {
            std::string_view opName;
            for (auto cand : std::array<std::string_view, 3>{"addStats", "reduceStats", "setStats"}) {
                if (startsWith(line, cand) && line.size() > cand.size() && line[cand.size()] == '(') {
                    opName = cand;
                    break;
                }
            }
            if (!opName.empty()) {
                std::size_t lp = opName.size();
                std::size_t rp = findMatchingRparen(line, lp);
                if (rp != std::string_view::npos) {
                    std::string_view tail = trim(line.substr(rp + 1));
                    if (tail.empty() || tail == ";") {
                        auto args = splitTopCommas(line.substr(lp + 1, rp - lp - 1));
                        bool allNamed = !args.empty();
                        for (auto a : args) if (!isNamedArgPiece(a)) { allNamed = false; break; }
                        bool allStatNames = allNamed;
                        std::vector<std::string> titleCased;
                        if (allNamed) {
                            const SymbolTable* local =
                                curScript ? &curScript->localSymbols : nullptr;
                            for (auto a : args) {
                                auto [k, _] = splitNamedArg(a);
                                std::string sn{trim(k)};
                                if (!sn.empty() && sn.front() >= 'a' && sn.front() <= 'z') {
                                    sn.front() = static_cast<char>(sn.front() - 'a' + 'A');
                                }
                                int dummy;
                                if (!lookupBareNameInScope(local, SymKind::Stat, sn, dummy)) {
                                    allStatNames = false;
                                    break;
                                }
                                titleCased.push_back(std::move(sn));
                            }
                        }
                        if (allStatNames) {
                            std::vector<std::string> expanded;
                            for (std::size_t i = 0; i < args.size(); ++i) {
                                auto [k, v] = splitNamedArg(args[i]);
                                std::string stmt{opName};
                                stmt += "(Stat.";
                                stmt += titleCased[i];
                                stmt += ", ";
                                stmt += std::string{trim(v)};
                                stmt += ");";
                                expanded.push_back(std::move(stmt));
                            }
                            for (auto it = expanded.rbegin(); it != expanded.rend(); ++it) {
                                pendingLines.push_front(PendingLine{std::move(*it), originFile, originLine});
                            }
                            continue;
                        }
                    }
                }
            }
        }

        // User-defined macro invocation: `<name>(<args>);` where <name> is
        // a previously-defined macro.  Body is substituted with positional
        // args (word-boundary, string-literal-safe) and pushed back; the
        // expanded lines re-enter the pull loop so nested macros + built-in
        // sugar work naturally.
        if (inSection && !macros.empty()) {
            std::string_view ident = leadingIdent(line);
            if (!ident.empty()) {
                auto mit = macros.find(std::string{ident});
                if (mit != macros.end()) {
                    std::string_view rest = trim(line.substr(ident.size()));
                    if (!rest.empty() && rest[0] == '(') {
                        // Multi-line capable arg accumulator: walk from `(`
                        // until matching `)`, pulling more lines as needed.
                        std::string argsBuf;
                        int depth = 1;
                        std::string tailStr;
                        bool complete = false;
                        for (std::size_t i = 1; i < rest.size(); ++i) {
                            char c = rest[i];
                            if (c == '(') ++depth;
                            else if (c == ')') {
                                --depth;
                                if (depth == 0) {
                                    tailStr.assign(trim(rest.substr(i + 1)));
                                    complete = true;
                                    break;
                                }
                            }
                            argsBuf += c;
                        }
                        while (!complete) {
                            if (!pullLine()) {
                                throw std::runtime_error(std::string{"function "} + std::string{ident}
                                    + ": unterminated argument list");
                            }
                            std::string_view ln2 = stripLineComment(current.text);
                            if (!ln2.empty() && ln2.back() == '\r') ln2.remove_suffix(1);
                            argsBuf += '\n';
                            for (std::size_t i = 0; i < ln2.size(); ++i) {
                                char c = ln2[i];
                                if (c == '(') ++depth;
                                else if (c == ')') {
                                    --depth;
                                    if (depth == 0) {
                                        tailStr.assign(trim(ln2.substr(i + 1)));
                                        complete = true;
                                        break;
                                    }
                                }
                                argsBuf += c;
                            }
                        }
                        if (complete && (tailStr.empty() || tailStr == ";")) {
                            auto argTokens = splitTopCommas(argsBuf);
                            std::vector<std::string> rawArgs;
                            for (auto a : argTokens) {
                                std::string_view ta = trim(a);
                                rawArgs.emplace_back(ta);
                            }
                            while (!rawArgs.empty() && rawArgs.back().empty()) rawArgs.pop_back();
                            const auto& def = mit->second;

                            // Bind args to params, accepting positional and
                            // named (`param: value`) forms.  Positional must
                            // precede named.
                            std::vector<std::string> args(def.params.size());
                            std::vector<bool> filled(def.params.size(), false);
                            bool namedSeen = false;
                            std::size_t posIdx = 0;
                            auto findParam = [&](std::string_view pname) -> std::ptrdiff_t {
                                for (std::size_t k = 0; k < def.params.size(); ++k) {
                                    if (def.params[k].name == pname) return static_cast<std::ptrdiff_t>(k);
                                }
                                return -1;
                            };
                            for (const auto& a : rawArgs) {
                                if (isNamedArgPiece(a)) {
                                    namedSeen = true;
                                    auto [n, v] = splitNamedArg(a);
                                    std::string pname{trim(n)};
                                    auto idx = findParam(pname);
                                    if (idx < 0) {
                                        throw std::runtime_error(std::string{"function "} + std::string{ident}
                                            + ": unknown parameter `" + pname + "`");
                                    }
                                    if (filled[idx]) {
                                        throw std::runtime_error(std::string{"function "} + std::string{ident}
                                            + ": parameter `" + pname + "` given twice");
                                    }
                                    args[idx] = std::string{trim(v)};
                                    filled[idx] = true;
                                } else {
                                    if (namedSeen) {
                                        throw std::runtime_error(std::string{"function "} + std::string{ident}
                                            + ": positional arg after named");
                                    }
                                    if (posIdx >= def.params.size()) {
                                        throw std::runtime_error(std::string{"function "} + std::string{ident}
                                            + ": too many positional args");
                                    }
                                    args[posIdx] = a;
                                    filled[posIdx] = true;
                                    ++posIdx;
                                }
                            }
                            for (std::size_t k = 0; k < def.params.size(); ++k) {
                                if (!filled[k]) {
                                    if (def.params[k].defaultExpr.has_value()) {
                                        args[k] = *def.params[k].defaultExpr;
                                        filled[k] = true;
                                    } else {
                                        throw std::runtime_error(std::string{"function "} + std::string{ident}
                                            + ": missing argument for `" + def.params[k].name + "`");
                                    }
                                }
                            }

                            // Resolve typed args.  Scalar typed: replace
                            // arg with numeric literal.  Array typed
                            // (`Kind[]`): split the `[...]` literal, resolve
                            // each element, reassemble as `[v1, v2, ...]`.
                            auto resolveTyped = [&](std::string_view a, SymKind k) -> int {
                                a = trim(a);
                                if (!a.empty() && a[0] == ':') {
                                    std::string_view name = a.substr(1);
                                    int v;
                                    if (!lookupBareNameInScope(g_localSyms, k, name, v)) {
                                        throw std::runtime_error(std::string{"function "} + std::string{ident}
                                            + ": `:" + std::string{name} + "` unbound in kind `"
                                            + std::string{symKindLabel(k)} + "`");
                                    }
                                    return v;
                                }
                                return parseNumOrSym(a, k);
                            };
                            for (std::size_t k = 0; k < def.params.size(); ++k) {
                                const auto& p = def.params[k];
                                if (!p.kind) continue;
                                if (p.isArray) {
                                    std::string_view a = trim(std::string_view{args[k]});
                                    if (a.size() < 2 || a.front() != '[' || a.back() != ']') {
                                        throw std::runtime_error(std::string{"function "} + std::string{ident}
                                            + ": param `" + p.name + ": " + std::string{symKindLabel(*p.kind)}
                                            + "[]` expected a `[...]` array literal");
                                    }
                                    auto items = splitTopCommas(a.substr(1, a.size() - 2));
                                    std::string out = "[";
                                    bool first = true;
                                    if (p.kind2) {
                                        // Pair-array `(K1, K2)[]`: each element
                                        // is `K => V`.  Resolve K in kind, V in
                                        // kind2; emit the pair as `<n1> => <n2>`
                                        // so the body's destructuring `for a, b`
                                        // can split it again.
                                        auto findArrow = [](std::string_view s) -> std::size_t {
                                            int dp = 0;
                                            for (std::size_t kk = 0; kk + 1 < s.size(); ++kk) {
                                                char c = s[kk];
                                                if (c == '(' || c == '[' || c == '{') ++dp;
                                                else if (c == ')' || c == ']' || c == '}') --dp;
                                                else if (dp == 0 && c == '=' && s[kk + 1] == '>') return kk;
                                            }
                                            return std::string_view::npos;
                                        };
                                        for (auto it : items) {
                                            std::string_view t = trim(it);
                                            if (t.empty()) continue;
                                            std::size_t ar = findArrow(t);
                                            if (ar == std::string_view::npos) {
                                                throw std::runtime_error(std::string{"function "} + std::string{ident}
                                                    + ": param `" + p.name + ": ("
                                                    + std::string{symKindLabel(*p.kind)} + ", "
                                                    + std::string{symKindLabel(*p.kind2)}
                                                    + ")[]` expected `K => V` element, got `"
                                                    + std::string{t} + "`");
                                            }
                                            std::string_view lhs = trim(t.substr(0, ar));
                                            std::string_view rhs = trim(t.substr(ar + 2));
                                            if (!first) out += ", ";
                                            out += toDec(static_cast<long long>(resolveTyped(lhs, *p.kind)));
                                            out += " => ";
                                            out += toDec(static_cast<long long>(resolveTyped(rhs, *p.kind2)));
                                            first = false;
                                        }
                                    } else {
                                        for (auto it : items) {
                                            std::string_view t = trim(it);
                                            if (t.empty()) continue;
                                            if (!first) out += ", ";
                                            out += toDec(static_cast<long long>(resolveTyped(t, *p.kind)));
                                            first = false;
                                        }
                                    }
                                    out += "]";
                                    args[k] = std::move(out);
                                } else {
                                    int v = resolveTyped(args[k], *p.kind);
                                    args[k] = toDec(static_cast<long long>(v));
                                }
                            }

                            std::vector<std::string> expanded;
                            expanded.reserve(def.bodyLines.size());
                            for (const auto& bl : def.bodyLines) {
                                std::string subbed = bl;
                                for (std::size_t k = 0; k < def.params.size(); ++k) {
                                    subbed = substituteIdent(subbed, def.params[k].name, args[k]);
                                }
                                expanded.push_back(std::move(subbed));
                            }
                            for (auto it = expanded.rbegin(); it != expanded.rend(); ++it) {
                                pendingLines.push_front(PendingLine{std::move(*it), originFile, originLine});
                            }
                            continue;
                        }
                    }
                }
            }
        }

        // Statement line.  Strip optional trailing `;`.
        std::string_view body = line;
        if (!body.empty() && body.back() == ';') body.remove_suffix(1);
        body = trim(body);
        if (body.empty() || !inSection) continue;

        Instr instr;
        instr.body = std::string{body};
        instr.labels = std::move(pendingLabels);
        instr.srcFile = originFile;
        instr.srcLine = originLine;
        instr.srcCol  = originCol;
        pendingLabels.clear();
        curSec.instrs.push_back(std::move(instr));
    }
    finalizeScript();

    ast.scripts = std::move(scriptsAccum);
    return ast;
}

// Resolver

namespace {

using Resolver = std::function<int(std::string_view label)>;

// Decode `L_<hex>` to its in-section offset (fallback when no decl exists).
// Returns -1 if the label isn't this form.
int hexFromLHex(std::string_view s) {
    if (!startsWith(s, "L_")) return -1;
    std::string_view hex = s.substr(2);
    if (hex.empty()) return -1;
    unsigned v = 0;
    for (char c : hex) {
        v <<= 4;
        if      (c >= '0' && c <= '9') v |= (c - '0');
        else if (c >= 'a' && c <= 'f') v |= (c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= (c - 'A' + 10);
        else return -1;
    }
    return static_cast<int>(v);
}

struct SectionInfo {
    int start;
    const std::unordered_map<std::string, std::size_t>* labelMap;
};

Resolver makeResolver(const ScriptAST& script) {
    std::unordered_map<std::string, SectionInfo> byName;
    std::unordered_set<std::string> dupNames;
    std::unordered_map<int, SectionInfo> byId;
    std::unordered_set<int> dupIds;

    for (const auto& s : script.sections) {
        SectionInfo info{ static_cast<int>(s.offset), &s.labelMap };
        if (byId.count(s.id)) dupIds.insert(s.id);
        else byId[s.id] = info;

        std::string name = s.name.empty()
            ? (s.hasDisambig
                ? (std::string{"section_"} + toDec(s.id) + "_at_" + toHexPadded(s.disambig, 4))
                : (std::string{"section_"} + toDec(s.id)))
            : s.name;
        if (s.id == ON_ENTER_ID && !s.hasDisambig && s.name.empty()) {
            name = std::string{ON_ENTER_LABEL};
        }
        if (byName.count(name)) {
            dupNames.insert(name);
        } else {
            byName[name] = info;
        }
    }

    return [byName = std::move(byName), dupNames = std::move(dupNames),
            byId = std::move(byId), dupIds = std::move(dupIds)]
           (std::string_view label) -> int {
        std::string_view orig = label;

        if (startsWith(label, "offset_")) return parseNum(label.substr(7));

        // `<sec>.<labelName>` cross-section.  Look up sec in byName, then
        // labelName in its labelMap (or hex-decode for `L_<hex>`).
        std::size_t dot = label.find('.');
        if (dot != std::string_view::npos) {
            std::string secName{label.substr(0, dot)};
            std::string_view labelPart = label.substr(dot + 1);
            const SectionInfo* info = nullptr;
            // Try by-id form (back-compat) first if it matches `section_<dec>`.
            if (startsWith(secName, "section_")) {
                std::string_view rest = std::string_view{secName}.substr(8);
                std::size_t i = 0;
                while (i < rest.size() && rest[i] >= '0' && rest[i] <= '9') i++;
                std::string_view after = rest.substr(i);
                if (i > 0 && after.empty()) {
                    int id = 0;
                    for (std::size_t k = 0; k < i; ++k) id = id * 10 + (rest[k] - '0');
                    auto it = byId.find(id);
                    if (it != byId.end() && !dupIds.count(id)) info = &it->second;
                }
            }
            if (!info) {
                auto bit = byName.find(secName);
                if (bit == byName.end()) {
                    throw std::runtime_error(std::string{"unknown section in cross-ref: "} + std::string{orig});
                }
                if (dupNames.count(secName)) {
                    throw std::runtime_error(std::string{"ambiguous section name '"} + secName + "'");
                }
                info = &bit->second;
            }
            // Look up label in target section's map; fall back to hex decode.
            auto lit = info->labelMap->find(std::string{labelPart});
            if (lit != info->labelMap->end()) {
                return info->start + static_cast<int>(lit->second);
            }
            int hx = hexFromLHex(labelPart);
            if (hx >= 0) return info->start + hx;
            throw std::runtime_error(std::string{"unknown label in cross-ref: "} + std::string{orig});
        }

        // Bare `section_<id>` (back-compat) or named section reference.
        if (startsWith(label, "section_")) {
            std::string_view rest = label.substr(8);
            std::size_t i = 0;
            while (i < rest.size() && rest[i] >= '0' && rest[i] <= '9') i++;
            std::string_view after = rest.substr(i);
            if (i > 0 && (after.empty() || startsWith(after, "_at_"))) {
                int id = 0;
                for (std::size_t k = 0; k < i; ++k) id = id * 10 + (rest[k] - '0');
                if (startsWith(after, "_at_")) {
                    auto bit = byName.find(std::string{label});
                    if (bit == byName.end()) {
                        throw std::runtime_error(std::string{"unknown section label "} + std::string{orig});
                    }
                    return bit->second.start;
                }
                if (dupIds.count(id)) {
                    throw std::runtime_error(std::string{"ambiguous section_"} + toDec(id) + " (needs _at_<offset>)");
                }
                auto it = byId.find(id);
                if (it == byId.end()) {
                    throw std::runtime_error(std::string{"unknown section label "} + std::string{orig});
                }
                return it->second.start;
            }
        }

        // Named section (custom name, onEnter, etc.)
        auto bit = byName.find(std::string{label});
        if (bit == byName.end()) {
            throw std::runtime_error(std::string{"unresolvable target: "} + std::string{orig});
        }
        if (dupNames.count(std::string{label})) {
            throw std::runtime_error(std::string{"ambiguous section name '"} + std::string{label} + "'");
        }
        return bit->second.start;
    };
}

// Per-section resolver: looks up labels in the current section's labelMap
// first (handles both `L_<hex>` decls and named labels), then falls back
// to the script-wide resolver.  As a final fallback, undeclared `L_<hex>`
// references hex-decode to current-section + offset.
std::function<int(std::string_view)> makeInSectionResolver(const Resolver& scriptResolver,
                                                            const SecAST& currentSec,
                                                            int currentSectionOffset) {
    return [&currentSec, scriptResolver, currentSectionOffset](std::string_view label) -> int {
        if (label.find('.') == std::string_view::npos) {
            auto it = currentSec.labelMap.find(std::string{label});
            if (it != currentSec.labelMap.end()) {
                return currentSectionOffset + static_cast<int>(it->second);
            }
            int hx = hexFromLHex(label);
            if (hx >= 0) return currentSectionOffset + hx;
        }
        return scriptResolver(label);
    };
}

} // namespace

// Statement parsing helpers

namespace {

// Parse "mnemonic(args)" into (mnemonic, args).  Returns false if there's
// no `(...)` -- caller handles bare mnemonic forms.
bool parseCall(std::string_view body, std::string_view& mnemonic,
               std::string_view& args) {
    std::size_t lp = body.find('(');
    if (lp == std::string_view::npos) return false;
    std::size_t rp = findMatchingRparen(body, lp);
    if (rp == std::string_view::npos) return false;
    mnemonic = trim(body.substr(0, lp));
    args = body.substr(lp + 1, rp - lp - 1);
    return true;
}

// Parse `{ ... }` body.  Returns the inside without the braces, trimmed.
bool parseBraced(std::string_view body, std::string_view& inside) {
    std::size_t lb = body.find('{');
    std::size_t rb = body.rfind('}');
    if (lb == std::string_view::npos || rb == std::string_view::npos || rb <= lb) return false;
    inside = trim(body.substr(lb + 1, rb - lb - 1));
    return true;
}

// Predicate parser (if opcode)

struct PredicateEnc { u8 opKind; std::vector<u8> payload; };

int cmpByte(std::string_view op) {
    if (op == "!=") return 0;
    if (op == "==") return 1;
    if (op == "<")  return 2;
    if (op == ">")  return 3;
    if (op == "<=") return 4;
    if (op == ">=") return 5;
    throw std::runtime_error(std::string{"bad cmp: "} + std::string{op});
}

int pstatKind(std::string_view op) {
    if (op == "!=") return 0x08;
    if (op == "==") return 0x09;
    if (op == "<")  return 0x0a;
    if (op == ">")  return 0x0b;
    if (op == "<=") return 0x0c;
    if (op == ">=") return 0x0d;
    throw std::runtime_error(std::string{"bad pstat op: "} + std::string{op});
}

bool matchIndexedCmp(std::string_view s, std::string_view name,
                     int& outN, std::string& outOp, int& outV) {
    if (!startsWith(s, name)) return false;
    std::string_view r = s.substr(name.size());
    if (r.empty() || r[0] != '[') return false;
    r.remove_prefix(1);
    std::size_t close = r.find(']');
    if (close == std::string_view::npos) return false;
    outN = parseNumOrSym(r.substr(0, close), predicateIndexKind(name));
    r = r.substr(close + 1);
    while (!r.empty() && r[0] == ' ') r.remove_prefix(1);
    std::string opStr;
    if (r.size() >= 2 && (r.substr(0, 2) == "!=" || r.substr(0, 2) == "==" ||
                          r.substr(0, 2) == "<=" || r.substr(0, 2) == ">=")) {
        opStr = std::string{r.substr(0, 2)}; r.remove_prefix(2);
    } else if (!r.empty() && (r[0] == '<' || r[0] == '>')) {
        opStr = std::string{r.substr(0, 1)}; r.remove_prefix(1);
    } else return false;
    while (!r.empty() && r[0] == ' ') r.remove_prefix(1);
    outOp = opStr;
    outV = parseNum(r);
    return true;
}

PredicateEnc encodePredicate(std::string_view sIn) {
    std::string_view s = trim(sIn);

    if (startsWith(s, "!trigger(") && endsWith(s, ")")) {
        std::string_view inner = s.substr(9, s.size() - 9 - 1);
        int v = parseNumOrSym(inner, SymKind::Trigger);
        return { 0x00, { static_cast<u8>(v & 0xff), static_cast<u8>((v >> 8) & 0xff) } };
    }
    if (startsWith(s, "trigger(") && endsWith(s, ")")) {
        std::string_view inner = s.substr(8, s.size() - 8 - 1);
        int v = parseNumOrSym(inner, SymKind::Trigger);
        return { 0x01, { static_cast<u8>(v & 0xff), static_cast<u8>((v >> 8) & 0xff) } };
    }
    {
        int n, v; std::string op;
        if (matchIndexedCmp(s, "pstat", n, op, v)) {
            return { static_cast<u8>(pstatKind(op)), { static_cast<u8>(n), static_cast<u8>(v & 0xff) } };
        }
    }
    {
        int n, v; std::string op;
        if (matchIndexedCmp(s, "stat", n, op, v)) {
            return { 0x20, { static_cast<u8>(n), static_cast<u8>(cmpByte(op)),
                            static_cast<u8>(v & 0xff), static_cast<u8>((v >> 8) & 0xff) } };
        }
    }
    {
        int n, v; std::string op;
        if (matchIndexedCmp(s, "card", n, op, v)) {
            return { 0x21, { static_cast<u8>(n), static_cast<u8>(cmpByte(op)),
                            static_cast<u8>(v & 0xff), static_cast<u8>((v >> 8) & 0xff) } };
        }
    }
    if (startsWith(s, "hasTech(")) {
        std::size_t close = s.find(')');
        if (close != std::string_view::npos) {
            int n = parseNumOrSym(s.substr(8, close - 8), SymKind::Move);
            std::string_view after = s.substr(close + 1);
            while (!after.empty() && after[0] == ' ') after.remove_prefix(1);
            if (startsWith(after, "==")) {
                after.remove_prefix(2);
                while (!after.empty() && after[0] == ' ') after.remove_prefix(1);
                int v = parseNum(after);
                return { 0x22, { static_cast<u8>(n), static_cast<u8>(v) } };
            }
        }
    }
    if (startsWith(s, "(cond")) {
        std::size_t amp = s.find('&');
        std::size_t close = s.find(')');
        std::size_t eq = s.find("==");
        if (amp != std::string_view::npos && close != std::string_view::npos && eq != std::string_view::npos) {
            std::string_view lhs = trim(s.substr(amp + 1, close - amp - 1));
            std::string_view rhs = trim(s.substr(eq + 2));
            int a = parseNum(lhs);
            int b = parseNum(rhs);
            return { 0x23, { static_cast<u8>(a), static_cast<u8>(b) } };
        }
    }
    {
        int n, v; std::string op;
        if (matchIndexedCmp(s, "item", n, op, v)) {
            return { 0x24, { static_cast<u8>(n), static_cast<u8>(cmpByte(op)),
                            static_cast<u8>(v & 0xff), static_cast<u8>((v >> 8) & 0xff) } };
        }
    }
    if (startsWith(s, "money")) {
        std::string_view r = s.substr(5);
        while (!r.empty() && r[0] == ' ') r.remove_prefix(1);
        std::string op;
        if (r.size() >= 2 && (r.substr(0, 2) == "!=" || r.substr(0, 2) == "==" ||
                              r.substr(0, 2) == "<=" || r.substr(0, 2) == ">=")) {
            op = std::string{r.substr(0, 2)}; r.remove_prefix(2);
        } else if (!r.empty() && (r[0] == '<' || r[0] == '>')) {
            op = std::string{r.substr(0, 1)}; r.remove_prefix(1);
        } else {
            throw std::runtime_error(std::string{"unknown predicate: "} + std::string{s});
        }
        while (!r.empty() && r[0] == ' ') r.remove_prefix(1);
        int v = parseNum(r);
        std::vector<u8> payload(6, 0);
        payload[1] = static_cast<u8>(cmpByte(op));
        payload[2] = static_cast<u8>(v & 0xff);
        payload[3] = static_cast<u8>((v >> 8) & 0xff);
        payload[4] = static_cast<u8>((v >> 16) & 0xff);
        payload[5] = static_cast<u8>((v >> 24) & 0xff);
        return { 0x25, std::move(payload) };
    }

    throw std::runtime_error(std::string{"unknown predicate: "} + std::string{s});
}

std::string stripOuter(std::string s) {
    auto trimInplace = [](std::string& str){
        std::size_t a = 0, b = str.size();
        while (a < b && (str[a] == ' ' || str[a] == '\t')) a++;
        while (b > a && (str[b - 1] == ' ' || str[b - 1] == '\t')) b--;
        str = str.substr(a, b - a);
    };
    trimInplace(s);
    while (s.size() >= 2 && s.front() == '(' && s.back() == ')') {
        int depth = 0;
        bool wraps = true;
        for (std::size_t i = 0; i < s.size(); ++i) {
            if (s[i] == '(') depth++;
            else if (s[i] == ')') depth--;
            if (depth == 0 && i < s.size() - 1) { wraps = false; break; }
        }
        if (!wraps) break;
        s = s.substr(1, s.size() - 2);
        trimInplace(s);
    }
    return s;
}

struct LinkSplit { std::string left; u8 linkBits; std::string right; bool found; };
LinkSplit splitAtRightmostLink(std::string_view s) {
    LinkSplit result{};
    result.found = false;
    int depth = 0;
    struct Tok { std::string_view word; u8 bits; };
    const Tok tokens[] = { {" && ", 0x40}, {" || ", 0x80}, {" ?? ", 0x00} };
    for (std::size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == '(') depth++;
        else if (c == ')') depth--;
        else if (depth == 0 && c == ' ') {
            for (const auto& t : tokens) {
                if (s.size() - i >= t.word.size()
                    && std::memcmp(s.data() + i, t.word.data(), t.word.size()) == 0) {
                    result.left = std::string{s.substr(0, i)};
                    result.linkBits = t.bits;
                    result.right = std::string{s.substr(i + t.word.size())};
                    result.found = true;
                    break;
                }
            }
        }
    }
    return result;
}

struct IfTerm { u8 link; std::string pred; };

std::vector<IfTerm> parseIfExprTerms(std::string expr) {
    expr = stripOuter(std::move(expr));
    auto sp = splitAtRightmostLink(expr);
    if (!sp.found) return { { 0, expr } };
    auto left = parseIfExprTerms(sp.left);
    auto rightStr = std::string{trim(sp.right)};
    left.push_back({ sp.linkBits, std::move(rightStr) });
    return left;
}

// `<lhs> in S..E`     -> `<lhs> >= S && <lhs> < E`   (half-open, Rust-style)
// `<lhs> in S..=E`    -> `<lhs> >= S && <lhs> <= E`  (inclusive)
// `<lhs> not in S..E` -> `<lhs> < S || <lhs> >= E`
// `<lhs> not in S..=E`-> `<lhs> < S || <lhs> > E`
// Only applied when the range predicate is the WHOLE condition -- i.e. the
// trimmed expression has no top-level `&&` / `||` outside the range itself.
// Combining ranges with other terms via `||` would silently mis-bind under
// the engine's strictly left-to-right predicate evaluation, so we refuse.
std::optional<std::string> tryExpandRangePredicate(std::string_view expr) {
    expr = trim(expr);
    // Strip one layer of redundant outer parens.
    while (expr.size() >= 2 && expr.front() == '(' && expr.back() == ')') {
        int d = 0;
        bool wraps = true;
        for (std::size_t i = 0; i < expr.size(); ++i) {
            if (expr[i] == '(') ++d;
            else if (expr[i] == ')') --d;
            if (d == 0 && i < expr.size() - 1) { wraps = false; break; }
        }
        if (!wraps) break;
        expr = trim(expr.substr(1, expr.size() - 2));
    }

    int depth = 0;
    bool inStr = false;
    std::size_t inPos = std::string_view::npos;
    bool isNot = false;
    for (std::size_t i = 0; i < expr.size(); ++i) {
        char c = expr[i];
        if (inStr) {
            if (c == '\\' && i + 1 < expr.size()) { ++i; continue; }
            if (c == '"') inStr = false;
            continue;
        }
        if (c == '"') { inStr = true; continue; }
        if (c == '(' || c == '[') { ++depth; continue; }
        if (c == ')' || c == ']') { --depth; continue; }
        if (depth != 0) continue;
        if (c == '&' || c == '|') return std::nullopt; // mixed with other terms -- bail
        if (i + 8 <= expr.size() && expr.substr(i, 8) == " not in ") {
            inPos = i; isNot = true; break;
        }
        if (inPos == std::string_view::npos
            && i + 4 <= expr.size() && expr.substr(i, 4) == " in ") {
            inPos = i; isNot = false;
            // Don't break -- continue to check the rest is && / || free.
        }
    }
    if (inPos == std::string_view::npos) return std::nullopt;

    const std::size_t tokLen = isNot ? 8 : 4;
    std::string_view lhs = trim(expr.substr(0, inPos));
    std::string_view rhs = trim(expr.substr(inPos + tokLen));
    std::size_t dd = rhs.find("..");
    if (dd == std::string_view::npos) return std::nullopt;
    std::string_view sStr = trim(rhs.substr(0, dd));
    std::string_view eStr = rhs.substr(dd + 2);
    bool closed = false;
    if (!eStr.empty() && eStr.front() == '=') { closed = true; eStr.remove_prefix(1); }
    eStr = trim(eStr);
    if (lhs.empty() || sStr.empty() || eStr.empty()) return std::nullopt;

    std::string lhsStr{lhs};
    std::string out;
    if (isNot) {
        // x not in S..E   -> x <  S || x >= E
        // x not in S..=E  -> x <  S || x >  E
        out  = lhsStr + " < "  + std::string{sStr};
        out += " || ";
        out += lhsStr + (closed ? " > " : " >= ") + std::string{eStr};
    } else {
        // x in S..E   -> x >= S && x <  E
        // x in S..=E  -> x >= S && x <= E
        out  = lhsStr + " >= " + std::string{sStr};
        out += " && ";
        out += lhsStr + (closed ? " <= " : " < ") + std::string{eStr};
    }
    return out;
}

// `if (<expr>) goto <thenLabel>; else goto <elseLabel>` -- semicolon
// between then-branch and else-clause is preserved in `body` (the
// outer trailing semicolon was already stripped by the line parser).
//
// Returns the encoded bytes.
std::vector<u8> encodeIfStmt(std::string_view body, const Resolver& resolve) {
    // The leading `if` keyword has already been stripped by the caller; `body`
    // is `(<expr>) goto <thenLabel>[; else goto <elseLabel>]`.
    std::size_t lp = body.find('(');
    if (lp == std::string_view::npos) throw std::runtime_error(std::string{"if: missing '('"});
    std::size_t rp = findMatchingRparen(body, lp);
    if (rp == std::string_view::npos) throw std::runtime_error(std::string{"if: unmatched '('"});
    std::string_view exprPart = trim(body.substr(lp + 1, rp - lp - 1));
    std::string_view after = trim(body.substr(rp + 1));

    // Split on top-level `;` for else clause.
    std::size_t semi = findTopLevelAny(after, ";");
    std::string_view thenBranch = (semi == std::string_view::npos) ? after : trim(after.substr(0, semi));
    std::string_view elseBranch = (semi == std::string_view::npos) ? std::string_view{} : trim(after.substr(semi + 1));

    // thenBranch must be `goto <label>`.
    if (!startsWith(thenBranch, "goto")) throw std::runtime_error(std::string{"if: expected 'goto' after condition"});
    std::string_view thenLabel = trim(thenBranch.substr(4));

    bool hasElse = false;
    std::string_view elseLabel;
    if (!elseBranch.empty()) {
        if (!startsWith(elseBranch, "else")) throw std::runtime_error(std::string{"if: expected 'else' after ';'"});
        std::string_view e = trim(elseBranch.substr(4));
        if (!startsWith(e, "goto")) throw std::runtime_error(std::string{"if: expected 'goto' after 'else'"});
        elseLabel = trim(e.substr(4));
        hasElse = true;
    }

    std::string exprToParse{exprPart};
    if (auto expanded = tryExpandRangePredicate(exprToParse)) {
        exprToParse = std::move(*expanded);
    }
    auto terms = parseIfExprTerms(std::move(exprToParse));

    std::vector<u8> out;
    out.push_back(0x19);
    out.push_back(0x00);
    for (const auto& t : terms) {
        auto enc = encodePredicate(t.pred);
        u16 cmp = static_cast<u16>((t.link & 0xc0) | (enc.opKind & 0x3f));
        appendU16LE(out, cmp);
        out.insert(out.end(), enc.payload.begin(), enc.payload.end());
    }
    appendU16LE(out, 0x0018);
    int thenV = resolve(thenLabel);
    appendU16LE(out, static_cast<u16>(thenV));
    int endIfV = hasElse ? resolve(elseLabel) : 0x19;
    appendU16LE(out, static_cast<u16>(endIfV));
    return out;
}

// Compute the byte size of an `if (...)` statement from its body.
std::size_t sizeOfIfStmt(std::string_view body) {
    std::size_t lp = body.find('(');
    std::size_t rp = findMatchingRparen(body, lp);
    std::string_view exprPart = trim(body.substr(lp + 1, rp - lp - 1));
    std::string exprToParse{exprPart};
    if (auto expanded = tryExpandRangePredicate(exprToParse)) {
        exprToParse = std::move(*expanded);
    }
    auto terms = parseIfExprTerms(std::move(exprToParse));
    std::size_t sz = 1 + 1;
    for (const auto& t : terms) {
        auto enc = encodePredicate(t.pred);
        sz += 2 + enc.payload.size();
    }
    sz += 2 + 2 + 2;
    return sz;
}

// Encode `switch (pstat[N]) { case K: goto L; ... }`.
std::vector<u8> encodeSwitchStmt(std::string_view body, const Resolver& resolve) {
    // body: "(pstat[N]) { case K: goto L; ... }"
    std::size_t lp = body.find('(');
    std::size_t rp = findMatchingRparen(body, lp);
    if (lp == std::string_view::npos || rp == std::string_view::npos) {
        throw std::runtime_error(std::string{"switch: bad parens"});
    }
    std::string_view expr = trim(body.substr(lp + 1, rp - lp - 1));
    // expr must be pstat[N].
    if (!startsWith(expr, "pstat[")) throw std::runtime_error(std::string{"switch: expected pstat[N]: "} + std::string{expr});
    std::size_t lb = expr.find('[');
    std::size_t rb = expr.find(']');
    int pstat = parseNumOrSym(expr.substr(lb + 1, rb - lb - 1), SymKind::PStat);

    std::string_view rest = trim(body.substr(rp + 1));
    std::string_view inside;
    if (!parseBraced(rest, inside)) throw std::runtime_error(std::string{"switch: missing braces"});

    auto arms = splitTopSemis(inside);
    std::vector<int> targets;
    targets.reserve(arms.size());
    for (auto arm : arms) {
        if (!startsWith(arm, "case")) throw std::runtime_error(std::string{"switch arm missing 'case': "} + std::string{arm});
        std::string_view r = trim(arm.substr(4));
        std::size_t colon = r.find(':');
        if (colon == std::string_view::npos) throw std::runtime_error(std::string{"switch arm missing ':': "} + std::string{arm});
        // Skip the case number; positional ordering implies value 0..N-1.
        (void)parseNum(trim(r.substr(0, colon)));
        std::string_view body2 = trim(r.substr(colon + 1));
        if (!startsWith(body2, "goto")) throw std::runtime_error(std::string{"switch arm expected 'goto': "} + std::string{arm});
        std::string_view lbl = trim(body2.substr(4));
        targets.push_back(resolve(lbl));
    }

    std::vector<u8> out(1 + 1 + 2 + 2 * targets.size(), 0);
    out[0] = 0x18;
    out[1] = static_cast<u8>(pstat);
    writeI16(out, 2, static_cast<i16>(targets.size()));
    for (std::size_t k = 0; k < targets.size(); ++k) {
        writeI16(out, 4 + k * 2, static_cast<i16>(targets[k]));
    }
    return out;
}

std::size_t sizeOfSwitchStmt(std::string_view body) {
    std::size_t lp = body.find('(');
    std::size_t rp = findMatchingRparen(body, lp);
    std::string_view rest = trim(body.substr(rp + 1));
    std::string_view inside;
    parseBraced(rest, inside);
    auto arms = splitTopSemis(inside);
    return 1 + 1 + 2 + arms.size() * 2;
}

// Parse hex byte list inside `{ ... }`.
std::vector<u8> parseHexBytes(std::string_view inside) {
    std::vector<u8> out;
    for (auto tok : splitWhitespace(trim(inside))) {
        unsigned v = 0;
        if (tok.empty()) continue;
        for (char c : tok) {
            v <<= 4;
            if      (c >= '0' && c <= '9') v |= (c - '0');
            else if (c >= 'a' && c <= 'f') v |= (c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') v |= (c - 'A' + 10);
            else throw std::runtime_error(std::string{"bad hex byte: "} + std::string{tok});
        }
        out.push_back(static_cast<u8>(v));
    }
    return out;
}

// Categorize a statement body into one of the structured forms below, or
// fall through to the generic `mnemonic(args)` path.
enum class StmtKind {
    Return, Goto, If, Switch, SetSelection, Garbage, Bytes, DeadString, Raw, Call
};

// Inspect the leading keyword and structural shape of `body` (which has had
// its trailing `;` already stripped).
StmtKind classifyStmt(std::string_view body) {
    if (body == "return" || startsWith(body, "return ")) return StmtKind::Return;
    if (startsWith(body, "goto ") || body == "goto") return StmtKind::Goto;
    if (startsWith(body, "if") && body.size() > 2 && (body[2] == ' ' || body[2] == '(')) return StmtKind::If;
    if (startsWith(body, "switch") && body.size() > 6 && (body[6] == ' ' || body[6] == '(')) return StmtKind::Switch;

    // Mnemonic-prefixed: setSelection / garbage / bytes / dead_string / other call
    std::string_view ident = leadingIdent(body);
    if (ident == "setSelection") return StmtKind::SetSelection;
    if (ident == "garbage") return StmtKind::Garbage;
    if (ident == "bytes") return StmtKind::Bytes;
    if (ident == "dead_string") return StmtKind::DeadString;
    if (ident == "raw") return StmtKind::Raw;
    return StmtKind::Call;
}

} // namespace

// Instruction size + encode

namespace {

const FixedOpcode* findFixedByMnemonic(std::string_view mnemonic) {
    const auto& t = fixedOpcodes();
    for (const auto& [op, def] : t) {
        if (def.mnemonic == mnemonic) return &def;
    }
    return nullptr;
}

std::pair<const FixedOpcode*, u8> findFixedByMnemonicWithOp(std::string_view mnemonic) {
    const auto& t = fixedOpcodes();
    for (const auto& [op, def] : t) {
        if (def.mnemonic == mnemonic) return { &def, op };
    }
    return { nullptr, 0 };
}

// Forward decl -- defined later in this TU.
std::vector<u8> encodeFixed(const FixedOpcode& def, u8 op, std::string_view args,
                            const Resolver& resolve,
                            const MnemonicSynonym* syn);

// Pick the canonical FixedOpcode mnemonic that a movement-family call should
// dispatch to, based on which named args are present.  Pure inspection -- no
// allocations, no label resolution; used both at sizing and encoding time.
std::string_view dispatchMovementOpcode(std::string_view verb, std::string_view args) {
    std::unordered_map<std::string, std::string_view> byName;
    for (auto p : splitTopCommas(args)) {
        if (!isNamedArgPiece(p)) continue;
        auto [n, v] = splitNamedArg(p);
        byName[std::string{n}] = v;
    }
    auto has = [&](std::string_view k) {
        return byName.count(std::string{k}) > 0;
    };
    auto getBoolFlag = [&](std::string_view k) {
        auto it = byName.find(std::string{k});
        if (it == byName.end()) return false;
        std::string_view v = trim(it->second);
        return v == "true" || v == "1";
    };
    auto toIsTuple = [&]() {
        auto it = byName.find("to");
        if (it == byName.end()) return false;
        std::string_view v = trim(it->second);
        return !v.empty() && v.front() == '(';
    };

    if (verb == "move") {
        bool wc = getBoolFlag("withCamera");
        if (has("axis")) return wc ? "moveEntityToAxisWithCamera" : "moveEntityToAxis";
        if (toIsTuple()) {
            if (has("animDuration")) return "moveEntityTo";
            return wc ? "entityWalkToWithCamera" : "entityWalkTo";
        }
        return wc ? "entityWalkToEntityWithCamera" : "entityWalkToEntity";
    }
    if (verb == "moveCamera") {
        return toIsTuple() ? "moveCameraTo" : "moveCameraToEntity";
    }
    if (verb == "look")     return "lookAt";
    if (verb == "rotate")   return "setRotation";
    if (verb == "teleport") return "teleport";
    if (verb == "warp")     return "warpTo";
    return {};
}

bool isMovementVerb(std::string_view m) {
    return m == "move" || m == "moveCamera" || m == "look" ||
           m == "rotate" || m == "teleport" || m == "warp";
}

// Encode a movement-family call by dispatching to the right canonical opcode
// and remapping the user-facing named args.
std::vector<u8> encodeMovement(std::string_view verb, std::string_view args,
                               const Resolver& resolve) {
    auto pieces = splitTopCommas(args);
    std::unordered_map<std::string, std::string_view> byName;
    for (const auto& p : pieces) {
        if (!isNamedArgPiece(p)) {
            throw std::runtime_error(std::string{verb} + ": expects named args (e.g. `to: ...`)");
        }
        auto [n, v] = splitNamedArg(p);
        byName[std::string{n}] = v;
    }
    auto get = [&](std::string_view k) -> std::optional<std::string_view> {
        auto it = byName.find(std::string{k});
        if (it == byName.end()) return std::nullopt;
        return it->second;
    };
    auto callFixed = [&](std::string_view canonical, const std::string& a) {
        auto [def, op] = findFixedByMnemonicWithOp(canonical);
        if (!def) throw std::runtime_error(std::string{"unknown opcode: "} + std::string{canonical});
        return encodeFixed(*def, op, a, resolve, /*syn=*/nullptr);
    };
    auto splitTuple = [&](std::string_view t) {
        t = trim(t);
        if (t.empty() || t.front() != '(' || t.back() != ')') {
            throw std::runtime_error("expected (x, y) tuple");
        }
        auto inner = splitTopCommas(t.substr(1, t.size() - 2));
        if (inner.size() != 2) throw std::runtime_error("tuple must be (x, y)");
        return std::pair<std::string, std::string>{
            std::string{trim(inner[0])}, std::string{trim(inner[1])}
        };
    };

    std::string_view canonical = dispatchMovementOpcode(verb, args);
    if (canonical.empty()) throw std::runtime_error(std::string{"unknown movement verb: "} + std::string{verb});

    if (canonical == "entityWalkTo" || canonical == "entityWalkToWithCamera") {
        auto e = get("entity"); auto to = get("to"); auto sp = get("sprint");
        if (!e || !to) throw std::runtime_error(std::string{verb} + ": missing entity/to");
        auto [x, y] = splitTuple(*to);
        std::string a = "entity: " + std::string{*e};
        a += ", positionX: " + x;
        a += ", positionY: " + y;
        a += ", sprint: " + std::string{sp ? *sp : std::string_view{"0"}};
        return callFixed(canonical, a);
    }
    if (canonical == "entityWalkToEntity" || canonical == "entityWalkToEntityWithCamera") {
        auto e = get("entity"); auto to = get("to"); auto sp = get("sprint");
        if (!e || !to) throw std::runtime_error(std::string{verb} + ": missing entity/to");
        std::string a = "entity: " + std::string{*e};
        a += ", sprint: " + std::string{sp ? *sp : std::string_view{"0"}};
        a += ", target: " + std::string{*to};
        return callFixed(canonical, a);
    }
    if (canonical == "moveEntityTo") {
        auto e = get("entity"); auto to = get("to"); auto d = get("animDuration");
        if (!e || !to || !d) throw std::runtime_error("move(animDuration): missing entity/to/animDuration");
        auto [x, y] = splitTuple(*to);
        std::string a = "entity: " + std::string{*e};
        a += ", positionX: " + x;
        a += ", positionY: " + y;
        a += ", animationDuration: " + std::string{*d};
        return callFixed("moveEntityTo", a);
    }
    if (canonical == "moveEntityToAxis" || canonical == "moveEntityToAxisWithCamera") {
        auto e = get("entity"); auto to = get("to"); auto ax = get("axis"); auto sp = get("speed");
        if (!e || !to || !ax || !sp) throw std::runtime_error("move(axis): missing entity/to/axis/speed");
        std::string a = "entity: " + std::string{*e};
        a += ", position: " + std::string{*to};
        a += ", axis: " + std::string{*ax};
        a += ", speed: " + std::string{*sp};
        return callFixed(canonical, a);
    }
    if (canonical == "moveCameraTo") {
        auto to = get("to"); auto sd = get("slowdown");
        if (!to) throw std::runtime_error("moveCamera: missing to");
        auto [x, y] = splitTuple(*to);
        std::string a = "cameraSlowdown: " + std::string{sd ? *sd : std::string_view{"0"}};
        a += ", positionX: " + x;
        a += ", positionY: " + y;
        return callFixed("moveCameraTo", a);
    }
    if (canonical == "moveCameraToEntity") {
        auto to = get("to"); auto sp = get("speed");
        if (!to) throw std::runtime_error("moveCamera: missing to");
        std::string a = "entity: " + std::string{*to};
        a += ", speed: " + std::string{sp ? *sp : std::string_view{"0"}};
        return callFixed("moveCameraToEntity", a);
    }
    if (canonical == "lookAt") {
        auto e = get("entity"); auto at = get("at");
        if (!e || !at) throw std::runtime_error("look: missing entity/at");
        std::string a = "entity: " + std::string{*e};
        a += ", target: " + std::string{*at};
        return callFixed("lookAt", a);
    }
    if (canonical == "setRotation") {
        auto e = get("entity"); auto to = get("to");
        if (!e || !to) throw std::runtime_error("rotate: missing entity/to");
        std::string a = "entity: " + std::string{*e};
        a += ", rotation: " + std::string{*to};
        return callFixed("setRotation", a);
    }
    if (canonical == "teleport") {
        auto p = get("pstat");
        if (!p) throw std::runtime_error("teleport: missing pstat");
        return callFixed("teleport", "pstat: " + std::string{*p});
    }
    if (canonical == "warpTo") {
        auto to = get("to"); auto sp = get("spawn"); auto tr = get("trigger");
        if (!to || !sp || !tr) throw std::runtime_error("warp: missing to/spawn/trigger");
        std::string a = "mapId: " + std::string{*to};
        a += ", spawnPoint: " + std::string{*sp};
        a += ", activateTrigger: " + std::string{*tr};
        return callFixed("warpTo", a);
    }
    throw std::runtime_error(std::string{"movement dispatch: unhandled canonical "} + std::string{canonical});
}

std::size_t instructionSize(std::string_view body) {
    StmtKind k = classifyStmt(body);

    switch (k) {
        case StmtKind::Return: {
            const auto* fx = findFixedByMnemonic("endSection");
            return fx ? fx->size : 2;
        }
        case StmtKind::Goto: {
            const auto* fx = findFixedByMnemonic("jump");
            return fx ? fx->size : 4;
        }
        case StmtKind::If:           return sizeOfIfStmt(body.substr(2));
        case StmtKind::Switch:       return sizeOfSwitchStmt(body.substr(6));
        case StmtKind::SetSelection: {
            std::string_view m, args;
            parseCall(body, m, args);
            auto pieces = splitTopCommas(args);
            std::size_t n = 0;
            for (auto& p : pieces) if (!p.empty()) n++;
            return 1 + 1 + n * 2;
        }
        case StmtKind::Garbage: {
            std::string_view inside;
            parseBraced(body, inside);
            auto bytes = parseHexBytes(inside);
            return 1 + 1 + bytes.size();
        }
        case StmtKind::Bytes: {
            std::string_view inside;
            parseBraced(body, inside);
            auto bytes = parseHexBytes(inside);
            return bytes.size();
        }
        case StmtKind::Raw: {
            std::string_view m, args;
            parseCall(body, m, args);
            auto pieces = splitTopCommas(args);
            std::size_t n = 0;
            for (const auto& p : pieces) {
                std::string_view t = trim(p);
                if (t.empty()) continue;
                auto startsWithP = [&](std::string_view pre) {
                    return t.size() > pre.size() && t.compare(0, pre.size(), pre) == 0 && t.back() == ')';
                };
                if (startsWithP("u16(") || startsWithP("s16(")) n += 2;
                else if (startsWithP("u32(") || startsWithP("s32(")) n += 4;
                else /* u8 / s8 / bare */ n += 1;
            }
            return n;
        }
        case StmtKind::DeadString: {
            std::string_view m, args;
            parseCall(body, m, args);
            std::string txt = unquoteString(args);
            return 2 * parseStringToU16s(txt).size() + 2;
        }
        case StmtKind::Call: {
            std::string_view m, args;
            if (!parseCall(body, m, args)) {
                // Bare-mnemonic (no parens) -- treat as zero-arg call.
                m = trim(body);
                args = {};
            }
            if (m == "showTextbox") {
                std::string txt = unquoteString(args);
                return 1 + 1 + 2 * parseStringToU16s(txt).size() + 2;
            }
            if (m == "tournamentData") {
                auto pieces = splitTopCommas(args);
                std::size_t n = 0;
                for (auto& p : pieces) if (!p.empty()) n++;
                return 1 + 1 + n;
            }
            if (m == "clearInventory") return 1;
            if (isMovementVerb(m)) {
                auto canonical = dispatchMovementOpcode(m, args);
                if (canonical.empty()) throw std::runtime_error(std::string{"unknown movement: "} + std::string{m});
                if (const auto* fx = findFixedByMnemonic(canonical)) return fx->size;
                throw std::runtime_error(std::string{"unknown opcode: "} + std::string{canonical});
            }
            const MnemonicSynonym* syn = findSynonymByUser(m);
            std::string_view canonical = syn ? syn->canonical : m;
            if (const auto* fx = findFixedByMnemonic(canonical)) return fx->size;
            throw std::runtime_error(std::string{"unknown mnemonic: "} + std::string{m});
        }
    }
    throw std::runtime_error("unreachable");
}

void writeField(std::vector<u8>& buf, std::size_t off, FieldKind k, int val) {
    switch (k) {
        case FieldKind::U8:  buf[off] = static_cast<u8>(val & 0xff); break;
        case FieldKind::S8:  buf[off] = static_cast<u8>(val); break;
        case FieldKind::U16: writeU16(buf, off, static_cast<u16>(val & 0xffff)); break;
        case FieldKind::S16: writeI16(buf, off, static_cast<i16>(val)); break;
        case FieldKind::U32: writeU32(buf, off, static_cast<u32>(val)); break;
        case FieldKind::S32: writeI32(buf, off, static_cast<i32>(val)); break;
    }
}

bool isFixedTargetField(std::string_view mnemonic, std::string_view fieldName) {
    if (mnemonic == "jump" && fieldName == "target") return true;
    if (mnemonic == "jumpAndLink" && fieldName == "value") return true;
    return false;
}

// Parse a single arg value into an int, handling labels (resolved through
// `resolve`), Ruby-style `:Symbol` shorthand whose kind is inferred from
// the field's metadata, symbolic <Kind>.<Name>, bare names in the expected
// kind, or numeric literals.  `fieldName` is the canonical (opcode-side)
// name.
int parseFieldValue(std::string_view tok, std::string_view mnemonic,
                    std::string_view fieldName, const Resolver& resolve) {
    tok = trim(tok);
    if (!tok.empty() && tok[0] == ':') {
        std::string_view name = tok.substr(1);
        auto k = fieldSymbolKind(mnemonic, fieldName);
        if (!k) {
            throw std::runtime_error(std::string{mnemonic}
                + ": `:" + std::string{name}
                + "` shorthand on non-symbolic field `" + std::string{fieldName} + "`");
        }
        int v;
        if (!lookupBareNameInScope(g_localSyms, *k, name, v)) {
            throw std::runtime_error(std::string{"`:"} + std::string{name}
                + "` unbound in kind `" + std::string{symKindLabel(*k)} + "`");
        }
        return v;
    }
    char c0 = tok.empty() ? '\0' : tok[0];
    const bool labelLike = isIdentStart(c0);
    if (labelLike && isFixedTargetField(mnemonic, fieldName)) {
        return resolve(tok);
    }
    return parseNumOrSym(tok, fieldSymbolKind(mnemonic, fieldName));
}

std::vector<u8> encodeFixed(const FixedOpcode& def, u8 op, std::string_view args,
                            const Resolver& resolve,
                            const MnemonicSynonym* syn = nullptr) {
    auto pieces = splitTopCommas(args);
    while (!pieces.empty() && pieces.back().empty()) pieces.pop_back();

    // Sort pieces into positional and named.  Positional must come before
    // named (no positional may follow a named arg).
    std::vector<std::string_view> positional;
    std::unordered_map<std::string, std::string_view> byName;
    bool namedSeen = false;
    for (const auto& p : pieces) {
        if (isNamedArgPiece(p)) {
            namedSeen = true;
            auto [n, v] = splitNamedArg(p);
            std::string canonical{translateFieldName(syn, n)};
            byName[std::move(canonical)] = v;
        } else {
            if (namedSeen) {
                throw std::runtime_error(std::string{def.mnemonic}
                    + ": positional arg after named");
            }
            positional.push_back(p);
        }
    }

    std::vector<u8> out(def.size, 0);
    out[0] = op;

    // If purely positional and the count matches total fields (including
    // empties), keep the legacy semantics of filling every field -- useful
    // for the rare case of explicit non-zero `empty` slots.
    const bool purelyPositional = byName.empty();
    if (purelyPositional && pieces.size() == def.fields.size()) {
        std::size_t cursor = 1;
        std::size_t argIdx = 0;
        for (const auto& f : def.fields) {
            const u8 sz = fieldSize(f.k);
            int val = parseFieldValue(pieces[argIdx++], def.mnemonic, f.n, resolve);
            writeField(out, cursor, f.k, val);
            cursor += sz;
        }
        return out;
    }

    // Mixed (or all-named, or short positional): positional consumes the
    // first K non-empty fields; named fills by name; any conflict is an
    // error; `empty` and unspecified fields default to 0.
    {
        std::unordered_set<std::string> filledByPositional;
        std::size_t pi = 0;
        for (const auto& f : def.fields) {
            if (pi >= positional.size()) break;
            if (f.n == "empty") continue;
            filledByPositional.insert(std::string{f.n});
            ++pi;
        }
        for (const auto& [name, _] : byName) {
            if (filledByPositional.count(name)) {
                throw std::runtime_error(std::string{def.mnemonic}
                    + ": arg `" + name + "` given both positionally and by name");
            }
        }
        std::size_t cursor = 1;
        std::size_t posIdx = 0;
        for (const auto& f : def.fields) {
            const u8 sz = fieldSize(f.k);
            auto it = byName.find(std::string{f.n});
            if (it != byName.end()) {
                int val = parseFieldValue(it->second, def.mnemonic, f.n, resolve);
                writeField(out, cursor, f.k, val);
            } else if (f.n != "empty" && posIdx < positional.size()) {
                int val = parseFieldValue(positional[posIdx], def.mnemonic, f.n, resolve);
                writeField(out, cursor, f.k, val);
                ++posIdx;
            }
            cursor += sz;
        }
        return out;
    }
}

std::vector<u8> encodeInstr(const Instr& instr, const Resolver& resolve) {
    std::string_view body = instr.body;
    StmtKind k = classifyStmt(body);

    switch (k) {
        case StmtKind::Return: {
            auto [def, op] = findFixedByMnemonicWithOp("endSection");
            if (!def) throw std::runtime_error("endSection missing");
            std::vector<u8> out(def->size, 0);
            out[0] = op;
            return out;
        }
        case StmtKind::Goto: {
            std::string_view lbl = trim(body.substr(4));
            auto [def, op] = findFixedByMnemonicWithOp("jump");
            if (!def) throw std::runtime_error("jump missing");
            std::vector<u8> out(def->size, 0);
            out[0] = op;
            // Find the target field offset.
            std::size_t cursor = 1;
            for (const auto& f : def->fields) {
                if (f.n == "target") {
                    writeField(out, cursor, f.k, resolve(lbl));
                    break;
                }
                cursor += fieldSize(f.k);
            }
            return out;
        }
        case StmtKind::If: {
            return encodeIfStmt(body.substr(2), resolve);
        }
        case StmtKind::Switch: {
            return encodeSwitchStmt(body.substr(6), resolve);
        }
        case StmtKind::SetSelection: {
            std::string_view m, args;
            parseCall(body, m, args);
            auto pieces = splitTopCommas(args);
            std::vector<std::string> labels;
            for (auto& p : pieces) if (!p.empty()) labels.emplace_back(p);
            std::vector<u8> out(2 + labels.size() * 2, 0);
            out[0] = 0x10;
            out[1] = static_cast<u8>(labels.size());
            for (std::size_t i = 0; i < labels.size(); ++i) {
                writeI16(out, 2 + i * 2, static_cast<i16>(resolve(labels[i])));
            }
            return out;
        }
        case StmtKind::Garbage: {
            std::string_view inside;
            parseBraced(body, inside);
            auto payload = parseHexBytes(inside);
            std::vector<u8> out(2 + payload.size(), 0);
            out[0] = 0xff;
            out[1] = 0x00;
            for (std::size_t i = 0; i < payload.size(); ++i) out[2 + i] = payload[i];
            return out;
        }
        case StmtKind::Bytes: {
            std::string_view inside;
            parseBraced(body, inside);
            return parseHexBytes(inside);
        }
        case StmtKind::Raw: {
            // `raw(b1, b2, ...);` -- each arg becomes 1+ bytes.  Forms accepted:
            //   * bare expression -> u8 (default width)
            //   * `s16(expr)` / `s32(expr)` / `u16(expr)` / `u8(expr)` --
            //     emits the value little-endian at the named width
            //   * Inside any of the above (and at the bare top), `expr` may be:
            //     - decimal / hex literal
            //     - qualified `Kind.Name`
            //     - `<Kind>!<expr2>` -- kind-annotated; expr2 may be `:Name`
            //       or bare `Name` resolved in `<Kind>`
            std::string_view m, args;
            parseCall(body, m, args);
            auto pieces = splitTopCommas(args);
            std::vector<u8> out;
            out.reserve(pieces.size());

            auto resolveOne = [&](std::string_view t) -> int {
                std::optional<SymKind> kindCtx;
                std::string_view expr = t;
                std::size_t bang = t.find('!');
                if (bang != std::string_view::npos) {
                    std::string_view kindTok = trim(t.substr(0, bang));
                    if (!kindTok.empty()) {
                        kindCtx = symKindFromLabel(kindTok);
                        if (!kindCtx) {
                            throw std::runtime_error(
                                std::string{"raw: unknown kind `"} + std::string{kindTok}
                                + "` (expected capitalized kind: Digimon, Entity, Item, Move, "
                                  "Stat, Condition, Map, Trigger, PStat, Animation)");
                        }
                        expr = trim(t.substr(bang + 1));
                    }
                }
                if (!expr.empty() && expr[0] == ':') {
                    if (!kindCtx) {
                        throw std::runtime_error(
                            std::string{"raw: `:Name` needs a kind annotation: `<kind>!"}
                            + std::string{expr} + "`");
                    }
                    std::string_view name = expr.substr(1);
                    int v;
                    if (!lookupBareNameInScope(g_localSyms, *kindCtx, name, v)) {
                        throw std::runtime_error(std::string{"raw: `:"} + std::string{name}
                            + "` unbound in kind `" + std::string{symKindLabel(*kindCtx)} + "`");
                    }
                    return v;
                }
                return parseNumOrSym(expr, kindCtx);
            };

            auto emitLE = [&](long long v, int width) {
                for (int i = 0; i < width; ++i) {
                    out.push_back(static_cast<u8>((v >> (8 * i)) & 0xff));
                }
            };

            auto stripWrapper = [](std::string_view t,
                                    std::string_view prefix,
                                    std::string_view& inner) -> bool {
                if (t.size() <= prefix.size()) return false;
                if (t.compare(0, prefix.size(), prefix) != 0) return false;
                if (t.back() != ')') return false;
                inner = trim(t.substr(prefix.size(), t.size() - prefix.size() - 1));
                return true;
            };

            for (const auto& p : pieces) {
                std::string_view t = trim(p);
                if (t.empty()) continue;
                std::string_view inner;
                if      (stripWrapper(t, "u8(",  inner)) { int v = resolveOne(inner); emitLE(v, 1); }
                else if (stripWrapper(t, "s8(",  inner)) { int v = resolveOne(inner); emitLE(v, 1); }
                else if (stripWrapper(t, "u16(", inner)) { int v = resolveOne(inner); emitLE(v, 2); }
                else if (stripWrapper(t, "s16(", inner)) { int v = resolveOne(inner); emitLE(v, 2); }
                else if (stripWrapper(t, "u32(", inner)) { int v = resolveOne(inner); emitLE(static_cast<long long>(static_cast<unsigned>(v)), 4); }
                else if (stripWrapper(t, "s32(", inner)) { int v = resolveOne(inner); emitLE(v, 4); }
                else {
                    int v = resolveOne(t);
                    if (v < -128 || v > 255) {
                        throw std::runtime_error(std::string{"raw: value out of u8 range (use s16/s32 wrapper): "} + std::string{t});
                    }
                    emitLE(v, 1);
                }
            }
            return out;
        }
        case StmtKind::DeadString: {
            std::string_view m, args;
            parseCall(body, m, args);
            std::string txt = unquoteString(args);
            auto u16s = parseStringToU16s(txt);
            std::vector<u8> out(2 * u16s.size() + 2, 0);
            for (std::size_t i = 0; i < u16s.size(); ++i) writeU16(out, i * 2, u16s[i]);
            return out;
        }
        case StmtKind::Call: {
            std::string_view m, args;
            if (!parseCall(body, m, args)) {
                m = trim(body);
                args = {};
            }
            if (m == "showTextbox") {
                std::string txt = unquoteString(args);
                auto u16s = parseStringToU16s(txt);
                std::vector<u8> out(2 + u16s.size() * 2 + 2, 0);
                out[0] = 0x1a;
                out[1] = 0x00;
                for (std::size_t i = 0; i < u16s.size(); ++i) writeU16(out, 2 + i * 2, u16s[i]);
                return out;
            }
            if (m == "tournamentData") {
                auto pieces = splitTopCommas(args);
                std::vector<int> vals;
                for (auto& p : pieces) if (!p.empty()) vals.push_back(parseNum(p));
                std::vector<u8> out(2 + vals.size(), 0);
                out[0] = 0x6b;
                out[1] = 0x00;
                for (std::size_t i = 0; i < vals.size(); ++i) out[2 + i] = static_cast<u8>(vals[i]);
                return out;
            }
            if (m == "clearInventory") {
                return std::vector<u8>{ 0x3a };
            }
            if (isMovementVerb(m)) {
                return encodeMovement(m, args, resolve);
            }
            const MnemonicSynonym* syn = findSynonymByUser(m);
            std::string_view canonical = syn ? syn->canonical : m;
            auto [def, op] = findFixedByMnemonicWithOp(canonical);
            if (!def) throw std::runtime_error(std::string{"unknown mnemonic: "} + std::string{m});
            return encodeFixed(*def, op, args, resolve, syn);
        }
    }
    throw std::runtime_error("encodeInstr: unreachable");
}

std::size_t computeScriptSize(const ScriptAST& s) {
    std::size_t N = s.sections.size();
    std::size_t body = 0;
    for (const auto& sec : s.sections) {
        for (const auto& instr : sec.instrs) body += instructionSize(instr.body);
    }
    return 2 + 4 * N + 2 + body;
}

} // namespace

// assembleContainer

std::vector<u8> assembleContainer(ContainerAST& ast, EmitMap* outMap) {
    std::unordered_map<int, ScriptAST*> scriptsBySlot;
    for (auto& s : ast.scripts) scriptsBySlot[s.index] = &s;

    std::size_t fileLen = 0;
    const u32 align = ast.alignment ? ast.alignment : 0x800;

    if (ast.kind == AsmKind::DG) {
        constexpr std::size_t headerBytes = 0x800;
        std::size_t cursor = headerBytes;
        for (const auto& fr : ast.files) {
            auto it = scriptsBySlot.find(fr.slot);
            if (it == scriptsBySlot.end() || it->second->sections.empty()) continue;
            LocalSymsScope guard(&it->second->localSymbols);
            std::size_t raw = computeScriptSize(*it->second);
            cursor += (raw + align - 1) & ~static_cast<std::size_t>(align - 1);
        }
        fileLen = cursor;
    } else if (!ast.scripts.empty()) {
        LocalSymsScope guard(&ast.scripts[0].localSymbols);
        fileLen = computeScriptSize(ast.scripts[0]);
    }

    std::vector<u8> out(fileLen, 0);

    if (ast.kind == AsmKind::DG) {
        constexpr std::size_t headerBytes = 0x800;
        std::size_t cursor = headerBytes;
        std::unordered_map<int, std::size_t> slotStart;
        for (const auto& fr : ast.files) {
            slotStart[fr.slot] = cursor;
            auto it = scriptsBySlot.find(fr.slot);
            if (it == scriptsBySlot.end() || it->second->sections.empty()) continue;
            LocalSymsScope guard(&it->second->localSymbols);
            std::size_t raw = computeScriptSize(*it->second);
            cursor += (raw + align - 1) & ~static_cast<std::size_t>(align - 1);
        }
        for (int slot = 0; slot < 223; ++slot) {
            auto it = slotStart.find(slot);
            u32 v = (it == slotStart.end()) ? static_cast<u32>(cursor) : static_cast<u32>(it->second);
            writeU32(out, slot * 4, v);
        }
        if (!slotStart.count(222)) writeU32(out, 222 * 4, static_cast<u32>(cursor));
        writeU32(out, 223 * 4, DG_END_POINTER);

        std::size_t fnOffset = 0x380;
        for (const auto& fr : ast.files) {
            std::string up = toUpperAscii(fr.name);
            if (!(startsWith(up, "MAP") && endsWith(up, ".SCN"))) continue;
            std::string mid = up.substr(3, up.size() - 7);
            if (mid.empty()) continue;
            int parsed = 0;
            bool ok = true;
            for (char c : mid) {
                if (c < '0' || c > '9') { ok = false; break; }
                parsed = parsed * 10 + (c - '0');
            }
            if (!ok || parsed != fr.slot) continue;

            std::array<u8, 32> entry{};
            std::string textline = "\\" + up;
            for (std::size_t i = 0; i < textline.size() && i < 27; ++i) {
                entry[i] = static_cast<u8>(textline[i]);
            }
            entry[28] = static_cast<u8>(DG_END_POINTER & 0xff);
            entry[29] = static_cast<u8>((DG_END_POINTER >> 8) & 0xff);
            entry[30] = static_cast<u8>((DG_END_POINTER >> 16) & 0xff);
            entry[31] = static_cast<u8>((DG_END_POINTER >> 24) & 0xff);
            for (std::size_t i = 0; i < 32; ++i) out[fnOffset + i] = entry[i];
            fnOffset += 32;
        }
    }

    auto baseOf = [&](const ScriptAST& s) -> std::size_t {
        if (ast.kind == AsmKind::Maphead) return 0;
        return readU32(out, static_cast<std::size_t>(s.index) * 4);
    };

    for (auto& script : ast.scripts) {
        LocalSymsScope guard(&script.localSymbols);
        const std::size_t N = script.sections.size();
        std::size_t offset = 4 + 4 * N;
        for (auto& sec : script.sections) {
            sec.labelMap.clear();
            std::size_t secSize = 0;
            for (auto& instr : sec.instrs) {
                for (const auto& lbl : instr.labels) {
                    sec.labelMap[lbl] = secSize;
                }
                std::size_t sz = instructionSize(instr.body);
                instr.size = sz;
                secSize += sz;
            }
            for (const auto& lbl : sec.trailingLabels) {
                sec.labelMap[lbl] = secSize;
            }
            sec.offset = offset;
            sec.size = secSize;
            offset += secSize;
        }
        if (script.sections.empty()) continue;

        std::size_t base = baseOf(script);
        if (base >= out.size()) continue;
        writeU16(out, base, script.headerU16);
        std::size_t cursor = base + 2;
        for (const auto& sec : script.sections) {
            writeU16(out, cursor,     static_cast<u16>(sec.id));
            writeU16(out, cursor + 2, static_cast<u16>(sec.offset));
            cursor += 4;
        }
        writeU16(out, cursor, 0xffff);

        Resolver scriptResolver = makeResolver(script);
        for (const auto& sec : script.sections) {
            auto resolve = makeInSectionResolver(scriptResolver, sec, static_cast<int>(sec.offset));
            std::size_t pc = base + sec.offset;
            for (const auto& instr : sec.instrs) {
                auto bytes = encodeInstr(instr, resolve);
                if (bytes.size() != instr.size) {
                    throw std::runtime_error(std::string{"size mismatch for "} + instr.body
                        + ": predicted " + toDec(static_cast<long long>(instr.size))
                        + ", got " + toDec(static_cast<long long>(bytes.size())));
                }
                if (pc + bytes.size() > out.size()) {
                    throw std::runtime_error(std::string{"overflow: slot "} + toDec(script.index)
                        + " section " + toDec(sec.id)
                        + " pc=0x" + toHex(pc) + " (instr: " + instr.body + ")");
                }
                if (outMap) {
                    outMap->spans.push_back(EmitSpan{
                        pc, bytes.size(),
                        script.index, sec.id, sec.disambig,
                        instr.srcFile, instr.srcLine, instr.srcCol,
                        instr.body,
                    });
                }
                for (std::size_t i = 0; i < bytes.size(); ++i) out[pc + i] = bytes[i];
                pc += bytes.size();
            }
        }
    }
    return out;
}


} // namespace dd
