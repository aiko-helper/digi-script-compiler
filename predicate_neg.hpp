// Predicate negation -- string-level inversion of an if-condition.
//
// Shared by assemble.cpp (block-form `if (cond) { body }` lowering needs
// to encode the *skip-when-cond* opcode, i.e. negate the condition) and
// disasm.cpp (collapsing the canonical `if (cond) goto Lx; body; Lx:`
// pattern back into `if (negate(cond)) { body }`).
//
// The engine's predicate evaluator is strictly left-associative -- the
// existing parser splits at the *rightmost* `&&` / `||`.  Under that
// rule, De Morgan reduces to flat term-by-term negation + link-byte
// flip with no parens needed:
//
//   !((A op1 B) op2 C)  ==  (!A negate(op1) !B) negate(op2) !C
//                      ==  !A negate(op1) !B negate(op2) !C   (flat)
//
// Atoms supported (matches encodePredicate in assemble.cpp and
// renderPredicate in custom-ops.cpp):
//   - pstat[N] OP V
//   - stat[Kind.Name] OP V
//   - card[N] OP V
//   - item[Kind.Name] OP V
//   - money OP V
//   - trigger(N)   <->  !trigger(N)
//
// Not supported -- throws (so the user can fall back to the goto form):
//   - hasTech(M) == V         (encoder only handles ==, no != path)
//   - (cond & 0xXX) == 0xYY   (same)
//   - in / not in ranges      (caller is expected to expand these to
//                              comparator chains BEFORE calling negate)

#pragma once

#include "common.hpp"

#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace dd {

namespace predneg {

// Strip exactly one layer of redundant outer parens.  Mirrors stripOuter
// in assemble.cpp -- kept local to avoid leaking that helper across TUs.
inline std::string stripOuterParens(std::string s) {
    auto trimInplace = [](std::string& str) {
        std::size_t a = 0, b = str.size();
        while (a < b && (str[a] == ' ' || str[a] == '\t')) ++a;
        while (b > a && (str[b - 1] == ' ' || str[b - 1] == '\t')) --b;
        str = str.substr(a, b - a);
    };
    trimInplace(s);
    while (s.size() >= 2 && s.front() == '(' && s.back() == ')') {
        int depth = 0;
        bool wraps = true;
        for (std::size_t i = 0; i < s.size(); ++i) {
            if (s[i] == '(') ++depth;
            else if (s[i] == ')') --depth;
            if (depth == 0 && i < s.size() - 1) { wraps = false; break; }
        }
        if (!wraps) break;
        s = s.substr(1, s.size() - 2);
        trimInplace(s);
    }
    return s;
}

// Negate a single (atom) predicate term -- no top-level && / ||.
// Returns the negated form as a fresh string.
inline std::string negateAtom(std::string_view sIn) {
    std::string s = stripOuterParens(std::string{sIn});
    std::string_view t{s};

    // !trigger(X)  <->  trigger(X)
    if (startsWith(t, "!trigger(") && endsWith(t, ")")) {
        return std::string{t.substr(1)};
    }
    if (startsWith(t, "trigger(") && endsWith(t, ")")) {
        return "!" + std::string{t};
    }

    // `X in S..E` <-> `X not in S..E` (same for ..=).  The range expansion
    // in encodeIfStmt accepts either form, so just toggle the keyword and
    // let the existing expander emit comparator pairs at encode time.
    {
        int depth = 0;
        for (std::size_t i = 0; i < t.size(); ++i) {
            char c = t[i];
            if (c == '(' || c == '[') { ++depth; continue; }
            if (c == ')' || c == ']') { --depth; continue; }
            if (depth != 0) continue;
            if (c != ' ') continue;
            if (t.size() - i >= 8 && t.substr(i, 8) == " not in ") {
                std::string out{t.substr(0, i)};
                out += " in ";
                out += t.substr(i + 8);
                return out;
            }
            if (t.size() - i >= 4 && t.substr(i, 4) == " in ") {
                std::string out{t.substr(0, i)};
                out += " not in ";
                out += t.substr(i + 4);
                return out;
            }
        }
    }

    // Find the *rightmost* top-level comparator -- handles atom shapes
    // where the LHS contains parens / brackets (e.g. `(cond & 0xX) == V`).
    // We reject the `(cond & ...)` and `hasTech(...) == V` shapes after
    // detection because the encoder only supports `==` for those.
    static const std::string_view ops[] = {">=", "<=", "==", "!=", ">", "<"};
    std::size_t opPos = std::string_view::npos;
    std::string_view opStr;
    {
        int depth = 0;
        for (std::size_t i = 0; i < t.size(); ++i) {
            char c = t[i];
            if (c == '(' || c == '[') { ++depth; continue; }
            if (c == ')' || c == ']') { --depth; continue; }
            if (depth != 0) continue;
            for (auto op : ops) {
                if (t.size() - i >= op.size()
                    && t.substr(i, op.size()) == op) {
                    opPos = i;
                    opStr = op;
                    break;
                }
            }
        }
    }
    if (opPos == std::string_view::npos) {
        throw std::runtime_error(
            std::string{"predicate-negate: cannot invert atom (no comparator): "}
            + std::string{sIn});
    }

    std::string_view lhs = t.substr(0, opPos);
    std::string_view rhs = t.substr(opPos + opStr.size());
    // Reject shapes the encoder only allows with `==`.
    auto lhsTrim = trim(lhs);
    if (startsWith(lhsTrim, "hasTech(") || startsWith(lhsTrim, "(cond")) {
        throw std::runtime_error(
            std::string{"predicate-negate: atom only encodable with `==` (not negatable in v1): "}
            + std::string{sIn});
    }

    std::string_view neg;
    if      (opStr == "==") neg = "!=";
    else if (opStr == "!=") neg = "==";
    else if (opStr == "<")  neg = ">=";
    else if (opStr == "<=") neg = ">";
    else if (opStr == ">")  neg = "<=";
    else /* >= */           neg = "<";

    std::string out{trim(lhs)};
    out += ' ';
    out += neg;
    out += ' ';
    out += trim(rhs);
    return out;
}

// Split at the rightmost top-level ` && ` or ` || ` (depth-aware).
// Returns nullopt if the expression has no top-level link.
struct LinkSplitView {
    std::string_view left;
    std::string_view linkSym; // " && " or " || "
    std::string_view right;
};
inline std::optional<LinkSplitView> splitRightmostLink(std::string_view s) {
    int depth = 0;
    std::size_t hit = std::string_view::npos;
    std::string_view linkSym;
    for (std::size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == '(' || c == '[') { ++depth; continue; }
        if (c == ')' || c == ']') { --depth; continue; }
        if (depth != 0) continue;
        if (c != ' ') continue;
        if (s.size() - i >= 4 && s.substr(i, 4) == " && ") {
            hit = i; linkSym = " && ";
        } else if (s.size() - i >= 4 && s.substr(i, 4) == " || ") {
            hit = i; linkSym = " || ";
        }
    }
    if (hit == std::string_view::npos) return std::nullopt;
    LinkSplitView r;
    r.left = s.substr(0, hit);
    r.linkSym = linkSym;
    r.right = s.substr(hit + 4);
    return r;
}

// Negate a full predicate expression -- any combination of && / || /
// single comparators / trigger atoms.  Output is a string the existing
// `if (<expr>) ...` parser accepts.
//
// Strategy (correct under left-associative eval, see top of file):
//   1. recursively split at rightmost link
//   2. negate each side
//   3. flip the link  ( &&  <->  || )
//   4. concat without extra parens
inline std::string negatePredicate(std::string_view sIn) {
    std::string s = stripOuterParens(std::string{sIn});
    auto sp = splitRightmostLink(s);
    if (!sp) {
        return negateAtom(s);
    }
    std::string left  = negatePredicate(sp->left);
    std::string right = negatePredicate(sp->right);
    std::string out = std::move(left);
    out += (sp->linkSym == " && ") ? " || " : " && ";
    out += right;
    return out;
}

} // namespace predneg

} // namespace dd
