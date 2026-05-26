// Symbol bindings: numeric IDs -> human names, loaded from
// `entities.dgs` (searched in CWD) and from per-script `symbols { }`
// blocks at the top of a `.dgs` file.
//
// Disasm prefers the named form `<Kind>.<Name>` (e.g.
// `Digimon.ModokiBetamon`) when a binding exists; the assembler accepts
// both that form and bare names inside kind-determined slots
// (`pstat[mapState]`, `trigger(CaveOpen)`, `loadDigimon(Agumon)`, ...).

#pragma once

#include "common.hpp"

#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace dd {

enum class SymKind {
    Entity, Digimon, Item, Move, Stat, Condition, Map,
    Trigger,    // setTrigger / unsetTrigger / trigger() / !trigger()
    PStat,      // pstat[N] and the .pstat fields of many opcodes
    Animation,  // playAnimation `a` slot; empty entity table for now -- exists
                // so function defs can annotate `a: Animation` even before the
                // ID catalog is populated.
};

// Render kind as it appears in source: "Entity", "Digimon", ...
std::string_view symKindLabel(SymKind k);

// Inverse -- case-sensitive match on the labels above.  nullopt for unknown.
std::optional<SymKind> symKindFromLabel(std::string_view name);

// Section name in entities.dgs / `symbols { <section> { ... } }` blocks:
// "entities", "digimon", "items", "moves", "stats", "conditions", "maps",
// "triggers", "pstat".
std::optional<SymKind> symKindFromSection(std::string_view section);

struct SymbolTable {
    std::unordered_map<int, std::unordered_map<int, std::string>> byValue;     // kind -> value -> name
    std::unordered_map<int, std::unordered_map<std::string, int>> byName;       // kind -> name -> value

    // Look up the name for a value; empty if unknown.
    std::string lookupName(SymKind k, int v) const;

    // Look up a bare name for a kind; returns true when found.
    bool tryLookupBareName(SymKind k, std::string_view name, int& outValue) const;

    // Add or override a binding.
    void bind(SymKind k, std::string name, int value);
};

// Lazy singleton.  First call loads `entities.dgs` from CWD if present;
// otherwise returns an empty table (everything falls back to decimal).
const SymbolTable& symbolTable();

// (mnemonic, fieldName) -> kind, or nullopt if the field isn't symbolic.
std::optional<SymKind> fieldSymbolKind(std::string_view mnemonic,
                                       std::string_view fieldName);

// Predicate-level: the indexable predicates / call predicates whose argument
// has a known kind:
//   "pstat"   -> PStat
//   "stat"    -> Stat
//   "item"    -> Item
//   "hasTech" -> Move
//   "trigger" -> Trigger
//   (others)  -> nullopt
std::optional<SymKind> predicateIndexKind(std::string_view name);

// Try local first, then global.  Returns true and fills outValue when found.
// `local` may be null.
bool lookupBareNameInScope(const SymbolTable* local,
                           SymKind kind,
                           std::string_view name,
                           int& outValue);

bool resolveQualifiedInScope(const SymbolTable* local,
                             std::string_view qualified,
                             int& outValue);

// Look up a name for emission: local first, then global.  Empty when unknown.
std::string lookupNameInScope(const SymbolTable* local, SymKind kind, int v);

} // namespace dd
