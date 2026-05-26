#include "symbols.hpp"

#include <filesystem>
#include <stdexcept>

namespace dd {

namespace {

struct KindBinding {
    std::string_view tomlSection;
    std::string_view label;
    SymKind kind;
};

const std::array<KindBinding, 10> kKindTable = {{
    { "entities",   "Entity",    SymKind::Entity    },
    { "digimon",    "Digimon",   SymKind::Digimon   },
    { "items",      "Item",      SymKind::Item      },
    { "moves",      "Move",      SymKind::Move      },
    { "stats",      "Stat",      SymKind::Stat      },
    { "conditions", "Condition", SymKind::Condition },
    { "maps",       "Map",       SymKind::Map       },
    { "triggers",   "Trigger",   SymKind::Trigger   },
    { "pstat",      "PStat",     SymKind::PStat     },
    { "animations", "Animation", SymKind::Animation },
}};

// (mnemonic, fieldName) -> kind table.  Only listed pairs are symbolized.
struct FieldBinding {
    std::string_view mnemonic;
    std::string_view fieldName;
    SymKind kind;
};

const FieldBinding kFieldTable[] = {
    // Digimon
    { "loadDigimon",         "digimonId",   SymKind::Digimon },
    { "unloadModel",         "digimonId",   SymKind::Digimon },
    { "setDigimon",          "typeId",      SymKind::Digimon },
    // Entity
    { "setDigimon",          "entityId",    SymKind::Entity },
    { "unloadEntity",        "entityId",    SymKind::Entity },
    { "waitForEntity",       "entityId",    SymKind::Entity },
    { "lookAt",              "entity",      SymKind::Entity },
    { "lookAt",              "target",      SymKind::Entity },
    { "setRotation",         "entity",      SymKind::Entity },
    { "entityWalkTo",        "entity",      SymKind::Entity },
    { "moveCameraToEntity",  "entity",      SymKind::Entity },
    { "entityWalkToEntity",  "entity",      SymKind::Entity },
    { "entityWalkToEntity",  "target",      SymKind::Entity },
    { "moveCameraToEntity",  "entity",      SymKind::Entity },
    { "entityWalkToEntityWithCamera", "entity", SymKind::Entity },
    { "entityWalkToEntityWithCamera", "target", SymKind::Entity },
    { "entityWalkToWithCamera",       "entity", SymKind::Entity },
    { "playAnimation",       "entity",      SymKind::Entity },
    { "playAnimation",       "animation",   SymKind::Animation },
    { "setAutotalk",         "entity",      SymKind::Entity },
    { "moveEntityTo",        "entity",      SymKind::Entity },
    { "moveEntityToAxis",    "entity",      SymKind::Entity },
    { "moveEntityToAxisWithCamera", "entity", SymKind::Entity },
    { "setDialogOwner",      "value",       SymKind::Entity },
    // Item
    { "giveItem",            "itemId",      SymKind::Item },
    { "removeItem",          "itemId",      SymKind::Item },
    { "spawnItem",           "id",          SymKind::Item },
    { "spawnChest",          "id",          SymKind::Item },
    // Move
    { "learnMove",           "move",        SymKind::Move },
    // Stat
    { "setStats",            "stat",        SymKind::Stat },
    { "addStats",            "stat",        SymKind::Stat },
    { "reduceStats",         "stat",        SymKind::Stat },
    // Condition
    { "removeCondition",     "mask",        SymKind::Condition },
    // Map
    { "warpTo",              "mapId",       SymKind::Map },
    { "setScript",           "mapId",       SymKind::Map },
    // Trigger
    { "setTrigger",          "bit",         SymKind::Trigger },
    { "unsetTrigger",        "bit",         SymKind::Trigger },
    // PStat (most opcodes that read/write a player-stat slot index)
    { "setPStat",            "pstat",       SymKind::PStat },
    { "addPStat",            "pstat",       SymKind::PStat },
    { "reducePStat",         "pstat",       SymKind::PStat },
    { "storeMapID",          "pstat",       SymKind::PStat },
    { "storeDigimonType",    "pstat",       SymKind::PStat },
    { "storeDate",           "pstat",       SymKind::PStat },
    { "copyPStat",           "source",      SymKind::PStat },
    { "copyPStat",           "target",      SymKind::PStat },
    { "dealMapDamage",       "pstat",       SymKind::PStat },
    { "teleport",            "pstat",       SymKind::PStat },
    { "advanceToDate",       "pstat",       SymKind::PStat },
    { "addMinutesToDate",    "pstat",       SymKind::PStat },
    { "storeDigimonTypus",   "pstat",       SymKind::PStat },
    { "storeRandom",         "target",      SymKind::PStat },
};

} // namespace

std::string_view symKindLabel(SymKind k) {
    for (const auto& b : kKindTable) if (b.kind == k) return b.label;
    return "?";
}

std::optional<SymKind> symKindFromLabel(std::string_view name) {
    for (const auto& b : kKindTable) if (b.label == name) return b.kind;
    return std::nullopt;
}

std::optional<SymKind> symKindFromSection(std::string_view section) {
    for (const auto& b : kKindTable) if (b.tomlSection == section) return b.kind;
    return std::nullopt;
}

std::string SymbolTable::lookupName(SymKind k, int v) const {
    auto it = byValue.find(static_cast<int>(k));
    if (it == byValue.end()) return "";
    auto jt = it->second.find(v);
    if (jt == it->second.end()) return "";
    return jt->second;
}

bool SymbolTable::tryLookupBareName(SymKind k, std::string_view name, int& outValue) const {
    auto it = byName.find(static_cast<int>(k));
    if (it == byName.end()) return false;
    auto jt = it->second.find(std::string{name});
    if (jt == it->second.end()) return false;
    outValue = jt->second;
    return true;
}

void SymbolTable::bind(SymKind k, std::string name, int value) {
    int key = static_cast<int>(k);
    byValue[key][value] = name;
    byName[key][std::move(name)] = value;
}

namespace {

// Parse the symbols-block format used by entities.dgs and per-script
// `symbols { ... }` blocks.  Grammar:
//   symbols { <kind> { <name> = <num>; ... } <kind> { ... } ... }
// Comments (`//` to EOL) are skipped.  Negative and 0x-prefixed ints OK.
bool isIdS(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'; }
bool isIdC(char c) { return isIdS(c) || (c >= '0' && c <= '9'); }

int parseIntLit(std::string_view s) {
    s = trim(s);
    bool neg = false;
    std::size_t i = 0;
    if (i < s.size() && s[i] == '-') { neg = true; ++i; }
    int v = 0;
    if (i + 1 < s.size() && s[i] == '0' && (s[i + 1] == 'x' || s[i + 1] == 'X')) {
        i += 2;
        for (; i < s.size(); ++i) {
            char c = s[i];
            v <<= 4;
            if (c >= '0' && c <= '9') v |= c - '0';
            else if (c >= 'a' && c <= 'f') v |= c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') v |= c - 'A' + 10;
            else break;
        }
    } else {
        for (; i < s.size(); ++i) {
            if (s[i] < '0' || s[i] > '9') break;
            v = v * 10 + (s[i] - '0');
        }
    }
    return neg ? -v : v;
}

void skipWS(std::string_view s, std::size_t& i) {
    while (i < s.size()) {
        char c = s[i];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') { ++i; continue; }
        if (i + 1 < s.size() && c == '/' && s[i + 1] == '/') {
            while (i < s.size() && s[i] != '\n') ++i;
            continue;
        }
        break;
    }
}

void parseSymbolBlocks(std::string_view src, SymbolTable& out) {
    std::size_t i = 0;
    skipWS(src, i);
    // Expect leading `symbols` ident + `{`
    if (i + 7 > src.size() || src.compare(i, 7, "symbols") != 0) return;
    i += 7;
    skipWS(src, i);
    if (i >= src.size() || src[i] != '{') return;
    ++i;
    while (true) {
        skipWS(src, i);
        if (i >= src.size() || src[i] == '}') break;
        if (!isIdS(src[i])) return;
        std::size_t a = i;
        while (i < src.size() && isIdC(src[i])) ++i;
        auto kind = symKindFromSection(src.substr(a, i - a));
        skipWS(src, i);
        if (i >= src.size() || src[i] != '{') return;
        ++i;
        while (true) {
            skipWS(src, i);
            if (i >= src.size() || src[i] == '}') break;
            if (!isIdS(src[i])) return;
            std::size_t na = i;
            while (i < src.size() && isIdC(src[i])) ++i;
            std::string name{src.substr(na, i - na)};
            skipWS(src, i);
            if (i >= src.size() || src[i] != '=') return;
            ++i;
            skipWS(src, i);
            std::size_t va = i;
            while (i < src.size() && src[i] != ';' && src[i] != '\n' && src[i] != '}') ++i;
            int v = parseIntLit(src.substr(va, i - va));
            if (kind) out.bind(*kind, std::move(name), v);
            if (i < src.size() && src[i] == ';') ++i;
        }
        if (i < src.size()) ++i;  // skip `}`
    }
}

void loadInto(SymbolTable& t, const std::filesystem::path& path) {
    if (!std::filesystem::exists(path)) return;
    std::string text = readFileText(path);
    parseSymbolBlocks(text, t);
}

} // namespace

const SymbolTable& symbolTable() {
    static SymbolTable t = []() {
        SymbolTable s;
        loadInto(s, std::filesystem::path{"entities.dgs"});
        return s;
    }();
    return t;
}

std::optional<SymKind> fieldSymbolKind(std::string_view mnemonic, std::string_view fieldName) {
    for (const auto& fb : kFieldTable) {
        if (fb.mnemonic == mnemonic && fb.fieldName == fieldName) return fb.kind;
    }
    return std::nullopt;
}

std::optional<SymKind> predicateIndexKind(std::string_view name) {
    if (name == "pstat")   return SymKind::PStat;
    if (name == "stat")    return SymKind::Stat;
    if (name == "item")    return SymKind::Item;
    if (name == "hasTech") return SymKind::Move;
    if (name == "trigger") return SymKind::Trigger;
    return std::nullopt;
}

bool lookupBareNameInScope(const SymbolTable* local,
                           SymKind kind,
                           std::string_view name,
                           int& outValue) {
    if (local && local->tryLookupBareName(kind, name, outValue)) return true;
    return symbolTable().tryLookupBareName(kind, name, outValue);
}

bool resolveQualifiedInScope(const SymbolTable* local,
                             std::string_view qualified,
                             int& outValue) {
    std::size_t dot = qualified.find('.');
    if (dot == std::string_view::npos) return false;
    auto k = symKindFromLabel(qualified.substr(0, dot));
    if (!k) return false;
    std::string_view name = qualified.substr(dot + 1);
    if (local && local->tryLookupBareName(*k, name, outValue)) return true;
    if (symbolTable().tryLookupBareName(*k, name, outValue)) return true;
    throw std::runtime_error(std::string{"unknown symbol "} + std::string{qualified});
}

std::string lookupNameInScope(const SymbolTable* local, SymKind kind, int v) {
    if (local) {
        std::string n = local->lookupName(kind, v);
        if (!n.empty()) return n;
    }
    return symbolTable().lookupName(kind, v);
}

} // namespace dd
