#include "targets.hpp"

namespace dd {

namespace {

bool isDuplicate(const Script& script, int id) {
    int count = 0;
    for (const auto& s : script.sections) {
        if (s.id == id) {
            count++;
            if (count > 1) return true;
        }
    }
    return false;
}

// Find the index of `sec` in `script.sections` (by pointer identity).
std::size_t indexOf(const Script& script, const Section& sec) {
    for (std::size_t i = 0; i < script.sections.size(); ++i) {
        if (&script.sections[i] == &sec) return i;
    }
    return script.sections.size();
}

// Find the section containing `scriptOffset` (or null if outside all).
const Section* findContaining(const Script& script, int scriptOffset) {
    for (const auto& sec : script.sections) {
        if (scriptOffset >= sec.offset && scriptOffset < sec.end) return &sec;
    }
    return nullptr;
}

} // namespace

std::string sectionKey(const Script& script, const Section& sec) {
    if (isDuplicate(script, sec.id)) {
        std::string out = toDec(sec.id);
        out += "@0x";
        out += toHex(sec.offset);
        return out;
    }
    return toDec(sec.id);
}

std::string defaultSectionName(const Script& script, const Section& sec) {
    std::string out = "section_";
    out += toDec(sec.id);
    if (isDuplicate(script, sec.id)) {
        out += "_at_";
        out += toHexPadded(sec.offset, 4);
    }
    return out;
}

std::string sectionName(const Script& script, const Section& sec) {
    auto it = script.names.byKey.find(sectionKey(script, sec));
    if (it != script.names.byKey.end()) return it->second;
    if (sec.id == ON_ENTER_ID && !isDuplicate(script, ON_ENTER_ID)) {
        return std::string{ON_ENTER_LABEL};
    }
    return defaultSectionName(script, sec);
}

std::string labelInSection(int inSecOffset) {
    std::string out = "L_";
    out += toHexPadded(static_cast<std::uint64_t>(inSecOffset), 4);
    return out;
}

std::string resolveLabel(const Script& script,
                         const Section* currentSec,
                         int scriptOffset,
                         LabelMap* outLabels) {
    const Section* tgt = findContaining(script, scriptOffset);
    if (!tgt) {
        std::string out = "offset_0x";
        if (scriptOffset < 0) {
            out += '-';
            out += toHex(static_cast<std::uint64_t>(-scriptOffset));
        } else {
            out += toHex(static_cast<std::uint64_t>(scriptOffset));
        }
        return out;
    }
    const int delta = scriptOffset - static_cast<int>(tgt->offset);

    // Register the offset in the target section's label set (unless offset 0,
    // which is the section's natural entry point and addressed by name alone).
    if (outLabels && delta != 0) {
        (*outLabels)[indexOf(script, *tgt)].insert(delta);
    }

    if (currentSec && tgt == currentSec) {
        if (delta == 0) {
            // Self-jump to own entry -- use bare section name.
            return sectionName(script, *tgt);
        }
        return labelInSection(delta);
    }
    if (delta == 0) {
        return sectionName(script, *tgt);
    }
    std::string out = sectionName(script, *tgt);
    out += '.';
    out += labelInSection(delta);
    return out;
}

} // namespace dd
