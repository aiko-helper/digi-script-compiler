// Jump/branch target resolution and section label rendering.
//
// Branch opcodes (jump 0x16, jumpAndLink 0x13, setSelection 0x10,
// switch 0x18, if 0x19) all store script-relative byte offsets.
// Resolving them against the script's section table turns raw numbers
// into navigable labels:
//
//   offset at a section start    -> `<name>`                     (cross-section)
//   offset inside another section -> `<name>.L_<4hex>`           (cross-section)
//   offset inside `currentSec`   -> `L_<4hex>`                    (intra-section)
//   offset outside any section   -> `offset_0x<raw>`              (sentinel)
//
// Sections have a default name `section_<id>` when their id is unique
// in the script, or `section_<id>_at_<4hex>` when the id is duplicated
// (the suffix is the in-script offset of the section, padded to 4 hex
// digits).  Users can override names via names.toml; rendering uses
// the override when present.

#pragma once

#include "common.hpp"
#include "container.hpp"

#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

namespace dd {

// Engine runs section 254 on map entry; rendered as `onEnter` when unique
// AND the user hasn't supplied an override name.
inline constexpr int ON_ENTER_ID = 254;
inline constexpr std::string_view ON_ENTER_LABEL = "onEnter";

// In-script label-offset map: section index in script.sections -> set of
// in-section offsets that need an `L_<4hex>:` line.
using LabelMap = std::unordered_map<std::size_t, std::unordered_set<int>>;

// Canonical key for a section, matching the keying used in names.toml:
//   "<id>"            unique-id sections
//   "<id>@0x<off>"    duplicate-id sections
std::string sectionKey(const Script& script, const Section& sec);

// Default name for a section.  Unique-id -> "section_<id>";
// duplicate-id -> "section_<id>_at_<4hex>" (offset padded to 4 hex digits).
std::string defaultSectionName(const Script& script, const Section& sec);

// Name for a section (override if present in `script.names`, else default).
// Always returns a unique identifier inside the script.
std::string sectionName(const Script& script, const Section& sec);

// Format an in-section offset as `L_<4hex>`.
std::string labelInSection(int inSecOffset);

// Resolve a script-relative byte offset to a navigable label.
// Registers the target in `outLabels` (when non-null) so the corresponding
// section knows to emit an `L_<4hex>:` line.  `currentSec` may be null when
// the caller has no notion of "current" (then everything is qualified).
std::string resolveLabel(const Script& script,
                         const Section* currentSec,
                         int scriptOffset,
                         LabelMap* outLabels);

} // namespace dd
