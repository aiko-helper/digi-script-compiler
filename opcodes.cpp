// FIXED_OPCODES and CUSTOM_OPCODES data.  Mechanical port of
// opcode-table.ts -- keep fields in source order so assemble's implicit-
// empty-field heuristic behaves identically.

#include "opcodes.hpp"

namespace dd {

namespace {
using K = FieldKind;

// Helper to build a FixedOpcode with a braced-init field list.
FixedOpcode mk(std::string_view m, u8 sz, std::vector<Field> fs) {
    return FixedOpcode{ m, sz, std::move(fs) };
}
} // namespace

const FixedOpcodeTable& fixedOpcodes() {
    static const FixedOpcodeTable t = []{
        FixedOpcodeTable x;
        x.reserve(128);
        x[0x12] = mk("waitForSelectionChoice", 2, {{"empty", K::U8}});
        x[0x13] = mk("jumpAndLink", 4, {{"empty", K::U8}, {"value", K::S16}});
        x[0x14] = mk("jumpAndLinkToFile", 6, {{"empty", K::U8}, {"script", K::S16}, {"section", K::S16}});
        x[0x15] = mk("jumpReturn", 2, {{"empty", K::U8}});
        x[0x16] = mk("jump", 4, {{"empty", K::U8}, {"target", K::S16}});
        x[0x17] = mk("jumpToScriptSection", 6, {{"empty", K::U8}, {"scriptFileId", K::S16}, {"scriptSection", K::S16}});
        x[0x1b] = mk("setDialogOwner", 2, {{"value", K::U8}});
        x[0x1c] = mk("setTrigger", 4, {{"empty", K::U8}, {"bit", K::S16}});
        x[0x1d] = mk("unsetTrigger", 4, {{"empty", K::U8}, {"bit", K::S16}});
        x[0x1e] = mk("setPStat", 4, {{"empty", K::U8}, {"pstat", K::U8}, {"value", K::U8}});
        x[0x1f] = mk("addPStat", 4, {{"empty", K::U8}, {"pstat", K::U8}, {"value", K::U8}});
        x[0x20] = mk("reducePStat", 4, {{"empty", K::U8}, {"pstat", K::U8}, {"value", K::U8}});
        x[0x21] = mk("storeMapID", 2, {{"pstat", K::U8}});
        x[0x22] = mk("storeDigimonType", 2, {{"pstat", K::U8}});
        x[0x23] = mk("setInventorySize", 2, {{"size", K::U8}});
        x[0x24] = mk("storeRandom", 4, {{"empty", K::U8}, {"target", K::U8}, {"upperLimit", K::U8}});
        x[0x25] = mk("storeDate", 2, {{"pstat", K::U8}});
        x[0x26] = mk("setTextboxSize", 4, {{"empty", K::U8}, {"width", K::U8}, {"height", K::U8}});
        x[0x27] = mk("fadeOutHUD", 2, {{"empty", K::U8}});
        x[0x28] = mk("giveItem", 4, {{"empty", K::U8}, {"itemId", K::U8}, {"amount", K::U8}});
        x[0x29] = mk("removeItem", 4, {{"empty", K::U8}, {"itemId", K::U8}, {"amount", K::U8}});
        x[0x2a] = mk("addMoney", 6, {{"empty", K::U8}, {"value", K::S32}});
        x[0x2b] = mk("reduceMoney", 6, {{"empty", K::U8}, {"value", K::S32}});
        x[0x2d] = mk("learnMove", 2, {{"move", K::U8}});
        x[0x2f] = mk("giveCard", 2, {{"cardId", K::U8}});
        x[0x30] = mk("takeCard", 2, {{"cardId", K::U8}});
        x[0x31] = mk("setMerit", 4, {{"empty", K::U8}, {"value", K::S16}});
        x[0x32] = mk("addMerit", 4, {{"empty", K::U8}, {"value", K::S16}});
        x[0x34] = mk("setStats", 4, {{"stat", K::U8}, {"value", K::S16}});
        x[0x35] = mk("addStats", 4, {{"stat", K::U8}, {"value", K::S16}});
        x[0x36] = mk("reduceStats", 4, {{"stat", K::U8}, {"value", K::S16}});
        x[0x37] = mk("advanceToDate", 2, {{"pstat", K::U8}});
        x[0x38] = mk("addMinutesToDate", 6, {{"pstat", K::U8}, {"value", K::S32}});
        x[0x3f] = mk("storeDigimonTypus", 4, {{"empty", K::U8}, {"value", K::U8}, {"pstat", K::U8}});
        x[0x46] = mk("loadDigimon", 2, {{"digimonId", K::U8}});
        x[0x47] = mk("setDigimon", 4, {{"typeId", K::U8}, {"entityId", K::U8}, {"autotalk", K::U8}});
        x[0x48] = mk("unloadEntity", 2, {{"entityId", K::U8}});
        x[0x49] = mk("callDigimonSubroutine", 2, {{"routine", K::U8}});
        x[0x4a] = mk("waitForEntity", 2, {{"entityId", K::U8}});
        x[0x4b] = mk("warpTo", 4, {{"mapId", K::U8}, {"spawnPoint", K::U8}, {"activateTrigger", K::U8}});
        x[0x4c] = mk("lookAt", 4, {{"empty", K::U8}, {"entity", K::U8}, {"target", K::U8}});
        x[0x4d] = mk("setRotation", 4, {{"entity", K::U8}, {"rotation", K::S16}});
        x[0x4e] = mk("entityWalkTo", 8, {{"entity", K::U8}, {"positionX", K::S16}, {"positionY", K::S16}, {"sprint", K::S16}});
        x[0x4f] = mk("moveCameraTo", 6, {{"cameraSlowdown", K::U8}, {"positionX", K::S16}, {"positionY", K::S16}});
        x[0x50] = mk("moveCameraToEntity", 4, {{"empty", K::U8}, {"entity", K::U8}, {"speed", K::U8}});
        x[0x51] = mk("entityWalkToEntity", 4, {{"entity", K::U8}, {"sprint", K::U8}, {"target", K::U8}});
        x[0x52] = mk("entityWalkToWithCamera", 8, {{"entity", K::U8}, {"positionX", K::S16}, {"positionY", K::S16}, {"sprint", K::S16}});
        x[0x53] = mk("entityWalkToEntityWithCamera", 4, {{"entity", K::U8}, {"sprint", K::U8}, {"target", K::U8}});
        x[0x55] = mk("setTextboxOrigin", 8, {{"empty", K::U8}, {"positionX", K::S16}, {"positionZ", K::S16}, {"positionY", K::S16}});
        x[0x56] = mk("playAnimation", 4, {{"empty", K::U8}, {"entity", K::U8}, {"animation", K::U8}});
        x[0x57] = mk("setObjectVisibility", 4, {{"empty", K::U8}, {"objectId", K::U8}, {"invisible", K::U8}});
        x[0x58] = mk("teleport", 2, {{"pstat", K::U8}});
        x[0x5a] = mk("playSound", 4, {{"empty", K::U8}, {"soundRegister", K::U8}, {"soundId", K::U8}});
        x[0x5d] = mk("setBGM", 2, {{"musicID", K::U8}});
        x[0x64] = mk("callSubroutine", 2, {{"routine", K::U8}});
        x[0x65] = mk("removeCondition", 2, {{"mask", K::U8}});
        x[0x66] = mk("startBattle", 2, {{"empty", K::U8}});
        x[0x67] = mk("delay", 4, {{"empty", K::U8}, {"duration", K::S16}});
        x[0x68] = mk("setTexboxMode", 4, {{"empty", K::U8}, {"mode", K::U8}, {"delay", K::U8}});
        x[0x69] = mk("dealMapDamage", 2, {{"pstat", K::U8}});
        x[0x6a] = mk("setAutotalk", 4, {{"empty", K::U8}, {"entity", K::U8}, {"value", K::U8}});
        x[0x6c] = mk("moveEntityTo", 8, {{"entity", K::U8}, {"positionX", K::S16}, {"positionY", K::S16}, {"animationDuration", K::S16}});
        x[0x70] = mk("rotate3DObject", 4, {{"modelId", K::U8}, {"empty", K::U8}, {"rotation", K::U8}});
        x[0x71] = mk("moveObjectTo", 10, {{"value1", K::U8}, {"value2", K::U8}, {"value3", K::U8}, {"value4", K::U8}, {"value5", K::U8}, {"positionX", K::S16}, {"positionY", K::S16}});
        x[0x72] = mk("moveEntityToAxis", 6, {{"entity", K::U8}, {"position", K::S16}, {"axis", K::U8}, {"speed", K::U8}});
        x[0x73] = mk("moveEntityToAxisWithCamera", 6, {{"entity", K::U8}, {"position", K::S16}, {"axis", K::U8}, {"speed", K::U8}});
        x[0x74] = mk("spawnItem", 6, {{"id", K::U8}, {"x", K::S16}, {"y", K::S16}});
        x[0x75] = mk("spawnChest", 12, {{"id", K::U8}, {"x", K::S16}, {"empty", K::S16}, {"y", K::S16}, {"rotation", K::S16}, {"trigger", K::S16}});
        x[0x76] = mk("spawnBoulder", 2, {{"empty", K::U8}});
        x[0x77] = mk("moveBoulder", 6, {{"empty", K::U8}, {"translateZ", K::S16}, {"translateY", K::S16}});
        x[0x78] = mk("despawnBoulder", 2, {{"empty", K::U8}});
        x[0x79] = mk("unloadModel", 2, {{"digimonId", K::U8}});
        x[0x7a] = mk("copyPStat", 4, {{"empty", K::U8}, {"source", K::U8}, {"target", K::U8}});
        x[0x7b] = mk("sectionOnExit", 2, {{"trigger", K::U8}});
        x[0x7c] = mk("setRectImpassible", 8, {{"empty", K::U8}, {"x", K::S16}, {"y", K::S16}, {"width", K::U8}, {"height", K::U8}});
        x[0x7d] = mk("spawnSpriteAtLocation", 10, {{"sprite", K::U8}, {"x", K::S16}, {"y", K::S16}, {"z", K::S16}, {"unk", K::S16}});
        x[0x7e] = mk("spawnSpriteAtEntity", 4, {{"entity", K::U8}, {"sprite", K::S16}});
        x[0xfb] = mk("setScript", 6, {{"empty", K::U8}, {"scriptId", K::S16}, {"mapId", K::S16}});
        x[0xfe] = mk("endSection", 2, {{"empty", K::U8}});
        return x;
    }();
    return t;
}

const std::vector<CustomOpcode>& customOpcodes() {
    static const std::vector<CustomOpcode> v = {
        { 0x10, "setSelection" },
        { 0x18, "switch" },
        { 0x19, "if" },
        { 0x1a, "showTextbox" },
        { 0x3a, "clearInventory" },
        { 0x6b, "tournamentData" },
        { 0xff, "garbage" },
    };
    return v;
}

const std::vector<MnemonicSynonym>& mnemonicSynonyms() {
    static const std::vector<MnemonicSynonym> t = {
        { "roll", "storeRandom", { {"pstat", "target"}, {"max", "upperLimit"} } },
    };
    return t;
}

const MnemonicSynonym* findSynonymByUser(std::string_view user) {
    for (const auto& s : mnemonicSynonyms()) if (s.user == user) return &s;
    return nullptr;
}

const MnemonicSynonym* findSynonymByCanonical(std::string_view canonical) {
    for (const auto& s : mnemonicSynonyms()) if (s.canonical == canonical) return &s;
    return nullptr;
}

std::string_view translateFieldName(const MnemonicSynonym* syn, std::string_view userFieldName) {
    if (!syn) return userFieldName;
    for (const auto& [u, c] : syn->fieldAliases) if (u == userFieldName) return c;
    return userFieldName;
}

std::string_view reverseFieldName(const MnemonicSynonym* syn, std::string_view canonicalFieldName) {
    if (!syn) return canonicalFieldName;
    for (const auto& [u, c] : syn->fieldAliases) if (c == canonicalFieldName) return u;
    return canonicalFieldName;
}

} // namespace dd
