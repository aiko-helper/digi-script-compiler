#include "container.hpp"

#include <cstdio>
#include <stdexcept>
#include <unordered_map>

namespace dd {

namespace {

// Parse one SCNScript inside a byte buffer: u16 header, {u16 id, u16
// offset} until 0xFFFF sentinel, then the section bytes.
//
// Sentinel offset is preserved as Script::sentinelOffset for byte-exact
// round-trip, but each section's span is clamped to the script's extent
// (the sentinel.offset field is unreliable: sometimes "end of last
// section", sometimes garbage -- see DG script 25).
Script parseScript(int index,
                   std::span<const u8> bytes,
                   std::size_t startOffset,
                   std::size_t endOffset) {
    if (endOffset < startOffset || endOffset > bytes.size()) {
        throw std::runtime_error("parseScript: bad range");
    }
    const std::size_t extent = endOffset - startOffset;
    auto sub = bytes.subspan(startOffset, extent);
    if (sub.size() < 2) throw std::runtime_error("parseScript: truncated header");

    Script s;
    s.index = index;
    s.name = "";
    s.startOffset = startOffset;
    s.endOffset = endOffset;
    s.headerU16 = readU16(sub, 0);

    struct Entry { u16 id; u16 offset; };
    std::vector<Entry> raw;
    std::size_t cursor = 2;
    while (cursor + 4 <= sub.size()) {
        u16 id  = readU16(sub, cursor);
        u16 off = readU16(sub, cursor + 2);
        raw.push_back({id, off});
        cursor += 4;
        if (id == 0xffff) break;
    }

    s.sentinelOffset = raw.empty() ? 0 : raw.back().offset;

    // Sections ordered by entry-table order; each ends at the next entry's
    // offset.  The last real section ends at the script's extent; the
    // sentinel's offset field is NOT used as section end (it's unreliable).
    //
    // Duplicate-ID entries are preserved verbatim so the reassembler can
    // reproduce the file byte-for-byte.  The engine's section lookup is a
    // linear scan that returns on the first ID match, so later entries with
    // an already-seen ID are unreachable at runtime -- but their bytes are
    // part of the shipping file and `targets.cpp` resolves them via the
    // `section_<id>@0x<off>` form.
    if (raw.size() >= 2) {
        for (std::size_t i = 0; i + 1 < raw.size(); ++i) {
            const auto& e = raw[i];
            const bool isLast = (i == raw.size() - 2);
            const u16 secEnd = isLast ? static_cast<u16>(extent) : raw[i + 1].offset;
            const std::size_t absStart = startOffset + e.offset;
            const std::size_t absEnd   = startOffset + secEnd;
            Section sec;
            sec.id = e.id;
            sec.offset = e.offset;
            sec.end = secEnd;
            sec.bytes.assign(bytes.data() + absStart, bytes.data() + absEnd);
            s.sections.push_back(std::move(sec));
        }
    }

    return s;
}

} // namespace

ScriptContainer parseMaphead(const std::filesystem::path& path) {
    ScriptContainer c;
    c.path = path;
    c.bytes = readFileBytes(path);
    c.kind = ContainerKind::Maphead;
    c.alignment = 0;
    Script s = parseScript(0, c.bytes, 0, c.bytes.size());
    s.name = basename(path);
    c.scripts.push_back(std::move(s));
    return c;
}

ScriptContainer parseDG(const std::filesystem::path& path, std::size_t numberScripts) {
    ScriptContainer c;
    c.path = path;
    c.bytes = readFileBytes(path);
    c.kind = ContainerKind::DG;

    // Read pointer table (numberScripts x u32 LE).
    std::vector<u32> pointers;
    pointers.reserve(numberScripts);
    for (std::size_t i = 0; i < numberScripts; ++i) {
        pointers.push_back(readU32(c.bytes, i * 4));
    }

    // Filename table at 0x380..0x800 -- 36x32-byte entries of the form
    // "\MAPxxx.SCN\0...".  Recover the slot->name mapping for named files.
    std::unordered_map<int, std::string> names;
    for (std::size_t off = 0x380; off + 32 <= 0x800; off += 32) {
        if (c.bytes[off] != 0x5c /* '\\' */) continue;
        std::string raw;
        for (std::size_t k = off + 1; k < off + 13 && c.bytes[k] != 0; ++k) {
            raw.push_back(static_cast<char>(c.bytes[k]));
        }
        // Match "MAP(\d+).SCN" case-insensitively.
        auto matchMap = [&]() -> int {
            std::string upper = toUpperAscii(raw);
            if (!startsWith(upper, "MAP")) return -1;
            if (!endsWith(upper, ".SCN"))  return -1;
            std::string mid = upper.substr(3, upper.size() - 3 - 4);
            if (mid.empty()) return -1;
            int n = 0;
            for (char ch : mid) {
                if (ch < '0' || ch > '9') return -1;
                n = n * 10 + (ch - '0');
            }
            return n;
        };
        int slot = matchMap();
        if (slot < 0) continue;
        names[slot] = toUpperAscii(raw);
    }

    const std::size_t fileLen = c.bytes.size();
    for (std::size_t i = 0; i + 1 < pointers.size(); ++i) {
        std::size_t start = std::min<std::size_t>(pointers[i],     fileLen);
        std::size_t end   = std::min<std::size_t>(pointers[i + 1], fileLen);
        std::string name;
        auto it = names.find(static_cast<int>(i));
        if (it != names.end()) name = it->second;
        else {
            // Pad slot index to 3 digits so the synthesized names sort
            // lexically in numeric order (DG000.SCN < DG001.SCN < ... < DG222.SCN).
            std::string num = toDec(static_cast<long long>(i));
            while (num.size() < 3) num.insert(num.begin(), '0');
            name = "DG" + num + ".SCN";
        }

        Script empty;
        empty.index = static_cast<int>(i);
        empty.name = name;
        empty.startOffset = start;
        empty.endOffset = end;
        empty.headerU16 = 0;
        empty.sentinelOffset = 0;

        if (end <= start) { c.scripts.push_back(std::move(empty)); continue; }
        try {
            Script s = parseScript(static_cast<int>(i), c.bytes, start, end);
            s.name = name;
            c.scripts.push_back(std::move(s));
        } catch (const std::exception& e) {
            std::fprintf(stderr,
                         "parseDG: script #%zu malformed at 0x%zx: %s\n",
                         i, start, e.what());
            c.scripts.push_back(std::move(empty));
        }
    }

    // Alignment detection: every non-empty slot's endOffset must land on a
    // 0x800 boundary in the shipping file.  If any one doesn't, we mark it
    // irregular but still default to 0x800 for the assembler.
    u32 alignment = 0x800;
    for (const auto& s : c.scripts) {
        if (s.endOffset == s.startOffset) continue;
        if ((s.endOffset & (alignment - 1)) != 0) { alignment = 0; break; }
    }
    c.alignment = alignment ? alignment : 0x800;
    return c;
}

ScriptContainer parseContainer(const std::filesystem::path& path) {
    std::string name = toUpperAscii(basename(path));
    if (name == "DG.SCN") return parseDG(path);
    return parseMaphead(path);
}

} // namespace dd
