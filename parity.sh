#!/usr/bin/env bash
#
# Round-trip parity gate for digi-disasm.
#
# Steps (per SCN):
#   1) split: ./digi-disasm <SCN> <out-dir>
#   2) reassemble: ./digi-disasm --assemble <out-dir> <SCN.reasm>
#   3) SHA256-compare reassembled bytes to the original
#
# Exit 0 only when every check passes.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$SCRIPT_DIR"
BIN="$SCRIPT_DIR/digi-disasm"
WORK_DIR="${TMPDIR:-/tmp}/digi-disasm-parity.$$"
trap 'rm -rf "$WORK_DIR"' EXIT

if [[ ! -x "$BIN" ]]; then
    echo "error: $BIN not built -- run 'make' first" >&2
    exit 1
fi

mkdir -p "$WORK_DIR"

# Repo-relative paths.  Each input is split to .dgs form and reassembled;
# layout depends on whether the SCN is a single script or an archive.
INPUTS_REL=(
    "extract/DIGIMON/SCN/MAPHEAD.SCN"
    "extract/DIGIMON/SCN/DG.SCN"
)

failures=0

cd "$REPO_ROOT"

for src in "${INPUTS_REL[@]}"; do
    name="$(basename "$src" .SCN)"
    case "$(basename "$src")" in
        DG.SCN)  split_path="$WORK_DIR/${name}.dgs.d";;
        *)       split_path="$WORK_DIR/${name}.dgs";;
    esac
    reasm="$WORK_DIR/${name}.SCN"

    echo "$(basename "$src")"

    "$BIN" "$src" "$split_path" >/dev/null
    if [[ -d "$split_path" ]]; then
        file_count=$(find "$split_path" -maxdepth 1 -name '*.dgs' | wc -l)
        echo "  split:        $file_count .dgs files in $(basename "$split_path")/"
    else
        echo "  split:        $(basename "$split_path") ($(stat -c%s "$split_path") bytes)"
    fi

    "$BIN" --assemble "$split_path" "$reasm" >/dev/null

    orig_hash=$(sha256sum "$src"   | cut -d' ' -f1)
    reasm_hash=$(sha256sum "$reasm" | cut -d' ' -f1)
    if [[ "$orig_hash" == "$reasm_hash" ]]; then
        echo "  reassemble:   PASS  $reasm_hash  ($(stat -c%s "$reasm") bytes)"
    else
        echo "  reassemble:   FAIL"
        echo "    original:   $orig_hash"
        echo "    reasm:      $reasm_hash"
        echo
        # First-divergence diagnostic: maps the failing byte back to a
        # source location via the EmitMap produced during assembly.
        "$BIN" --diff "$split_path" "$src" 2>&1 | sed 's/^/    /' || true
        failures=$((failures + 1))
    fi
done

echo
if (( failures == 0 )); then
    echo "PARITY: PASS -- every SCN reassembles byte-identical to the original"
    exit 0
else
    echo "PARITY: FAIL ($failures check(s))"
    exit 1
fi
