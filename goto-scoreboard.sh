#!/usr/bin/env bash
# Diagnostic scoreboard for .dgs output. Reports per-file and grand-total
# counts of control-flow shapes, classifies remaining gotos (cross-section
# vs local, forward vs backward), and lists global dispatch hubs
# (goto-targets hit >=3 times). Parity-neutral: reads only.
#
# Usage:
#   ./goto-scoreboard.sh                                 # default: ../scn (full decomp output)
#   ./goto-scoreboard.sh path/to/file.dgs ...
#   ./goto-scoreboard.sh ../scn/DG.SCN                   # directory recursion
#   ./goto-scoreboard.sh --summary                       # totals + hubs only, no per-file blocks
set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"

summary_only=0
paths=()
for a in "$@"; do
    case "$a" in
        --summary|-s) summary_only=1 ;;
        *) paths+=("$a") ;;
    esac
done

if [ "${#paths[@]}" -eq 0 ]; then
    paths=(../scn)
fi

files=()
for p in "${paths[@]}"; do
    if [ -d "$p" ]; then
        while IFS= read -r f; do
            files+=("$f")
        done < <(find "$p" -type f -name "*.dgs" | sort)
    elif [ -f "$p" ]; then
        files+=("$p")
    else
        echo "skip: $p (not a file or directory)" >&2
    fi
done

if [ "${#files[@]}" -eq 0 ]; then
    echo "no .dgs files found" >&2
    exit 1
fi

awk -v SUMMARY_ONLY="$summary_only" '
function reset_file() {
    sections = 0; funcs = 0; ifblocks = 0; elseifs = 0; elses = 0
    loops = 0; breaks_ = 0; continues_ = 0
    tot_gotos = 0; xsec_gotos = 0; local_gotos = 0
    ifgoto_kept = 0
    nlines = 0; n_scopes = 0; scopes_closed = 0
    delete line; delete scope_starts; delete scope_ends
    delete file_target_hits
}

function extract_goto_target(s,    t) {
    t = s
    sub(/^[[:space:]]*/, "", t)
    sub(/^goto[[:space:]]+/, "", t)
    sub(/;.*$/, "", t)
    return t
}

function compute_and_emit(fname,    i, j, ln, s, t, lbl, fwd_local, bwd_local, unresolved_local) {
    fwd_local = 0; bwd_local = 0; unresolved_local = 0

    for (i = 1; i <= n_scopes; i++) {
        delete label_line
        if (!(i in scope_ends)) continue
        for (j = scope_starts[i]; j <= scope_ends[i]; j++) {
            ln = line[j]
            if (match(ln, /^[[:space:]]*L[0-9]+:/)) {
                lbl = substr(ln, RSTART, RLENGTH - 1)
                sub(/^[[:space:]]+/, "", lbl)
                label_line[lbl] = j
            }
        }
        for (j = scope_starts[i]; j <= scope_ends[i]; j++) {
            ln = line[j]
            if (match(ln, /(^|[[:space:]])goto [^;]+;/)) {
                s = substr(ln, RSTART, RLENGTH)
                t = extract_goto_target(s)
                if (t ~ /^section_/) continue
                if (t in label_line) {
                    if (label_line[t] < j) bwd_local++
                    else fwd_local++
                } else {
                    unresolved_local++
                }
            }
        }
    }

    files_scanned++
    G_sections += sections; G_funcs += funcs; G_ifblocks += ifblocks
    G_elseifs += elseifs; G_elses += elses
    G_loops += loops; G_breaks += breaks_; G_continues += continues_
    G_tot_gotos += tot_gotos; G_xsec_gotos += xsec_gotos; G_local_gotos += local_gotos
    G_fwd_local += fwd_local; G_bwd_local += bwd_local; G_unresolved_local += unresolved_local
    G_ifgoto_kept += ifgoto_kept

    if (SUMMARY_ONLY == "1") return

    print "== " fname " =="
    printf("  sections: %d   functions: %d\n", sections, funcs)
    printf("  if-blocks: %d   else: %d   else-if: %d   loops: %d   breaks: %d   continues: %d\n",
           ifblocks, elses, elseifs, loops, breaks_, continues_)
    printf("  if-goto retained: %d\n", ifgoto_kept)
    printf("  gotos: %d   cross-section: %d   local: %d\n", tot_gotos, xsec_gotos, local_gotos)
    printf("    local forward: %d   local backward: %d   unresolved local: %d\n",
           fwd_local, bwd_local, unresolved_local)
    n_hot = 0
    for (k in file_target_hits) {
        if (file_target_hits[k] >= 3) {
            n_hot++
            hot_keys[n_hot] = k
            hot_vals[n_hot] = file_target_hits[k]
        }
    }
    if (n_hot > 0) {
        for (i = 1; i <= n_hot; i++) {
            for (k = i + 1; k <= n_hot; k++) {
                if (hot_vals[k] > hot_vals[i]) {
                    tmp = hot_vals[i]; hot_vals[i] = hot_vals[k]; hot_vals[k] = tmp
                    tmps = hot_keys[i]; hot_keys[i] = hot_keys[k]; hot_keys[k] = tmps
                }
            }
        }
        print "  hot targets (>=3 hits in this file):"
        max = (n_hot < 8 ? n_hot : 8)
        for (i = 1; i <= max; i++) printf("    %4d  goto %s\n", hot_vals[i], hot_keys[i])
        if (n_hot > 8) printf("    ... %d more\n", n_hot - 8)
    }
    delete hot_keys; delete hot_vals
    print ""
}

FNR == 1 {
    if (cur_file != "") compute_and_emit(cur_file)
    reset_file()
    cur_file = FILENAME
}

{
    nlines++
    line[nlines] = $0

    if ($0 ~ /^[a-zA-Z_].*\{[[:space:]]*$/) {
        n_scopes++
        scope_starts[n_scopes] = nlines
        if ($0 ~ /^section[ (]/) sections++
        else if ($0 ~ /^function /) funcs++
    }
    if ($0 ~ /^\}[[:space:]]*$/) {
        if (n_scopes > scopes_closed) {
            scopes_closed++
            scope_ends[scopes_closed] = nlines
        }
    }

    if ($0 ~ /^[[:space:]]*if \(/) ifblocks++
    if ($0 ~ /^[[:space:]]*\} else if \(/) elseifs++
    if ($0 ~ /^[[:space:]]*\} else \{[[:space:]]*$/) elses++
    if ($0 ~ /^[[:space:]]*loop \{[[:space:]]*$/) loops++
    if ($0 ~ /(^|[[:space:]])break;/) breaks_++
    if ($0 ~ /(^|[[:space:]])continue;/) continues_++
    if ($0 ~ /^[[:space:]]*if \(.+\) goto L[0-9]+/) ifgoto_kept++

    if (match($0, /(^|[[:space:]])goto [^;]+;/)) {
        tot_gotos++
        s = substr($0, RSTART, RLENGTH)
        t = extract_goto_target(s)
        if (t ~ /^section_/) xsec_gotos++
        else local_gotos++
        file_target_hits[t]++
        if (t ~ /^section_/) global_xsec_hits[t]++
    }
}

END {
    if (cur_file != "") compute_and_emit(cur_file)
    printf("== TOTALS (%d files) ==\n", files_scanned)
    printf("  sections: %d   functions: %d\n", G_sections, G_funcs)
    printf("  if-blocks: %d   else: %d   else-if: %d   loops: %d   breaks: %d   continues: %d\n",
           G_ifblocks, G_elses, G_elseifs, G_loops, G_breaks, G_continues)
    printf("  if-goto retained: %d\n", G_ifgoto_kept)
    printf("  gotos: %d   cross-section: %d   local: %d\n", G_tot_gotos, G_xsec_gotos, G_local_gotos)
    printf("    local forward: %d   local backward: %d   unresolved local: %d\n",
           G_fwd_local, G_bwd_local, G_unresolved_local)

    n_hub = 0
    for (k in global_xsec_hits) {
        if (global_xsec_hits[k] >= 3) {
            n_hub++
            hub_keys[n_hub] = k
            hub_vals[n_hub] = global_xsec_hits[k]
        }
    }
    if (n_hub > 0) {
        for (i = 1; i <= n_hub; i++) {
            for (k = i + 1; k <= n_hub; k++) {
                if (hub_vals[k] > hub_vals[i]) {
                    tmp = hub_vals[i]; hub_vals[i] = hub_vals[k]; hub_vals[k] = tmp
                    tmps = hub_keys[i]; hub_keys[i] = hub_keys[k]; hub_keys[k] = tmps
                }
            }
        }
        max = (n_hub < 20 ? n_hub : 20)
        printf("\n== CROSS-SECTION DISPATCH HUBS (>=3 global hits, top %d of %d) ==\n", max, n_hub)
        for (i = 1; i <= max; i++) printf("  %4d  goto %s\n", hub_vals[i], hub_keys[i])
    }
}
' "${files[@]}"
