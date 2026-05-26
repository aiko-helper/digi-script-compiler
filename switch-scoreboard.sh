#!/usr/bin/env bash
# Diagnostic for eq-chain switch candidates: runs of >=2 consecutive
# `if (pstat[N] == K ...)` blocks sharing the same N with distinct K_i.
# Reports run length, total sites, total folded-away if-blocks.
# Parity-neutral: reads only.
#
# Usage:
#   ./switch-scoreboard.sh                       # default: ../scn
#   ./switch-scoreboard.sh path/to/file.dgs ...
#   ./switch-scoreboard.sh --summary             # totals only
#   ./switch-scoreboard.sh --top N               # show top N hottest files (default 10)
set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"

summary_only=0
top=10
paths=()
while [ $# -gt 0 ]; do
    case "$1" in
        --summary|-s) summary_only=1; shift ;;
        --top) top="$2"; shift 2 ;;
        *) paths+=("$1"); shift ;;
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
    fi
done

if [ "${#files[@]}" -eq 0 ]; then
    echo "no .dgs files found" >&2
    exit 1
fi

awk -v SUMMARY_ONLY="$summary_only" -v TOP="$top" '
function flush_run(    rl) {
    rl = run_len
    if (rl >= 2) {
        runs_per_len[rl]++
        file_runs[cur_file]++
        file_folded[cur_file] += rl
        G_sites++
        G_folded += rl
    }
    run_len = 0
    run_reg = ""
    delete run_seen_k
}

FNR == 1 {
    cur_file = FILENAME
    files_scanned[cur_file] = 1
    run_len = 0
    run_reg = ""
    delete run_seen_k
}

{
    # Match: `  if (pstat[N] ...` capturing the operand N and the comparator value(s).
    # Only treat lines whose if-condition references pstat[N] == K (anywhere in the
    # condition) as candidates. We extract the FIRST pstat[N] == K occurrence.
    line = $0

    if (match(line, /^[[:space:]]*if \(/)) {
        # extract the condition between the first "(" after "if " and the matching ")"
        # crude but adequate: the first "==" with pstat[N]
        cond = line
        sub(/^[[:space:]]*if \(/, "", cond)
        # find pattern: pstat[N] == K  (N may be int or PStat.Name; K usually int)
        if (match(cond, /pstat\[[^]]+\][[:space:]]*==[[:space:]]*[A-Za-z0-9_.()-]+/)) {
            seg = substr(cond, RSTART, RLENGTH)
            # split on ==
            n_op = seg
            sub(/[[:space:]]*==.*/, "", n_op)
            k_op = seg
            sub(/.*==[[:space:]]*/, "", k_op)
            # strip surrounding whitespace
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", n_op)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", k_op)

            if (run_reg == n_op) {
                # same operand; require distinct K
                if (k_op in run_seen_k) {
                    flush_run()
                    run_reg = n_op
                    run_seen_k[k_op] = 1
                    run_len = 1
                } else {
                    run_seen_k[k_op] = 1
                    run_len++
                }
            } else {
                flush_run()
                run_reg = n_op
                run_seen_k[k_op] = 1
                run_len = 1
            }
            next
        } else {
            # if-block that does not start with pstat[N]==K: breaks the run
            flush_run()
            next
        }
    }

    # Non-if lines that are non-blank, non-comment, non-close-brace break the run.
    # We tolerate the lines INSIDE an if-body (comments / opening brace lives on the
    # if line itself). The closing `}` of an if-body and the next `if (...)` are
    # what we care about. A reasonable heuristic: ignore lines that are clearly
    # inside a body (deeper indent than the if), break on lines at shallower indent.
    # Simpler heuristic: only treat `}` lines and `if (...)` lines as significant;
    # everything else is body content and does not break the run.
    if (line ~ /^[[:space:]]*\}[[:space:]]*$/) {
        # closing brace — ok, run continues if next is another matching if
        next
    }
    # Other lines: ignored (body content)
}

END {
    flush_run()

    n_scanned = 0
    for (f in files_scanned) n_scanned++

    printf("== eq-chain switch scoreboard (%d files) ==\n", n_scanned)
    printf("  sites (runs of length >=2): %d\n", G_sites)
    printf("  total if-blocks foldable:  %d\n", G_folded)
    print "  distribution by run length:"
    for (l = 2; l <= 16; l++) {
        if (runs_per_len[l] > 0) {
            printf("    len %2d: %5d sites (%d if-blocks)\n", l, runs_per_len[l], l * runs_per_len[l])
        }
    }

    if (SUMMARY_ONLY == "1") exit

    # hottest files
    n_hot = 0
    for (f in file_runs) {
        n_hot++
        hot_files[n_hot] = f
        hot_sites[n_hot] = file_runs[f]
        hot_folded[n_hot] = file_folded[f]
    }
    # sort by folded desc
    for (i = 1; i <= n_hot; i++) {
        for (k = i + 1; k <= n_hot; k++) {
            if (hot_folded[k] > hot_folded[i]) {
                t = hot_folded[i]; hot_folded[i] = hot_folded[k]; hot_folded[k] = t
                t = hot_sites[i];  hot_sites[i]  = hot_sites[k];  hot_sites[k]  = t
                s = hot_files[i];  hot_files[i]  = hot_files[k];  hot_files[k]  = s
            }
        }
    }
    max = (n_hot < TOP ? n_hot : TOP)
    if (max > 0) {
        printf("\n== top %d files by foldable if-blocks ==\n", max)
        printf("  %-50s  %6s  %6s\n", "file", "sites", "folded")
        for (i = 1; i <= max; i++) {
            printf("  %-50s  %6d  %6d\n", hot_files[i], hot_sites[i], hot_folded[i])
        }
    }
}
' "${files[@]}"
