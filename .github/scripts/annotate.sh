#!/usr/bin/env bash
# usage: annotate.sh <log file> <title>
#
# Emits up to 6 annotations with compiler/verifier error blocks plus one with the
# tail of the log (GitHub keeps at most 10 error annotations per step).
log="$1"
title="$2"
[ -s "$log" ] || exit 0
work="$(mktemp -d)"

emit() {
    local msg
    msg="$(sed -e 's/\x1b\[[0-9;]*[A-Za-z]//g' -e 's/%/%25/g' -e 's/\r/%0D/g' | awk 'BEGIN { ORS = "%0A" } { print }')"
    [ -n "$msg" ] && echo "::error title=$1::$msg"
}

grep -E -A 14 '^(error(\[E[0-9]+\])?:|.*: (fatal )?error:|FAIL|thread .* panicked)' "$log" \
    | head -n 180 | split -l 30 - "$work/err_"
for chunk in "$work"/err_*; do
    [ -e "$chunk" ] && emit "$title (errors)" < "$chunk"
done
tail -n 40 "$log" | emit "$title (tail)"
rm -rf "$work"
