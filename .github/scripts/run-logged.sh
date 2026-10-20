#!/usr/bin/env bash
# usage: run-logged.sh <title> <command> [args...]
#
# Runs a command, and if it fails, re-emits the important part of its output as
# GitHub error annotations. Annotations are readable through the public checks
# API, while raw job logs need authentication.
set -o pipefail
title="$1"
shift
log="$(mktemp)"
"$@" 2>&1 | tee "$log"
rc=${PIPESTATUS[0]}
if [ "$rc" -ne 0 ]; then
    "$(dirname "$0")/annotate.sh" "$log" "$title"
fi
exit "$rc"
