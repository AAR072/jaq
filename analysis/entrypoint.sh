#!/bin/sh
set -eu

sample=/input/sample.exe
output=/tmp/raw-observations.jsonl
project_dir=/tmp/jaq-project
project_name=analysis

if [ ! -f "$sample" ] || [ ! -r "$sample" ]; then
    echo "sample must be mounted read-only at $sample" >&2
    exit 64
fi
umask 077
mkdir -p "$HOME" "$project_dir"

"$GHIDRA_HOME/support/analyzeHeadless" \
    "$project_dir" "$project_name" \
    -import "$sample" \
    -overwrite \
    -analysisTimeoutPerFile 900 \
    -scriptPath /opt/jaq/ghidra_scripts \
    -postScript ExportEvidence.java "$output" \
    -deleteProject >&2

cat "$output"
