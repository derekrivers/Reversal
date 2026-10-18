#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 2 ]]; then
  echo "Usage: run_ghidra.sh /absolute/path/cm0102.exe /new/output-directory" >&2
  exit 2
fi
: "${GHIDRA_INSTALL_DIR:?Set GHIDRA_INSTALL_DIR to Ghidra 12.1.x}"
: "${JAVA_HOME:?Set JAVA_HOME to a compatible JDK 21+}"
target="$1"
output="$2"
scripts="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
mkdir -- "$output"
mkdir -- "$output/project" "$output/evidence"
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$output/project" cm0102 \
  -import "$target" -max-cpu 2 -analysisTimeoutPerFile 600 \
  -scriptPath "$scripts" -postScript CM0102FirstPass.java "$output/evidence" \
  > "$output/evidence/ghidra-run.log" 2>&1
test -f "$output/evidence/ghidra-first-pass.json"
echo "Static export: $output/evidence/ghidra-first-pass.json"
