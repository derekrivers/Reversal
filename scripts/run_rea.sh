#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 2 ]]; then
  echo "Usage: run_rea.sh /absolute/path/cm0102.exe /new/output-directory" >&2
  exit 2
fi
: "${GHIDRA_INSTALL_DIR:?Set GHIDRA_INSTALL_DIR to Ghidra 12.1.x}"
: "${JAVA_HOME:?Set JAVA_HOME to a compatible JDK 21+}"
target="$1"
output="$2"
mkdir -- "$output"
repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -x "$repository_root/tools/rea/node_modules/.bin/rea" ]]; then
  rea_command=("$repository_root/tools/rea/node_modules/.bin/rea")
else
  rea_command=(npx --yes rea-agents@6.7.0)
fi
"${rea_command[@]}" inspect-pe-resources "$target" --json > "$output/rea-pe-resources.json"
"${rea_command[@]}" doctor --provider ghidra --json > "$output/rea-doctor.json"
"${rea_command[@]}" analyze "$target" --provider ghidra --json > "$output/rea-overview.json"
# Choose an address from the returned overview / string references before
# using 'rea function', 'rea xrefs' or 'rea decompile'. Do not guess function names.
