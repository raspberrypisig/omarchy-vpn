#!/usr/bin/env bash
# Run this installer from a terminal after downloading/reviewing the plugin.
set -euo pipefail

usage() {
  echo 'Usage: bash install.sh <plugin-git-url>'
  echo 'Checks dependencies, installs missing packages, then adds and enables the plugin.'
  echo 'For an existing installation, use: bash scripts/setup-dependencies.sh --install'
}
if [[ ${1:-} == --help || ${1:-} == -h ]]; then usage; exit 0; fi
if (( $# != 1 )); then usage >&2; exit 2; fi

for tool in omarchy omarchy-git-url-check; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "Required Omarchy command is missing: $tool" >&2
    exit 2
  fi
done
# Reject options and unsafe Git transports before making any changes.
omarchy-git-url-check "$1"
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
bash "$script_dir/scripts/setup-dependencies.sh" --install
omarchy plugin add "$1" --enable
