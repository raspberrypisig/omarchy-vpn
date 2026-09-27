#!/usr/bin/env bash
# Dependency setup for the OpenVPN edition of this Omarchy plugin.
set -euo pipefail

usage() {
  echo 'Usage: bash scripts/setup-dependencies.sh [--check | --install]'
  echo '  --check    Report dependencies without changing the system (default).'
  echo '  --install  Confirm and install missing packages using Omarchy.'
}

mode=${1:---check}
if (( $# > 1 )); then usage >&2; exit 2; fi
case "$mode" in
  --help|-h) usage; exit 0 ;;
  --check|--install) ;;
  *) usage >&2; exit 2 ;;
esac

if ! command -v pacman >/dev/null 2>&1; then
  echo 'Dependency setup requires Omarchy with the Arch Linux pacman package manager.' >&2
  exit 2
fi

packages=(networkmanager openvpn networkmanager-openvpn coreutils python)
descriptions=('nmcli' 'OpenVPN client' 'NetworkManager OpenVPN integration' 'installer utilities' 'profile storage helper')
missing=()
for index in "${!packages[@]}"; do
  package=${packages[index]}
  if pacman -Q "$package" >/dev/null 2>&1; then
    printf 'SKIP: %s (%s) is already installed.\n' "$package" "${descriptions[index]}"
  else
    printf 'MISSING: %s (%s)\n' "$package" "${descriptions[index]}"
    missing+=("$package")
  fi
done

if (( ${#missing[@]} )); then
  if [[ $mode == --check ]]; then
    echo 'Run this script with --install to install the missing packages.'
    exit 1
  fi
  if ! command -v omarchy >/dev/null 2>&1; then
    echo 'The omarchy command is required to install dependencies.' >&2
    exit 2
  fi
  printf '\nPackages to install: %s\n' "${missing[*]}"
  echo 'Omarchy will request administrator authentication if needed.'
  read -r -p 'Install these packages? [y/N] ' answer || answer=''
  case "$answer" in
    y|Y|yes|YES) ;;
    *) echo 'Cancelled. No packages were installed.'; exit 1 ;;
  esac
  if ! omarchy pkg add "${missing[@]}"; then
    echo 'Dependency installation failed. Fix the reported package error and rerun setup.' >&2
    exit 1
  fi
  for package in "${missing[@]}"; do
    if ! pacman -Q "$package" >/dev/null 2>&1; then
      printf 'ERROR: %s is still missing after installation.\n' "$package" >&2
      exit 1
    fi
    printf 'INSTALLED: %s\n' "$package"
  done
fi

for tool in nmcli openvpn timeout python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'ERROR: %s is not on PATH despite its package being installed. Check PATH or repair the package.\n' "$tool" >&2
    exit 1
  fi
done
echo 'All VPN dependencies are installed.'
