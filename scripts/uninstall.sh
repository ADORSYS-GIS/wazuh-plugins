#!/usr/bin/env bash
set -euo pipefail

PINNED_VERSION="${PINNED_VERSION:-0.5.2}"
DEFAULT_BUILDERS=("yara" "suricata" "wazuh-agent")

log() {
  printf '[uninstall-all] %s\n' "$*" >&2
}

usage() {
  cat <<EOF
Usage: $(basename "$0") [builder...]

Runs per-builder uninstallers (yara, suricata, wazuh-agent) for release ${PINNED_VERSION}.
If no builders are provided, all are uninstalled.

Env overrides:
  PINNED_VERSION         Override the hardcoded release version (for logging only).
  BUILDER_ROOT           Root directory containing builders/ (default: script dir parent).
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${BUILDER_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}"

builders=("$@")
if [ ${#builders[@]} -eq 0 ]; then
  builders=("${DEFAULT_BUILDERS[@]}")
fi

for builder in "${builders[@]}"; do
  case "$builder" in
  yara|suricata|wazuh-agent) ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    log "Unknown builder: $builder"
    usage
    exit 1
    ;;
  esac
done

for builder in "${builders[@]}"; do
  script_path="$ROOT/builders/$builder/scripts/uninstall.sh"
  if [ ! -x "$script_path" ]; then
    log "Uninstaller not found for $builder at $script_path"
    exit 1
  fi

  log "Uninstalling $builder (release ${PINNED_VERSION})"
  PINNED_VERSION="$PINNED_VERSION" \
    "$script_path"
done
