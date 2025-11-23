#!/usr/bin/env bash
set -euo pipefail

PINNED_VERSION="${PINNED_VERSION:-0.5.1}"
DEFAULT_BUILDERS=("yara" "suricata" "wazuh-agent")

log() {
  printf '[install-all] %s\n' "$*" >&2
}

usage() {
  cat <<EOF
Usage: $(basename "$0") [builder...]

Runs per-builder installers (yara, suricata, wazuh-agent) for release ${PINNED_VERSION}.
If no builders are provided, all are installed.

Env overrides:
  PINNED_VERSION         Override the hardcoded release version.
  BUILDER_ROOT           Root directory containing builders/ (default: script dir parent).
  ARTIFACT_DIR           Preferred artifact directory to pass to builder installers (all builders).
  ARTIFACT_DIR_<NAME>    Per-builder artifact directory, e.g. ARTIFACT_DIR_yara=/tmp/yara-artifacts
  ARTIFACT_BASE_URL      Optional URL where artifacts are hosted; passed through to installers.
  ARTIFACT_BASE_URL_<NAME>  Per-builder URL override, e.g. ARTIFACT_BASE_URL_suricata=https://...
  FORCE_TAR_INSTALL=1    Force tarball fallback inside builders.
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
  script_path="$ROOT/builders/$builder/scripts/install.sh"
  if [ ! -x "$script_path" ]; then
    log "Installer not found for $builder at $script_path"
    exit 1
  fi

  artifact_dir_env="ARTIFACT_DIR_${builder//-/_}"
  artifact_base_env="ARTIFACT_BASE_URL_${builder//-/_}"
  artifact_dir="${ARTIFACT_DIR:-$ROOT/builders/$builder/dist/artifacts}"
  if [ -n "${!artifact_dir_env-}" ]; then
    artifact_dir="${!artifact_dir_env}"
  fi
  artifact_base_url="${ARTIFACT_BASE_URL:-}"
  if [ -n "${!artifact_base_env-}" ]; then
    artifact_base_url="${!artifact_base_env}"
  fi

  log "Installing $builder (release ${PINNED_VERSION})"
  RELEASE_VERSION="$PINNED_VERSION" \
    ARTIFACT_DIR="$artifact_dir" \
    ARTIFACT_BASE_URL="$artifact_base_url" \
    FORCE_TAR_INSTALL="${FORCE_TAR_INSTALL:-0}" \
    "$script_path"
done
