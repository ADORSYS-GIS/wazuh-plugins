#!/usr/bin/env bash
set -euo pipefail

# Install a built appliance (yara or suricata) on the local machine.
# Accepts a builder name, a version (from builders/<name>/release.txt), and an optional
# path to the artifact directory. The script autodetects the local triplet and prefers
# installing from the tarball; on macOS it can fall back to the DMG if the tarball is
# missing.

usage() {
  cat <<'EOF'
Usage: install_appliance.sh <builder> <version> [artifact_dir]

  <builder>      : yara | suricata | wazuh-agent
  <version>      : Release version (e.g., 0.4.0)
  [artifact_dir] : Directory containing packaged artifacts.
                   Defaults to builders/<builder>/dist/<triplet>/artifacts
                   where <triplet> is auto-detected (linux-amd64, linux-arm64,
                   macos-amd64, macos-arm64).

Examples:
  ./scripts/install_appliance.sh yara 0.4.0
  ./scripts/install_appliance.sh suricata 0.4.0 /tmp/artifacts
  ./scripts/install_appliance.sh wazuh-agent 0.4.0
EOF
}

err() {
  echo "error: $*" >&2
}

detect_triplet() {
  local os arch
  case "$(uname -s)" in
    Linux) os="linux" ;;
    Darwin) os="macos" ;;
    *) err "unsupported OS $(uname -s)"; exit 1 ;;
  esac
  case "$(uname -m)" in
    x86_64|amd64) arch="amd64" ;;
    arm64|aarch64) arch="arm64" ;;
    *) err "unsupported arch $(uname -m)"; exit 1 ;;
  esac
  printf "%s-%s" "$os" "$arch"
}

ensure_wazuh_user() {
  if id -u wazuh >/dev/null 2>&1; then
    return 0
  fi
  if [[ "$(uname -s)" == "Linux" ]]; then
    if ! getent group wazuh >/dev/null 2>&1; then
      sudo groupadd --system wazuh 2>/dev/null || sudo addgroup --system wazuh 2>/dev/null || true
    fi
    if ! id -u wazuh >/dev/null 2>&1; then
      sudo useradd --system --gid wazuh --home-dir /var/ossec --shell /usr/sbin/nologin wazuh 2>/dev/null || \
        sudo adduser --system --ingroup wazuh --home /var/ossec --shell /usr/sbin/nologin wazuh 2>/dev/null || true
    fi
    return 0
  fi
  echo "warning: wazuh user not created automatically on $(uname -s); create it manually if needed" >&2
  return 1
}

mount_and_copy_dmg() {
  local dmg="$1" target="$2"
  local mountpoint
  mountpoint="$(/usr/bin/mktemp -d -t wappliance)"
  hdiutil attach -quiet -mountpoint "$mountpoint" "$dmg"
  trap 'hdiutil detach -quiet "$mountpoint" || true; rmdir "$mountpoint" 2>/dev/null || true' EXIT
  local payload_root
  payload_root="$(find "$mountpoint" -mindepth 1 -maxdepth 1 -type d | head -n1)"
  if [[ -z "$payload_root" ]]; then
    err "unable to locate payload inside mounted dmg"
    exit 1
  fi
  sudo cp -R "$payload_root"/. /
  hdiutil detach -quiet "$mountpoint" || true
  rmdir "$mountpoint" 2>/dev/null || true
  trap - EXIT
}

install_tarball() {
  local tarball="$1" install_root="$2"
  echo "Installing from tarball: $tarball"
  sudo tar -C / --strip-components=1 -xzf "$tarball"
  ensure_wazuh_user || true
  if id -u wazuh >/dev/null 2>&1; then
    sudo chown -R wazuh:wazuh "$install_root" 2>/dev/null || true
  fi
}

install_dmg() {
  local dmg="$1" install_root="$2"
  if [[ "$(uname -s)" != "Darwin" ]]; then
    err "DMG install is only supported on macOS"
    exit 1
  fi
  echo "Installing from dmg: $dmg"
  mount_and_copy_dmg "$dmg" "$install_root"
  ensure_wazuh_user || true
  if id -u wazuh >/dev/null 2>&1; then
    sudo chown -R wazuh:wazuh "$install_root" 2>/dev/null || true
  fi
}

main() {
  if [[ $# -lt 2 ]]; then
    usage
    exit 1
  fi

  local builder="$1"
  local version="$2"
  local triplet="${ARTIFACT_TRIPLET:-$(detect_triplet)}"
  local artifact_dir="${3:-builders/${builder}/dist/${triplet}/artifacts}"
  local install_root
  case "$builder" in
    yara) install_root="/opt/wazuh/yara" ;;
    suricata) install_root="/opt/wazuh/suricata" ;;
    wazuh-agent) install_root="/var/ossec" ;;
  esac

  if [[ "$builder" != "yara" && "$builder" != "suricata" && "$builder" != "wazuh-agent" ]]; then
    err "builder must be 'yara', 'suricata', or 'wazuh-agent'"
    exit 1
  fi

  if [[ ! -d "$artifact_dir" ]]; then
    err "artifact directory not found: $artifact_dir"
    exit 1
  fi

  local base="${builder}-${version}-${triplet}"
  local tarball="${artifact_dir}/${base}.tar.gz"
  local dmg="${artifact_dir}/${base}.dmg"

  if [[ -f "$tarball" ]]; then
    install_tarball "$tarball" "$install_root"
    if [[ "$builder" == "suricata" ]] && command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
      systemctl daemon-reload >/dev/null 2>&1 || true
      systemctl enable --now suricata-wazuh.service >/dev/null 2>&1 || systemctl restart suricata-wazuh.service >/dev/null 2>&1 || true
    fi
    return
  fi

  if [[ -f "$dmg" ]]; then
    install_dmg "$dmg" "$install_root"
    return
  fi

  err "no usable artifact found (looked for $tarball and $dmg)"
  exit 1
}

main "$@"
