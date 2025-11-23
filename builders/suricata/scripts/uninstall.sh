#!/usr/bin/env bash
set -euo pipefail

log() {
  printf '[suricata][uninstall] %s\n' "$*" >&2
}

warn() {
  printf '[suricata][uninstall][warn] %s\n' "$*" >&2
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
metadata_root="$script_dir/.."

SUDO="${SUDO:-}"
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  SUDO="${SUDO:-sudo}"
fi

read_first_line() {
  local path="$1"
  if [ -f "$path" ]; then
    head -n 1 "$path" | tr -d '\n'
  fi
}

component_version="${COMPONENT_VERSION:-$(read_first_line "$metadata_root/version.txt")}"

uname_s=$(uname -s | tr '[:upper:]' '[:lower:]')
os_id="unknown"
pkg_type="tar"
case "$uname_s" in
linux*)
  os_id="linux"
  if [ -r /etc/os-release ]; then
    distro_like=$(grep -E '^ID_LIKE=' /etc/os-release | cut -d= -f2 | tr -d '"')
    distro_id=$(grep -E '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
    distro="$distro_like $distro_id"
    if echo "$distro" | grep -Eiq 'debian|ubuntu'; then
      pkg_type="deb"
    elif echo "$distro" | grep -Eiq 'rhel|centos|fedora|rocky|almalinux|suse|amzn'; then
      pkg_type="rpm"
    fi
  fi
  ;;
darwin*)
  os_id="macos"
  pkg_type="dmg"
  ;;
*)
  log "Unsupported OS: $uname_s"
  exit 1
  ;;
esac

arch_id_raw=$(uname -m | tr '[:upper:]' '[:lower:]')
case "$arch_id_raw" in
x86_64|amd64)
  arch_id="amd64"
  ;;
arm64|aarch64)
  arch_id="arm64"
  ;;
*)
  log "Unsupported architecture: $arch_id_raw"
  exit 1
  ;;
esac

package_name="suricata"
component_prefix="/opt/wazuh/suricata"
systemd_unit="/lib/systemd/system/suricata-wazuh.service"

remove_package() {
  case "$pkg_type" in
  deb)
    if dpkg -s "$package_name" >/dev/null 2>&1; then
      log "Removing deb package $package_name"
      if command -v apt-get >/dev/null 2>&1; then
        $SUDO apt-get remove -y "$package_name" || true
        $SUDO apt-get autoremove -y || true
      else
        $SUDO dpkg -r "$package_name" || true
      fi
    fi
    ;;
  rpm)
    if rpm -q "$package_name" >/dev/null 2>&1; then
      log "Removing rpm package $package_name"
      if command -v dnf >/dev/null 2>&1; then
        $SUDO dnf remove -y "$package_name" || true
      elif command -v yum >/dev/null 2>&1; then
        $SUDO yum remove -y "$package_name" || true
      else
        $SUDO rpm -e "$package_name" || true
      fi
    fi
    ;;
  esac
}

cleanup_service() {
  if [ "$os_id" != "linux" ]; then
    return
  fi
  if [ -f "$systemd_unit" ]; then
    log "Removing systemd unit $systemd_unit"
    if command -v systemctl >/dev/null 2>&1; then
      $SUDO systemctl stop "$(basename "$systemd_unit")" >/dev/null 2>&1 || true
      $SUDO systemctl disable "$(basename "$systemd_unit")" >/dev/null 2>&1 || true
    fi
    $SUDO rm -f "$systemd_unit"
    if command -v systemctl >/dev/null 2>&1; then
      $SUDO systemctl daemon-reload >/dev/null 2>&1 || true
    fi
  fi
}

main() {
  log "Uninstalling Suricata ${component_version} from ${os_id}/${arch_id}"
  remove_package
  cleanup_service
  if [ -d "$component_prefix" ]; then
    log "Removing files under $component_prefix"
    $SUDO rm -rf "$component_prefix"
  else
    warn "Component directory not found: $component_prefix"
  fi
}

main "$@"
