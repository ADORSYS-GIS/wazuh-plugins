#!/usr/bin/env bash
set -euo pipefail

log() {
  printf '[wazuh-agent][uninstall] %s\n' "$*" >&2
}

warn() {
  printf '[wazuh-agent][uninstall][warn] %s\n' "$*" >&2
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

agent_version="${AGENT_VERSION:-$(read_first_line "$metadata_root/version.txt")}"
package_revision="${PACKAGE_REVISION:-$(read_first_line "$metadata_root/package_revision.txt")}"
if [ -z "$package_revision" ]; then
  package_revision="1"
fi

uname_s=$(uname -s | tr '[:upper:]' '[:lower:]')
os_id="unknown"
pkg_type="tar"
component_prefix=""
case "$uname_s" in
linux*)
  os_id="linux"
  component_prefix="/var/ossec"
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
  component_prefix="/Library/Ossec"
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

package_name="wazuh-agent"
systemd_unit="/lib/systemd/system/wazuh-agent.service"
init_script="/etc/init.d/wazuh-agent"
launchd_plist="/Library/LaunchDaemons/com.wazuh.agent.plist"

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

cleanup_services() {
  if [ "$os_id" = "linux" ]; then
    if command -v systemctl >/dev/null 2>&1; then
      $SUDO systemctl stop "$(basename "$systemd_unit")" >/dev/null 2>&1 || true
      $SUDO systemctl disable "$(basename "$systemd_unit")" >/dev/null 2>&1 || true
    fi
    $SUDO rm -f "$systemd_unit" "$init_script"
    if command -v systemctl >/dev/null 2>&1; then
      $SUDO systemctl daemon-reload >/dev/null 2>&1 || true
    fi
  elif [ "$os_id" = "macos" ]; then
    if [ -f "$launchd_plist" ] && command -v launchctl >/dev/null 2>&1; then
      $SUDO launchctl unload "$launchd_plist" >/dev/null 2>&1 || true
    fi
    $SUDO rm -f "$launchd_plist"
  fi
}

main() {
  log "Uninstalling Wazuh agent ${agent_version}-r${package_revision} from ${os_id}/${arch_id}"
  remove_package
  cleanup_services
  if [ -d "$component_prefix" ]; then
    log "Removing files under $component_prefix"
    $SUDO rm -rf "$component_prefix"
  else
    warn "Component directory not found: $component_prefix"
  fi
}

main "$@"
