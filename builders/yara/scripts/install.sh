#!/usr/bin/env bash
set -euo pipefail

log() {
  printf '[yara][install] %s\n' "$*" >&2
}

warn() {
  printf '[yara][install][warn] %s\n' "$*" >&2
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
release_version="${RELEASE_VERSION:-$(read_first_line "$metadata_root/release.txt")}"

if [ -z "$component_version" ]; then
  log "Component version not found; set COMPONENT_VERSION"
  exit 1
fi

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

release_name="yara-${component_version}-${os_id}-${arch_id}"
artifact_candidates=(
  "${ARTIFACT_DIR:-}"
  "$script_dir"
  "$metadata_root"
  "$metadata_root/dist/artifacts"
  "$metadata_root/../dist/artifacts"
  "$metadata_root/.."
)

resolve_artifact() {
  local filename="$1"
  local candidate
  for candidate in "${artifact_candidates[@]}"; do
    if [ -n "$candidate" ] && [ -f "$candidate/$filename" ]; then
      printf '%s\n' "$candidate/$filename"
      return 0
    fi
  done
  if [ -n "${ARTIFACT_BASE_URL:-}" ]; then
    local dest="${TMPDIR:-/tmp}/$filename"
    log "Downloading $filename from ${ARTIFACT_BASE_URL%/}/$filename"
    if curl -fLso "$dest" "${ARTIFACT_BASE_URL%/}/$filename"; then
      printf '%s\n' "$dest"
      return 0
    fi
  fi
  return 1
}

run_postinstall() {
  local prefix="$1"
  local postinstall="$prefix/scripts/postinstall.sh"
  if [ -x "$postinstall" ]; then
    log "Running postinstall"
    $SUDO /bin/sh "$postinstall" "$prefix" || warn "postinstall exited with status $?"
  fi
}

install_tarball() {
  local tarball="$1"
  local component_prefix="/opt/wazuh/yara"
  local component_rel="${component_prefix#/}"
  local tmpdir
  tmpdir=$(mktemp -d)
  trap "rm -rf \"$tmpdir\"" EXIT

  log "Extracting tarball fallback: $tarball"
  tar -xzf "$tarball" -C "$tmpdir"

  local src_root="$tmpdir/$release_name/$component_rel"
  if [ ! -d "$src_root" ]; then
    log "Component path not found inside tarball: $src_root"
    exit 1
  fi

  $SUDO rm -rf "$component_prefix"
  $SUDO mkdir -p "$(dirname "$component_prefix")"
  $SUDO cp -a "$src_root" "$component_prefix"
  run_postinstall "$component_prefix"
  rm -rf "$tmpdir"
  trap - EXIT
}

install_dmg() {
  local dmg="$1"
  local mount_point
  mount_point=$(mktemp -d)
  log "Mounting DMG $dmg"
  trap "hdiutil detach -quiet \"$mount_point\" || true; rm -rf \"$mount_point\"" EXIT
  hdiutil attach -nobrowse -readonly -mountpoint "$mount_point" "$dmg" >/dev/null

  local component_prefix="/opt/wazuh/yara"
  local component_rel="${component_prefix#/}"
  local src_root="$mount_point/$release_name/$component_rel"

  if [ ! -d "$src_root" ]; then
    log "Component path not found inside DMG: $src_root"
    exit 1
  fi

  $SUDO rm -rf "$component_prefix"
  $SUDO mkdir -p "$(dirname "$component_prefix")"
  $SUDO cp -a "$src_root" "$component_prefix"
  run_postinstall "$component_prefix"
  hdiutil detach -quiet "$mount_point" || true
  rm -rf "$mount_point"
  trap - EXIT
}

install_package() {
  case "$pkg_type" in
  deb)
    local deb
    if deb=$(resolve_artifact "${release_name}.deb"); then
      log "Installing deb package $deb"
      $SUDO dpkg -i "$deb"
      return 0
    fi
    ;;
  rpm)
    local rpm
    if rpm=$(resolve_artifact "${release_name}.rpm"); then
      log "Installing rpm package $rpm"
      if command -v dnf >/dev/null 2>&1; then
        $SUDO dnf install -y "$rpm"
      elif command -v yum >/dev/null 2>&1; then
        $SUDO yum install -y "$rpm"
      else
        $SUDO rpm -Uvh --force "$rpm"
      fi
      return 0
    fi
    ;;
  dmg)
    local dmg
    if dmg=$(resolve_artifact "${release_name}.dmg"); then
      install_dmg "$dmg"
      return 0
    fi
    ;;
  esac
  return 1
}

main() {
  log "Installing YARA ${component_version} for ${os_id}/${arch_id}${release_version:+ (release $release_version)}"
  if [ "${FORCE_TAR_INSTALL:-0}" -ne 1 ]; then
    if install_package; then
      log "Package installation complete"
      return 0
    fi
    warn "Package artifact not found or install failed; falling back to tarball"
  fi

  local tarball
  if tarball=$(resolve_artifact "${release_name}.tar.gz"); then
    install_tarball "$tarball"
    log "Tarball installation complete"
  else
    log "Unable to locate artifact for ${release_name} (.deb/.rpm/.dmg/.tar.gz)"
    exit 1
  fi
}

main "$@"
