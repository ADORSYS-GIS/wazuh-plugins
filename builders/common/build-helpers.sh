#!/usr/bin/env bash
set -euo pipefail

# Common helper functions shared by native builders.

bh_detect_platform() {
    case "$(uname -s)" in
        Linux) BH_PLATFORM_OS="linux" ;;
        Darwin) BH_PLATFORM_OS="macos" ;;
        *) BH_PLATFORM_OS="unknown" ;;
    esac

    case "$(uname -m)" in
        x86_64|amd64) BH_PLATFORM_ARCH="amd64" ;;
        aarch64|arm64) BH_PLATFORM_ARCH="arm64" ;;
        *) BH_PLATFORM_ARCH="unknown" ;;
    esac
}

bh_detect_make_jobs() {
    if [[ -n "${MAKE_JOBS:-}" ]]; then
        printf '%s\n' "${MAKE_JOBS}"
        return
    fi
    if command -v nproc >/dev/null 2>&1; then
        nproc
    elif [[ "$(uname -s)" == "Darwin" ]] && command -v sysctl >/dev/null 2>&1; then
        sysctl -n hw.ncpu
    elif command -v getconf >/dev/null 2>&1; then
        getconf _NPROCESSORS_ONLN
    else
        printf '1\n'
    fi
}

bh_ensure_syft() {
    if [[ -n "${BH_SYFT_BIN:-}" && -x "${BH_SYFT_BIN}" ]]; then
        return 0
    fi

    if command -v syft >/dev/null 2>&1; then
        BH_SYFT_BIN="$(command -v syft)"
        return 0
    fi

    local dest_root="${1:?artifact dest required}"
    local tools_dir="${dest_root}/.tools"
    mkdir -p "${tools_dir}"

    local syft_version="${SYFT_VERSION:-v1.5.0}"
    if command -v curl >/dev/null 2>&1 && command -v tar >/dev/null 2>&1; then
        curl -sSfL "https://raw.githubusercontent.com/anchore/syft/main/install.sh" | \
            sh -s -- -b "${tools_dir}" "${syft_version}"
    fi

    if [[ -x "${tools_dir}/syft" ]]; then
        BH_SYFT_BIN="${tools_dir}/syft"
        return 0
    fi

    echo "Unable to install syft for SBOM generation" >&2
    exit 1
}

bh_generate_sboms() {
    local dest_root="$1"
    local scan_dir="$2"
    local spdx_out="$3"
    local cdx_out="$4"

    bh_ensure_syft "${dest_root}"

    mkdir -p "$(dirname "${spdx_out}")" "$(dirname "${cdx_out}")"

    local temp_spdx temp_cdx
    temp_spdx="$(mktemp)"
    temp_cdx="$(mktemp)"

    "${BH_SYFT_BIN}" "dir:${scan_dir}" -o spdx-json > "${temp_spdx}"
    "${BH_SYFT_BIN}" "dir:${scan_dir}" -o cyclonedx-json > "${temp_cdx}"

    mv "${temp_spdx}" "${spdx_out}"
    mv "${temp_cdx}" "${cdx_out}"
}

bh_checksum_file() {
    local file="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "${file}"
    else
        shasum -a 256 "${file}"
    fi
}

bh_install_with_package_manager() {
    local missing_tools=("$@")
    if [[ ${#missing_tools[@]} -eq 0 ]]; then
        return 0
    fi

    if [[ "$(uname -s)" == "Darwin" ]] && command -v brew >/dev/null 2>&1; then
        local packages=()
        for tool in "${missing_tools[@]}"; do
            case "$tool" in
                pkg-config)
                    packages+=("pkg-config") ;;
                glibtoolize|libtoolize)
                    packages+=("libtool") ;;
                ninja)
                    packages+=("ninja") ;;
                *)
                    packages+=("$tool") ;;
            esac
        done
        if [[ ${#packages[@]} -gt 0 ]]; then
            HOMEBREW_NO_AUTO_UPDATE=1 brew install "${packages[@]}"
        fi
        return 0
    fi

    return 1
}

bh_require_tools() {
    local extra_tools=("$@")

    local libtool_cmd="libtoolize"
    if [[ "$(uname -s)" == "Darwin" ]]; then
        libtool_cmd="glibtoolize"
    fi

    local required=(curl tar make gcc autoconf automake pkg-config python3 "${libtool_cmd}")
    required+=("${extra_tools[@]}")

    if [[ "$(uname -s)" == "Linux" ]]; then
        required+=(dpkg-deb)
    fi

    if [[ "$(uname -s)" == "Darwin" ]]; then
        required+=(hdiutil)
    fi

    local missing=()
    for tool in "${required[@]}"; do
        if [[ -n "${tool}" ]] && ! command -v "${tool}" >/dev/null 2>&1; then
            missing+=("${tool}")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        if bh_install_with_package_manager "${missing[@]}"; then
            missing=()
            for tool in "${required[@]}"; do
                if [[ -n "${tool}" ]] && ! command -v "${tool}" >/dev/null 2>&1; then
                    missing+=("${tool}")
                fi
            done
        fi
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "Missing build dependencies: ${missing[*]}" >&2
        exit 1
    fi
}

bh_require_libraries() {
    local libs=("$@")
    local missing=()
    for lib in "${libs[@]}"; do
        if ! pkg-config --exists "${lib}" >/dev/null 2>&1; then
            missing+=("${lib}")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "Missing required libraries (pkg-config): ${missing[*]}" >&2
        exit 1
    fi
}

bh_prune_payload_directory() {
    local target_dir="$1"
    [[ -d "${target_dir}" ]] || return 0

    rm -rf "${target_dir}/include"
    rm -rf "${target_dir}/share" "${target_dir}/share/doc" "${target_dir}/share/man" "${target_dir}/share/info"
    rm -rf "${target_dir}/lib/pkgconfig"
    if [[ -d "${target_dir}/lib" ]]; then
        find "${target_dir}/lib" -type f \( -name '*.a' -o -name '*.la' \) -delete
    fi
}

bh_write_deb_control_from_template() {
    local staging_dir="$1"          # path to DEBIAN dir parent
    local tpl_path="$2"            # template file path
    local package_name="$3"        # fallback Package name
    local maintainer="$4"          # fallback Maintainer
    local description="$5"         # fallback Description
    local deb_version="$6"         # dynamic Version
    local deb_arch="$7"            # dynamic Architecture
    local installed_size="$8"      # dynamic Installed-Size

    : > "${staging_dir}/DEBIAN/control"
    if [[ -f "${tpl_path}" ]]; then
        cat "${tpl_path}" >> "${staging_dir}/DEBIAN/control"
    else
        cat >>"${staging_dir}/DEBIAN/control" <<EOF
Package: ${package_name}
Maintainer: ${maintainer}
Section: utils
Priority: optional
Description: ${description}
EOF
    fi

    # ensure there is a single trailing newline so additional fields remain in the same paragraph
    python3 - <<'PY' "${staging_dir}/DEBIAN/control"
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text()
text = text.rstrip("\n")
path.write_text(text + "\n")
PY

    cat >>"${staging_dir}/DEBIAN/control" <<EOF
Version: ${deb_version}
Architecture: ${deb_arch}
Installed-Size: ${installed_size:-0}
EOF
}
