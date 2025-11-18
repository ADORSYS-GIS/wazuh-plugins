#!/usr/bin/env bash
set -euo pipefail

triplet="${ARTIFACT_TRIPLET:-native}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
builder_root="$(cd "${script_dir}/.." && pwd)"
dest="${ARTIFACT_DEST:-${builder_root}/dist/${triplet}}"
version="${PIPELINE_VERSION:-dev}"
rule_bundle="${RULE_BUNDLE:-${builder_root}/rules}"
build_dir=""

cleanup() {
    if [[ -n "${build_dir}" && -d "${build_dir}" ]]; then
        rm -rf "${build_dir}"
    fi
}

trap cleanup EXIT

detect_make_jobs() {
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

install_with_package_manager() {
    local missing_tools=("$@")
    if [[ ${#missing_tools[@]} -eq 0 ]]; then
        return 0
    fi

    if [[ "$(uname -s)" == "Darwin" ]] && command -v brew >/dev/null 2>&1; then
        local packages=()
        for tool in "${missing_tools[@]}"; do
            case "$tool" in
                pkg-config)
                    packages+=("pkg-config")
                    ;;
                glibtoolize|libtoolize)
                    packages+=("libtool")
                    ;;
                *)
                    packages+=("$tool")
                    ;;
            esac
        done
        if [[ ${#packages[@]} -gt 0 ]]; then
            HOMEBREW_NO_AUTO_UPDATE=1 brew install "${packages[@]}"
        fi
        return 0
    fi

    return 1
}

require_tools() {
    local libtool_cmd="libtoolize"
    if [[ "$(uname -s)" == "Darwin" ]]; then
        libtool_cmd="glibtoolize"
    fi

    local required=(curl tar make gcc autoconf automake pkg-config flex bison python3 "$libtool_cmd")
    local missing=()
    for tool in "${required[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing+=("$tool")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        if install_with_package_manager "${missing[@]}"; then
            missing=()
            for tool in "${required[@]}"; do
                if ! command -v "$tool" >/dev/null 2>&1; then
                    missing+=("$tool")
                fi
            done
        fi
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "Missing build dependencies: ${missing[*]}" >&2
        exit 1
    fi
}

prepare_dest() {
    rm -rf "${dest}"
    mkdir -p "${dest}/release"
}

install_rules_and_scripts() {
    local release_root="${dest}/release"
    if [[ -d "${rule_bundle}" ]]; then
        mkdir -p "${release_root}/rules"
        cp -R "${rule_bundle}/." "${release_root}/rules/"
    fi
    mkdir -p "${release_root}/scripts"
    cp "${script_dir}/scan.sh" "${release_root}/scripts/scan.sh"
    cp "${script_dir}/scan-fixtures.sh" "${release_root}/scripts/scan-fixtures.sh"
    chmod +x "${release_root}/scripts/"*.sh
}

write_metadata() {
    local release_root="${dest}/release"
    local yara_version="$1"
    cat >"${release_root}/BUILDINFO.txt" <<EOF_INFO
# YARA native build
PIPELINE_VERSION=${version}
TRIPLET=${triplet}
YARA_VERSION=${yara_version}
EOF_INFO
    cat >"${release_root}/README.txt" <<EOF_README
YARA ${yara_version}
This archive was produced by the Wazuh plugins builder for ${triplet}.
EOF_README
}

main() {
    require_tools
    prepare_dest

    local resolver_script="${script_dir}/resolve_yara_version.py"
    local yara_version
    if ! yara_version=$(python3 "${resolver_script}"); then
        echo "Unable to resolve a YARA version" >&2
        exit 1
    fi
    local jobs="$(detect_make_jobs)"
    build_dir="$(mktemp -d)"

    curl -fsSL "https://github.com/VirusTotal/yara/archive/refs/tags/${yara_version}.tar.gz" -o "${build_dir}/yara.tar.gz"
    mkdir -p "${build_dir}/src"
    tar -xzf "${build_dir}/yara.tar.gz" --strip-components=1 -C "${build_dir}/src"

    pushd "${build_dir}/src" >/dev/null
    ./bootstrap.sh

    local rpath_flag
    if [[ "$(uname -s)" == "Darwin" ]]; then
        rpath_flag="-Wl,-rpath,@loader_path/../lib -Wl,-install_name,@rpath/libyara.dylib"
    else
        rpath_flag="-Wl,-rpath,\\$ORIGIN/../lib"
    fi

    LDFLAGS="${LDFLAGS:-} ${rpath_flag}" ./configure --prefix="${dest}/release"
    make -j "${jobs}"
    make install
    popd >/dev/null

    install_rules_and_scripts
    write_metadata "${yara_version}"
}

main "$@"
