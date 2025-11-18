#!/usr/bin/env bash
set -euo pipefail

triplet="${ARTIFACT_TRIPLET:-native}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
builder_root="$(cd "${script_dir}/.." && pwd)"
dest="${ARTIFACT_DEST:-${builder_root}/dist/${triplet}}"
version="${PIPELINE_VERSION:-dev}"
rule_bundle="${RULE_BUNDLE:-${builder_root}/rules}"
build_dir=""
syft_bin=""
platform_os=""
platform_arch=""
release_root="${dest}/release"

ensure_linux_dependencies() {
    if [[ "$(uname -s)" != "Linux" ]]; then
        return 0
    fi

    if ! command -v sudo >/dev/null 2>&1 || ! command -v apt-get >/dev/null 2>&1; then
        return 0
    fi

    local packages=(
        build-essential
        autoconf
        automake
        libtool
        pkg-config
        git
        libssl-dev
        libpcre2-dev
        libmagic-dev
        libjansson-dev
        libprotobuf-c-dev
        protobuf-c-compiler
    )

    sudo apt-get update -qq
    sudo apt-get install -y "${packages[@]}"
}

ensure_macos_environment() {
    if [[ "$(uname -s)" != "Darwin" ]] || ! command -v brew >/dev/null 2>&1; then
        return 0
    fi

    brew update
    brew install autoconf automake libtool pkg-config openssl@3 pcre2 libmagic jansson protobuf-c

    local openssl_prefix libmagic_prefix pcre2_prefix
    openssl_prefix="$(brew --prefix openssl@3)"
    libmagic_prefix="$(brew --prefix libmagic)"
    pcre2_prefix="$(brew --prefix pcre2)"

    export PKG_CONFIG_PATH="${openssl_prefix}/lib/pkgconfig:${libmagic_prefix}/lib/pkgconfig:${pcre2_prefix}/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
    export CPPFLAGS="-I${openssl_prefix}/include -I${libmagic_prefix}/include -I${pcre2_prefix}/include ${CPPFLAGS:-}"
    export LDFLAGS="-L${openssl_prefix}/lib -L${libmagic_prefix}/lib -L${pcre2_prefix}/lib ${LDFLAGS:-}"
}

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

detect_platform() {
    case "$(uname -s)" in
        Linux) platform_os="linux" ;;
        Darwin) platform_os="macos" ;;
        *) platform_os="unknown" ;;
    esac

    case "$(uname -m)" in
        x86_64|amd64) platform_arch="amd64" ;;
        aarch64|arm64) platform_arch="arm64" ;;
        *) platform_arch="unknown" ;;
    esac
}

ensure_syft() {
    if [[ -n "${syft_bin}" && -x "${syft_bin}" ]]; then
        return 0
    fi

    if command -v syft >/dev/null 2>&1; then
        syft_bin="$(command -v syft)"
        return 0
    fi

    local tools_dir="${dest}/.tools"
    mkdir -p "${tools_dir}"

    local syft_version="${SYFT_VERSION:-v1.5.0}"
    if command -v curl >/dev/null 2>&1 && command -v tar >/dev/null 2>&1; then
        curl -sSfL "https://raw.githubusercontent.com/anchore/syft/main/install.sh" | \
            sh -s -- -b "${tools_dir}" "${syft_version}"
    fi

    if [[ -x "${tools_dir}/syft" ]]; then
        syft_bin="${tools_dir}/syft"
        return 0
    fi

    echo "Unable to install syft for SBOM generation" >&2
    exit 1
}

generate_sboms() {
    local scan_dir="$1"
    local spdx_out="$2"
    local cdx_out="$3"

    ensure_syft

    mkdir -p "$(dirname "${spdx_out}")" "$(dirname "${cdx_out}")"

    local temp_spdx temp_cdx
    temp_spdx="$(mktemp)"
    temp_cdx="$(mktemp)"

    "${syft_bin}" "dir:${scan_dir}" -o spdx-json > "${temp_spdx}"
    "${syft_bin}" "dir:${scan_dir}" -o cyclonedx-json > "${temp_cdx}"

    mv "${temp_spdx}" "${spdx_out}"
    mv "${temp_cdx}" "${cdx_out}"
}

generate_pom() {
    local output="$1"
    local component="$2"
    local component_version="$3"

    cat >"${output}" <<EOF
{
  "artifact": "${component}",
  "version": "${component_version}",
  "os": "${platform_os}",
  "arch": "${platform_arch}",
  "build": {
    "timestamp": "$(date -u +%FT%TZ)",
    "builder": "yara-native",
    "triplet": "${triplet}",
    "user": "$(whoami 2>/dev/null || echo unknown)"
  },
  "source": {
    "repository": "${PIPELINE_REPO:-}",
    "commit": "${PIPELINE_COMMIT:-}",
    "ref": "${PIPELINE_REF:-}"
  }
}
EOF
}

checksum_file() {
    local file="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "${file}"
    else
        shasum -a 256 "${file}"
    fi
}

package_deb() {
    local outbase="$1"
    local release_dir="$2"
    local component_version="$3"

    if [[ "${platform_os}" != "linux" ]]; then
        return 0
    fi

    if ! command -v dpkg-deb >/dev/null 2>&1; then
        echo "dpkg-deb not available; skipping .deb packaging" >&2
        return 0
    fi

    local staging="${dest}/deb-build"
    rm -rf "${staging}"
    mkdir -p "${staging}/opt/wazuh/yara" "${staging}/DEBIAN"

    cp -R "${release_dir}/." "${staging}/opt/wazuh/yara/"

    local deb_arch="${platform_arch}"
    case "${deb_arch}" in
        amd64|arm64) ;;
        *) deb_arch="all" ;;
    esac

    local installed_size
    installed_size=$(du -ks "${staging}/opt/wazuh/yara" | awk '{print $1}')

    cat >"${staging}/DEBIAN/control" <<EOF
Package: yara
Version: ${component_version}
Architecture: ${deb_arch}
Maintainer: Wazuh Plugins <packages@wazuh.com>
Section: utils
Priority: optional
Installed-Size: ${installed_size:-0}
Description: YARA rule scanner packaged for Wazuh deployments
EOF

    local deb_out="${dest}/artifacts/${outbase}.deb"
    dpkg-deb --build "${staging}" "${deb_out}" >/dev/null
    printf '%s\n' "${deb_out}"
}

package_dmg() {
    local outbase="$1"
    local release_dir="$2"

    if [[ "${platform_os}" != "macos" ]]; then
        return 0
    fi

    if ! command -v hdiutil >/dev/null 2>&1; then
        echo "hdiutil not available; skipping .dmg packaging" >&2
        return 0
    fi

    local staging="${dest}/dmg-build"
    rm -rf "${staging}"
    mkdir -p "${staging}"

    cp -R "${release_dir}" "${staging}/yara"

    local dmg_out="${dest}/artifacts/${outbase}.dmg"
    hdiutil create -volname "${outbase}" -srcfolder "${staging}" -format UDZO -ov "${dmg_out}" >/dev/null
    printf '%s\n' "${dmg_out}"
}

package_release() {
    local yara_version="$1"

    detect_platform

    local outbase="yara-${yara_version}-${platform_os}-${platform_arch}"
    local artifact_root="${dest}/artifacts/${outbase}"
    local sbom_dir="${artifact_root}/SBOM"
    local dist_dir="${dest}/artifacts"
    local tarball="${dist_dir}/${outbase}.tar.gz"
    local checksum_file_path="${dist_dir}/${outbase}.sha256.txt"
    local pom_file="${artifact_root}/${outbase}.pom.json"

    rm -rf "${artifact_root}"
    mkdir -p "${artifact_root}" "${sbom_dir}"

    cp -R "${release_root}/." "${artifact_root}/"

    generate_sboms "${artifact_root}" "${sbom_dir}/${outbase}.sbom.spdx.json" "${sbom_dir}/${outbase}.sbom.cdx.json"
    generate_pom "${pom_file}" "${outbase}" "${yara_version}"

    (cd "${dist_dir}" && tar -czf "${tarball##*/}" "${outbase}")

    local deb_pkg dmg_pkg
    deb_pkg=$(package_deb "${outbase}" "${release_root}" "${yara_version}" || true)
    dmg_pkg=$(package_dmg "${outbase}" "${release_root}" || true)

    {
        checksum_file "${tarball}"
        checksum_file "${sbom_dir}/${outbase}.sbom.spdx.json"
        checksum_file "${sbom_dir}/${outbase}.sbom.cdx.json"
        checksum_file "${pom_file}"
        if [[ -n "${deb_pkg:-}" ]]; then
            checksum_file "${deb_pkg}"
        fi
        if [[ -n "${dmg_pkg:-}" ]]; then
            checksum_file "${dmg_pkg}"
        fi
    } > "${checksum_file_path}"
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

    if [[ "$(uname -s)" == "Linux" ]]; then
        required+=(dpkg-deb)
    fi

    if [[ "$(uname -s)" == "Darwin" ]]; then
        required+=(hdiutil)
    fi
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

require_libraries() {
    local required_libs=(openssl libpcre2-8 libmagic jansson libprotobuf-c)
    local missing=()

    for lib in "${required_libs[@]}"; do
        if ! pkg-config --exists "$lib"; then
            missing+=("$lib")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "Missing required libraries (pkg-config): ${missing[*]}" >&2
        echo "Ensure crypto, PCRE2, libmagic, jansson, and protobuf-c development packages are installed." >&2
        exit 1
    fi
}

prepare_dest() {
    rm -rf "${dest}"
    mkdir -p "${release_root}"
}

install_rules_and_scripts() {
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
    ensure_linux_dependencies
    ensure_macos_environment
    require_tools
    require_libraries
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
        rpath_flag='-Wl,-rpath,$ORIGIN/../lib'
    fi

    local configure_args=(
        --prefix="${dest}/release"
        --with-crypto
        --enable-magic
    )

    LDFLAGS="${LDFLAGS:-} ${rpath_flag}" ./configure "${configure_args[@]}"
    make -j "${jobs}"
    make install
    popd >/dev/null

    install_rules_and_scripts
    write_metadata "${yara_version}"

    package_release "${yara_version}"
}

main "$@"
