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
release_name=""
release_root=""

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
        cmake
        ninja-build
        rustc
        cargo
        libpcre2-dev
        libpcre3-dev
        libyaml-dev
        libjansson-dev
        libmagic-dev
        libpcap-dev
        libcap-ng-dev
        libnss3-dev
        libnspr4-dev
        liblz4-dev
        liblzma-dev
        libnet1-dev
        zlib1g-dev
        libhtp-dev
    )

    sudo apt-get update -qq
    sudo apt-get install -y "${packages[@]}"
}

ensure_macos_environment() {
    if [[ "$(uname -s)" != "Darwin" ]] || ! command -v brew >/dev/null 2>&1; then
        return 0
    fi

    brew update
    brew install autoconf automake libtool pkg-config pcre2 libyaml jansson libmagic libpcap lz4 libnet rust cmake ninja

    local pkg
    local pkgconfig_paths=()
    for pkg in pcre2 libyaml jansson libmagic libpcap libnet lz4; do
        if prefix="$(brew --prefix "$pkg" 2>/dev/null)"; then
            if [[ -d "${prefix}/lib/pkgconfig" ]]; then
                pkgconfig_paths+=("${prefix}/lib/pkgconfig")
            fi
            if [[ -d "${prefix}/include" ]]; then
                export CPPFLAGS="-I${prefix}/include ${CPPFLAGS:-}"
            fi
            if [[ -d "${prefix}/lib" ]]; then
                export LDFLAGS="-L${prefix}/lib ${LDFLAGS:-}"
            fi
        fi
    done

    if [[ ${#pkgconfig_paths[@]} -gt 0 ]]; then
        local joined
        joined="$(IFS=:; echo "${pkgconfig_paths[*]}")"
        export PKG_CONFIG_PATH="${joined}:${PKG_CONFIG_PATH:-}"
    fi
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
    local upstream_tag="${4:-}"
    local upstream_version="${5:-}"

    {
        printf '{\n'
        printf '  "artifact": "%s",\n' "${component}"
        printf '  "version": "%s",\n' "${component_version}"
        printf '  "os": "%s",\n' "${platform_os}"
        printf '  "arch": "%s",\n' "${platform_arch}"
        printf '  "build": {\n'
        printf '    "timestamp": "%s",\n' "$(date -u +%FT%TZ)"
        printf '    "builder": "suricata-native",\n'
        printf '    "triplet": "%s",\n' "${triplet}"
        printf '    "user": "%s"\n' "$(whoami 2>/dev/null || echo unknown)"
        printf '  },\n'
        printf '  "source": {\n'
        printf '    "repository": "%s",\n' "${PIPELINE_REPO:-}"
        printf '    "commit": "%s",\n' "${PIPELINE_COMMIT:-}"
        printf '    "ref": "%s"\n' "${PIPELINE_REF:-}"
        printf '  }'
        if [[ -n "${upstream_tag}" || -n "${upstream_version}" ]]; then
            printf ',\n  "upstream": {\n'
            local wrote=false
            if [[ -n "${upstream_tag}" ]]; then
                printf '    "suricata_tag": "%s"' "${upstream_tag}"
                wrote=true
            fi
            if [[ -n "${upstream_version}" ]]; then
                if [[ "${wrote}" == true ]]; then
                    printf ',\n'
                else
                    printf '\n'
                fi
                printf '    "suricata": "%s"' "${upstream_version}"
            else
                printf '\n'
            fi
            printf '\n  }'
        fi
        printf '\n}\n'
    } >"${output}"
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

    local staging
    staging="$(mktemp -d)"
    mkdir -p "${staging}/opt/wazuh/suricata" "${staging}/DEBIAN"

    cp -R "${release_dir}/." "${staging}/opt/wazuh/suricata/"

    local deb_arch="${platform_arch}"
    case "${deb_arch}" in
        amd64|arm64) ;;
        *) deb_arch="all" ;;
    esac

    local installed_size
    installed_size=$(du -ks "${staging}/opt/wazuh/suricata" | awk '{print $1}')

    local deb_version="${component_version}"
    if [[ "${deb_version}" == v* ]]; then
        deb_version="${deb_version#v}"
    fi

    cat >"${staging}/DEBIAN/control" <<EOF
Package: suricata
Version: ${deb_version}
Architecture: ${deb_arch}
Maintainer: Wazuh Plugins <packages@wazuh.com>
Section: utils
Priority: optional
Installed-Size: ${installed_size:-0}
Description: Suricata IDS companion packaged for Wazuh deployments
EOF

    local deb_out="${dest}/artifacts/${outbase}.deb"
    dpkg-deb --build "${staging}" "${deb_out}" >/dev/null
    rm -rf "${staging}"
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

    local staging
    staging="$(mktemp -d)"
    mkdir -p "${staging}/${outbase}"

    cp -R "${release_dir}/." "${staging}/${outbase}/"

    local dmg_out="${dest}/artifacts/${outbase}.dmg"
    hdiutil create -volname "${outbase}" -srcfolder "${staging}" -format UDZO -ov "${dmg_out}" >/dev/null
    rm -rf "${staging}"
    printf '%s\n' "${dmg_out}"
}

prune_payload_directory() {
    local target_dir="$1"
    [[ -d "${target_dir}" ]] || return 0

    rm -rf "${target_dir}/include"
    rm -rf "${target_dir}/share/doc" "${target_dir}/share/man" "${target_dir}/share/info"
    rm -rf "${target_dir}/lib/pkgconfig"
    if [[ -d "${target_dir}/lib" ]]; then
        find "${target_dir}/lib" -type f \( -name '*.a' -o -name '*.la' \) -delete
    fi
}

prune_release_payload() {
    prune_payload_directory "${release_root}"
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
                ninja)
                    packages+=("ninja")
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

    local required=(curl tar make gcc autoconf automake pkg-config cmake ninja rustc cargo python3 "$libtool_cmd")

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
    local required_libs=(libpcap libpcre2-8 yaml-0.1 jansson libmagic libnet liblz4 zlib)
    if [[ "${platform_os}" == "linux" ]]; then
        required_libs+=(libcap-ng)
    fi

    local missing=()
    for lib in "${required_libs[@]}"; do
        if ! pkg-config --exists "$lib" >/dev/null 2>&1; then
            missing+=("$lib")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "Missing required libraries (pkg-config): ${missing[*]}" >&2
        echo "Ensure libpcap, PCRE2, libyaml, jansson, libmagic, libnet, and lz4/zlib development headers are installed." >&2
        exit 1
    fi
}

prepare_dest() {
    rm -rf "${dest}"
    release_root="${dest}/release/${release_name}"
    mkdir -p "${release_root}" "${dest}/artifacts"
    mkdir -p "${release_root}/var/log/suricata" "${release_root}/var/run" "${release_root}/var/lib/suricata"
}

install_rules_and_scripts() {
    if [[ -d "${rule_bundle}" ]]; then
        mkdir -p "${release_root}/rules" "${release_root}/custom-rules"
        cp -R "${rule_bundle}/." "${release_root}/rules/"
        cp -R "${rule_bundle}/." "${release_root}/custom-rules/"
    fi

    mkdir -p "${release_root}/scripts"
    cp "${script_dir}/entrypoint.sh" "${release_root}/scripts/entrypoint.sh"
    cp "${script_dir}/run-regression.sh" "${release_root}/scripts/run-regression.sh"
    chmod +x "${release_root}/scripts/"*.sh
}

write_metadata() {
    local builder_version="$1"
    local suricata_tag="$2"
    local suricata_version="$3"
    cat >"${release_root}/BUILDINFO.txt" <<EOF_INFO
# Suricata native build
PIPELINE_VERSION=${builder_version}
TRIPLET=${triplet}
SURICATA_TAG=${suricata_tag}
SURICATA_VERSION=${suricata_version}
RELEASE_NAME=${release_name}
EOF_INFO
    cat >"${release_root}/README.txt" <<EOF_README
Wazuh Suricata package ${builder_version}
Contains Suricata upstream release ${suricata_version} (${suricata_tag}) for ${platform_os}/${platform_arch}.
EOF_README
}

package_release() {
    local builder_version="$1"
    local suricata_tag="$2"
    local suricata_version="$3"

    local outbase="${release_name:-suricata-${builder_version}-${platform_os}-${platform_arch}}"
    local dist_dir="${dest}/artifacts"
    local artifact_root="${dist_dir}/${outbase}"
    local sbom_dir="${artifact_root}/SBOM"
    local tarball="${dist_dir}/${outbase}.tar.gz"
    local checksum_file_path="${dist_dir}/${outbase}.sha256.txt"
    local pom_file="${artifact_root}/${outbase}.pom.json"

    rm -rf "${artifact_root}"
    mkdir -p "${artifact_root}" "${sbom_dir}"

    cp -R "${release_root}/." "${artifact_root}/"
    prune_payload_directory "${artifact_root}"

    generate_sboms "${artifact_root}" "${sbom_dir}/${outbase}.sbom.spdx.json" "${sbom_dir}/${outbase}.sbom.cdx.json"
    generate_pom "${pom_file}" "${outbase}" "${builder_version}" "${suricata_tag}" "${suricata_version}"

    (cd "${dist_dir}" && tar -czf "${tarball##*/}" "${outbase}")

    local deb_pkg dmg_pkg
    deb_pkg=$(package_deb "${outbase}" "${release_root}" "${builder_version}" || true)
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

build_suricata() {
    local suricata_tag="$1"
    local suricata_version="$2"

    local jobs
    jobs="$(detect_make_jobs)"
    build_dir="$(mktemp -d)"

    curl -fsSL "https://github.com/OISF/suricata/archive/refs/tags/${suricata_tag}.tar.gz" -o "${build_dir}/suricata.tar.gz"
    mkdir -p "${build_dir}/src"
    tar -xzf "${build_dir}/suricata.tar.gz" --strip-components=1 -C "${build_dir}/src"

    pushd "${build_dir}/src" >/dev/null

    local configure_args=(
        --prefix="${release_root}"
        --sysconfdir="${release_root}/etc"
        --localstatedir="${release_root}/var"
        --disable-gccmarch-native
    )

    ./configure "${configure_args[@]}"
    make -j "${jobs}"
    make install
    make install-conf || true
    make install-rules || true
    popd >/dev/null

    prune_release_payload
    install_rules_and_scripts
    write_metadata "${version}" "${suricata_tag}" "${suricata_version}"
    package_release "${version}" "${suricata_tag}" "${suricata_version}"
}

main() {
    detect_platform
    ensure_linux_dependencies
    ensure_macos_environment
    require_tools
    require_libraries

    release_name="suricata-${version}-${platform_os}-${platform_arch}"
    prepare_dest

    local resolver_script="${script_dir}/resolve_suricata_version.py"
    local suricata_tag
    if ! suricata_tag=$(python3 "${resolver_script}"); then
        echo "Unable to resolve a Suricata release tag" >&2
        exit 1
    fi

    local suricata_version="${suricata_tag}"
    if [[ "${suricata_version}" == suricata-* ]]; then
        suricata_version="${suricata_version#suricata-}"
    fi
    if [[ "${suricata_version}" == v* ]]; then
        suricata_version="${suricata_version#v}"
    fi

    build_suricata "${suricata_tag}" "${suricata_version}"
}

main "$@"
