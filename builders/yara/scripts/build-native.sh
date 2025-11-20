#!/usr/bin/env bash
set -euo pipefail

triplet="${ARTIFACT_TRIPLET:-native}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
builder_root="$(cd "${script_dir}/.." && pwd)"
common_dir="${builder_root}/../common"
COMMON_HELPERS="${common_dir}/build-helpers.sh"
dest="${ARTIFACT_DEST:-${builder_root}/dist/${triplet}}"
version="${PIPELINE_VERSION:-dev}"
rule_bundle="${RULE_BUNDLE:-${builder_root}/rules}"
build_dir=""
platform_os=""
platform_arch=""
release_name=""
release_root=""

if [[ -f "${COMMON_HELPERS}" ]]; then
    # shellcheck disable=SC1090
    source "${COMMON_HELPERS}"
fi

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
    bh_detect_platform
    platform_os="${BH_PLATFORM_OS:-unknown}"
    platform_arch="${BH_PLATFORM_ARCH:-unknown}"
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
    bh_generate_sboms "${dest}" "${scan_dir}" "${spdx_out}" "${cdx_out}"
}

generate_pom() {
    local output="$1"
    local component="$2"
    local component_version="$3"
    local upstream_version="${4:-}"

    {
        printf '{\n'
        printf '  "artifact": "%s",\n' "${component}"
        printf '  "version": "%s",\n' "${component_version}"
        printf '  "os": "%s",\n' "${platform_os}"
        printf '  "arch": "%s",\n' "${platform_arch}"
        printf '  "build": {\n'
        printf '    "timestamp": "%s",\n' "$(date -u +%FT%TZ)"
        printf '    "builder": "yara-native",\n'
        printf '    "triplet": "%s",\n' "${triplet}"
        printf '    "user": "%s"\n' "$(whoami 2>/dev/null || echo unknown)"
        printf '  },\n'
        printf '  "source": {\n'
        printf '    "repository": "%s",\n' "${PIPELINE_REPO:-}"
        printf '    "commit": "%s",\n' "${PIPELINE_COMMIT:-}"
        printf '    "ref": "%s"\n' "${PIPELINE_REF:-}"
        printf '  }'
        if [[ -n "${upstream_version}" ]]; then
            printf ',\n  "upstream": {\n'
            printf '    "yara": "%s"\n' "${upstream_version}"
            printf '  }'
        else
            printf '\n'
        fi
        printf '\n}\n'
    } >"${output}"
}

checksum_file() { bh_checksum_file "$1"; }

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

    local staging="$(mktemp -d)"
    mkdir -p "${staging}/opt/wazuh/yara" "${staging}/DEBIAN"

    cp -R "${release_dir}/." "${staging}/opt/wazuh/yara/"

    local deb_arch="${platform_arch}"
    case "${deb_arch}" in
        amd64|arm64) ;;
        *) deb_arch="all" ;;
    esac

    local installed_size
    installed_size=$(du -ks "${staging}/opt/wazuh/yara" | awk '{print $1}')

    local deb_version="${component_version}"
    if [[ "${deb_version}" == v* ]]; then
        deb_version="${deb_version#v}"
    fi

    local control_tpl="${builder_root}/package-tpl.txt"
    bh_write_deb_control_from_template \
        "${staging}" \
        "${control_tpl}" \
        "yara" \
        "Wazuh Plugins <info@adorsys.com>" \
        "YARA rule scanner packaged for Wazuh deployments" \
        "${deb_version}" \
        "${deb_arch}" \
        "${installed_size}"

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

    local staging="$(mktemp -d)"
    mkdir -p "${staging}/${outbase}"

    cp -R "${release_dir}/." "${staging}/${outbase}/"

    local dmg_out="${dest}/artifacts/${outbase}.dmg"
    hdiutil create -volname "${outbase}" -srcfolder "${staging}" -format UDZO -ov "${dmg_out}" >/dev/null
    rm -rf "${staging}"
    printf '%s\n' "${dmg_out}"
}

prune_payload_directory() {
    bh_prune_payload_directory "$1"
}

prune_release_payload() {
    prune_payload_directory "${release_root}"
}

package_release() {
    local builder_version="$1"
    local yara_version="$2"

    local outbase="${release_name:-yara-${builder_version}-${platform_os}-${platform_arch}}"
    local artifact_root="${dest}/artifacts/${outbase}"
    local sbom_dir="${artifact_root}/SBOM"
    local dist_dir="${dest}/artifacts"
    local tarball="${dist_dir}/${outbase}.tar.gz"
    local checksum_file_path="${dist_dir}/${outbase}.sha256.txt"
    local pom_file="${artifact_root}/${outbase}.pom.json"

    rm -rf "${artifact_root}"
    mkdir -p "${artifact_root}" "${sbom_dir}"

    cp -R "${release_root}/." "${artifact_root}/"
    prune_payload_directory "${artifact_root}"

    generate_sboms "${artifact_root}" "${sbom_dir}/${outbase}.sbom.spdx.json" "${sbom_dir}/${outbase}.sbom.cdx.json"
    generate_pom "${pom_file}" "${outbase}" "${builder_version}" "${yara_version}"

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

require_tools() { bh_require_tools flex bison; }

require_libraries() {
    local required_libs=(openssl libpcre2-8 libmagic jansson libprotobuf-c)
    bh_require_libraries "${required_libs[@]}"
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
    local builder_version="$1"
    local yara_version="$2"
    cat >"${release_root}/BUILDINFO.txt" <<EOF_INFO
# YARA native build
PIPELINE_VERSION=${builder_version}
TRIPLET=${triplet}
YARA_VERSION=${yara_version}
RELEASE_NAME=${release_name}
EOF_INFO
    cat >"${release_root}/README.txt" <<EOF_README
Wazuh YARA package ${builder_version}
Contains YARA upstream release ${yara_version} for ${platform_os}/${platform_arch}.
EOF_README
}

bundle_linux_runtime_libs() {
    if [[ "${platform_os}" != "linux" ]]; then
        return 0
    fi

    local multiarch=""
    if command -v dpkg-architecture >/dev/null 2>&1; then
        multiarch="$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || true)"
    fi

    local search_paths=()
    if [[ -n "${multiarch}" ]]; then
        search_paths+=("/usr/lib/${multiarch}")
    fi
    search_paths+=("/usr/lib" "/usr/lib64")

    local libs=(libcrypto.so.1.1 libssl.so.1.1)
    local copied=0
    for lib in "${libs[@]}"; do
        local found=""
        for base in "${search_paths[@]}"; do
            if [[ -f "${base}/${lib}" ]]; then
                found="${base}/${lib}"
                break
            fi
        done
        if [[ -n "${found}" ]]; then
            mkdir -p "${release_root}/lib"
            cp "${found}" "${release_root}/lib/"
            copied=1
        fi
    done

    if [[ "${copied}" -eq 0 ]]; then
        echo "Warning: Unable to bundle OpenSSL runtime libraries; YARA may expect system libcrypto/libssl." >&2
    fi
}

wrap_linux_binaries() {
    if [[ "${platform_os}" != "linux" ]]; then
        return 0
    fi

    local bin_dir="${release_root}/bin"
    for name in yara yarac; do
        local target="${bin_dir}/${name}"
        if [[ -x "${target}" && ! -L "${target}" ]]; then
            mv "${target}" "${target}.real"
            cat >"${target}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export LD_LIBRARY_PATH="${script_dir}/../lib:${LD_LIBRARY_PATH:-}"
exec "${script_dir}/$(basename "$0").real" "$@"
EOF
            chmod +x "${target}"
        fi
    done
}

main() {
    ensure_linux_dependencies
    ensure_macos_environment
    require_tools
    require_libraries
    detect_platform
    release_name="yara-${version}-${platform_os}-${platform_arch}"
    release_root="${dest}/release/${release_name}"
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
        --prefix="${release_root}"
        --with-crypto
        --enable-magic
    )

    local revision_label="Wazuh Plugin Build ${PIPELINE_COMMIT:-unknown}"
    local escaped_revision="${revision_label//\"/\\\"}"
    local revision_cppflag="-DREVISION=\\\"${escaped_revision}\\\""

    local configure_cppflags="${CPPFLAGS:-} ${revision_cppflag}"
    local configure_ldflags="${LDFLAGS:-} ${rpath_flag}"
    env CPPFLAGS="${configure_cppflags}" \
        LDFLAGS="${configure_ldflags}" \
        ./configure "${configure_args[@]}"
    make -j "${jobs}"
    make install
    popd >/dev/null

    prune_release_payload
    bundle_linux_runtime_libs
    wrap_linux_binaries
    install_rules_and_scripts
    write_metadata "${version}" "${yara_version}"

    package_release "${version}" "${yara_version}"
}

main "$@"
