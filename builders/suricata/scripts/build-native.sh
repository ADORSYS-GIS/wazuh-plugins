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
syft_bin=""
platform_os=""
platform_arch=""
release_name=""
release_root=""
component_prefix="/opt/wazuh/suricata"
component_root=""

export PATH="${HOME}/.cargo/bin:${PATH}"

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
        cmake
        ninja-build
        rustc
        cargo
        cbindgen
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

version_ge() {
    local a="$1" b="$2"
    if [[ -z "${a}" || -z "${b}" ]]; then
        return 1
    fi
    local first
    first="$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -n1)"
    [[ "${first}" == "$b" ]]
}

ensure_cbindgen_version() {
    if [[ "$(uname -s)" != "Linux" ]]; then
        return 0
    fi
    local required="0.20.0"
    local install_version="0.26.0"
    local current=""
    if command -v cbindgen >/dev/null 2>&1; then
        current="$(cbindgen --version 2>/dev/null | awk '{print $2}')"
        if version_ge "${current}" "${required}"; then
            return 0
        fi
    fi

    if ! command -v cargo >/dev/null 2>&1; then
        echo "cargo not available to install a newer cbindgen" >&2
        return 1
    fi

    echo "Installing cbindgen ${install_version} via cargo" >&2
    cargo install --locked --force cbindgen --version "${install_version}"
    hash -r
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

detect_make_jobs() { bh_detect_make_jobs; }

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

    local staging
    staging="$(mktemp -d)"
    mkdir -p "${staging}/DEBIAN"

    cp -R "${release_dir}/." "${staging}/"

    local deb_arch="${platform_arch}"
    case "${deb_arch}" in
        amd64|arm64) ;;
        *) deb_arch="all" ;;
    esac

    local component_path="${staging}${component_prefix}"
    local installed_size
    installed_size=$(du -ks "${component_path}" | awk '{print $1}')

    local deb_version="${component_version}"
    if [[ "${deb_version}" == v* ]]; then
        deb_version="${deb_version#v}"
    fi

    local control_tpl="${builder_root}/package-tpl.txt"
    bh_write_deb_control_from_template \
        "${staging}" \
        "${control_tpl}" \
        "suricata" \
        "Wazuh Plugins <info@adorsys.com>" \
        "Suricata IDS companion packaged for Wazuh deployments" \
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
    prune_payload_directory "${component_root}"
}

require_tools() { bh_require_tools cmake ninja rustc cargo cbindgen; }

require_libraries() {
    local required_libs=(libpcap libpcre2-8 yaml-0.1 jansson libmagic liblz4 zlib)
    if [[ "${platform_os}" == "linux" ]]; then
        required_libs+=(libcap-ng)
    fi
    bh_require_libraries "${required_libs[@]}"
}

prepare_dest() {
    release_root="${dest}/release/${release_name}"
    component_root="${release_root}${component_prefix}"
    rm -rf "${release_root}"
    mkdir -p "${component_root}" "${dest}/artifacts"
    mkdir -p "${component_root}/var/log/suricata" "${component_root}/var/run" "${component_root}/var/lib/suricata"
}

install_rules_and_scripts() {
    if [[ -d "${rule_bundle}" ]]; then
        mkdir -p "${component_root}/rules" "${component_root}/custom-rules"
        cp -R "${rule_bundle}/." "${component_root}/rules/"
        cp -R "${rule_bundle}/." "${component_root}/custom-rules/"
    fi

    mkdir -p "${component_root}/scripts"
    cp "${script_dir}/entrypoint.sh" "${component_root}/scripts/entrypoint.sh"
    cp "${script_dir}/run-regression.sh" "${component_root}/scripts/run-regression.sh"
    chmod +x "${component_root}/scripts/"*.sh
}

write_metadata() {
    local builder_version="$1"
    local suricata_tag="$2"
    local suricata_version="$3"
    cat >"${component_root}/BUILDINFO.txt" <<EOF_INFO
# Suricata native build
PIPELINE_VERSION=${builder_version}
TRIPLET=${triplet}
SURICATA_TAG=${suricata_tag}
SURICATA_VERSION=${suricata_version}
RELEASE_NAME=${release_name}
EOF_INFO
    cat >"${component_root}/README.txt" <<EOF_README
Wazuh Suricata package ${builder_version}
Contains Suricata upstream release ${suricata_version} (${suricata_tag}) for ${platform_os}/${platform_arch}.
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

    local libs=(libnet.so.1)
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
            mkdir -p "${component_root}/lib"
            cp "${found}" "${component_root}/lib/"
            copied=1
        fi
    done

    if [[ "${copied}" -eq 0 ]]; then
        echo "Warning: Unable to bundle libnet runtime library; Suricata may require libnet.so.1 on the host." >&2
    fi
}

wrap_linux_binaries() {
    if [[ "${platform_os}" != "linux" ]]; then
        return 0
    fi

    local bin_dir="${component_root}/bin"
    for name in suricata suricatactl suricatasc; do
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
    prune_payload_directory "${artifact_root}${component_prefix}"

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

    if [[ -x "./autogen.sh" ]]; then
        ./autogen.sh
    fi

    local configure_args=(
        --prefix="${component_prefix}"
        --sysconfdir="${component_prefix}/etc"
        --localstatedir="${component_prefix}/var"
        --disable-gccmarch-native
    )
    local revision_label="Wazuh Plugin Build ${PIPELINE_COMMIT:-unknown}"
    local escaped_revision="${revision_label//\"/\\\"}"
    local revision_header="${build_dir}/revision.h"
    printf '#define REVISION "%s"\n' "${escaped_revision}" > "${revision_header}"

    local old_cppflags="${CPPFLAGS:-}"
    CPPFLAGS="${old_cppflags} -include ${revision_header}"
    export CPPFLAGS
    ./configure "${configure_args[@]}"
    make -j "${jobs}"
    make DESTDIR="${release_root}" install
    make DESTDIR="${release_root}" install-conf || true
    make DESTDIR="${release_root}" install-rules || true
    CPPFLAGS="${old_cppflags}"
    popd >/dev/null

    prune_release_payload
    bundle_linux_runtime_libs
    wrap_linux_binaries
    install_rules_and_scripts
    write_metadata "${version}" "${suricata_tag}" "${suricata_version}"
    package_release "${version}" "${suricata_tag}" "${suricata_version}"
}

main() {
    detect_platform
    ensure_linux_dependencies
    ensure_cbindgen_version
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
