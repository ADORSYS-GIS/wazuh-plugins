#!/usr/bin/env bash
set -euo pipefail

triplet="${ARTIFACT_TRIPLET:-native}"
dest="${ARTIFACT_DEST:-$(pwd)/dist/${triplet}}"
version="${PIPELINE_VERSION:-dev}"

syft_bin=""
platform_os=""
platform_arch=""

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

    cat >"${output}" <<EOF_POM
{
  "artifact": "${component}",
  "version": "${component_version}",
  "os": "${platform_os}",
  "arch": "${platform_arch}",
  "build": {
    "timestamp": "$(date -u +%FT%TZ)",
    "builder": "suricata-native",
    "triplet": "${triplet}",
    "user": "$(whoami 2>/dev/null || echo unknown)"
  },
  "source": {
    "repository": "${PIPELINE_REPO:-}",
    "commit": "${PIPELINE_COMMIT:-}",
    "ref": "${PIPELINE_REF:-}"
  }
}
EOF_POM
}

checksum_file() {
    local file="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "${file}"
    else
        shasum -a 256 "${file}"
    fi
}

prepare_release_layout() {
    rm -rf "${dest}"
    mkdir -p "${dest}/release/bin" "${dest}/release/rules" "${dest}/release/custom-rules" "${dest}/release/scripts"

    cat >"${dest}/release/bin/suricata" <<'SCRIPT'
#!/usr/bin/env bash
echo "Suricata placeholder binary"
SCRIPT
    chmod +x "${dest}/release/bin/suricata"

    cat >"${dest}/release/BUILDINFO.txt" <<EOF_INFO
# Suricata native build
VERSION=${version}
TRIPLET=${triplet}
EOF_INFO

    cp rules/sample.rules "${dest}/release/rules/sample.rules"
    cp -R rules/. "${dest}/release/custom-rules/"
    cp scripts/entrypoint.sh "${dest}/release/scripts/entrypoint.sh"
    cp scripts/run-regression.sh "${dest}/release/scripts/run-regression.sh"

    printf "# Native build artifacts for %s (%s)\n" "${PIPELINE_NAME:-suricata}" "${triplet}" > "${dest}/release/README.txt"
}

package_release() {
    detect_platform

    local outbase="suricata-${version}-${platform_os}-${platform_arch}"
    local artifact_root="${dest}/artifacts/${outbase}"
    local sbom_dir="${artifact_root}/SBOM"
    local dist_dir="${dest}/artifacts"
    local tarball="${dist_dir}/${outbase}.tar.gz"
    local checksum_file_path="${dist_dir}/${outbase}.sha256.txt"
    local pom_file="${artifact_root}/${outbase}.pom.json"

    rm -rf "${artifact_root}"
    mkdir -p "${artifact_root}" "${sbom_dir}"

    cp -R "${dest}/release/." "${artifact_root}/"

    generate_sboms "${artifact_root}" "${sbom_dir}/${outbase}.sbom.spdx.json" "${sbom_dir}/${outbase}.sbom.cdx.json"
    generate_pom "${pom_file}" "${outbase}" "${version}"

    (cd "${dist_dir}" && tar -czf "${tarball##*/}" "${outbase}")

    {
        checksum_file "${tarball}"
        checksum_file "${sbom_dir}/${outbase}.sbom.spdx.json"
        checksum_file "${sbom_dir}/${outbase}.sbom.cdx.json"
        checksum_file "${pom_file}"
    } > "${checksum_file_path}"
}

main() {
    prepare_release_layout
    package_release
}

main "$@"
