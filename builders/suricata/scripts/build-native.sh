#!/usr/bin/env bash
set -euo pipefail

triplet="${ARTIFACT_TRIPLET:-native}"
dest="${ARTIFACT_DEST:-$(pwd)/dist/${triplet}}"
version="${PIPELINE_VERSION:-dev}"

syft_bin=""
platform_os=""
platform_arch=""
release_root="${dest}/release"

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

package_deb() {
    local outbase="$1"

    if [[ "${platform_os}" != "linux" ]]; then
        return 0
    fi

    if ! command -v dpkg-deb >/dev/null 2>&1; then
        echo "dpkg-deb not available; skipping .deb packaging" >&2
        return 0
    fi

    local staging="${dest}/deb-build"
    rm -rf "${staging}"
    mkdir -p "${staging}/opt/wazuh/suricata" "${staging}/DEBIAN"

    cp -R "${release_root}/." "${staging}/opt/wazuh/suricata/"

    local deb_arch="${platform_arch}"
    case "${deb_arch}" in
        amd64|arm64) ;;
        *) deb_arch="all" ;;
    esac

    local installed_size
    installed_size=$(du -ks "${staging}/opt/wazuh/suricata" | awk '{print $1}')

    cat >"${staging}/DEBIAN/control" <<EOF
Package: suricata
Version: ${version}
Architecture: ${deb_arch}
Maintainer: Wazuh Plugins <packages@wazuh.com>
Section: utils
Priority: optional
Installed-Size: ${installed_size:-0}
Description: Suricata IDS companion packaged for Wazuh deployments
EOF

    local deb_out="${dest}/artifacts/${outbase}.deb"
    dpkg-deb --build "${staging}" "${deb_out}" >/dev/null
    printf '%s\n' "${deb_out}"
}

package_dmg() {
    local outbase="$1"

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

    cp -R "${release_root}" "${staging}/suricata"

    local dmg_out="${dest}/artifacts/${outbase}.dmg"
    hdiutil create -volname "${outbase}" -srcfolder "${staging}" -format UDZO -ov "${dmg_out}" >/dev/null
    printf '%s\n' "${dmg_out}"
}

prepare_release_layout() {
    rm -rf "${dest}"
    mkdir -p "${release_root}/bin" "${release_root}/rules" "${release_root}/custom-rules" "${release_root}/scripts"

    cat >"${release_root}/bin/suricata" <<'SCRIPT'
#!/usr/bin/env bash
echo "Suricata placeholder binary"
SCRIPT
    chmod +x "${release_root}/bin/suricata"

    cat >"${release_root}/BUILDINFO.txt" <<EOF_INFO
# Suricata native build
VERSION=${version}
TRIPLET=${triplet}
EOF_INFO

    cp rules/sample.rules "${release_root}/rules/sample.rules"
    cp -R rules/. "${release_root}/custom-rules/"
    cp scripts/entrypoint.sh "${release_root}/scripts/entrypoint.sh"
    cp scripts/run-regression.sh "${release_root}/scripts/run-regression.sh"

    printf "# Native build artifacts for %s (%s)\n" "${PIPELINE_NAME:-suricata}" "${triplet}" > "${release_root}/README.txt"
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

    cp -R "${release_root}/." "${artifact_root}/"

    generate_sboms "${artifact_root}" "${sbom_dir}/${outbase}.sbom.spdx.json" "${sbom_dir}/${outbase}.sbom.cdx.json"
    generate_pom "${pom_file}" "${outbase}" "${version}"

    (cd "${dist_dir}" && tar -czf "${tarball##*/}" "${outbase}")

    local deb_pkg dmg_pkg
    deb_pkg=$(package_deb "${outbase}" || true)
    dmg_pkg=$(package_dmg "${outbase}" || true)

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

main() {
    prepare_release_layout
    package_release
}

main "$@"
