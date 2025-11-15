#!/usr/bin/env bash
set -euo pipefail
triplet="${ARTIFACT_TRIPLET:-native}"
dest="${ARTIFACT_DEST:-$(pwd)/dist/${triplet}}"
version="${PIPELINE_VERSION:-dev}"

rm -rf "${dest}"
mkdir -p "${dest}/release/bin" "${dest}/release/rules" "${dest}/release/scripts"

cat >"${dest}/release/bin/yara" <<'SCRIPT'
#!/usr/bin/env bash
echo "YARA placeholder binary"
SCRIPT
chmod +x "${dest}/release/bin/yara"

cat >"${dest}/release/BUILDINFO.txt" <<EOF_INFO
# YARA native build
VERSION=${version}
TRIPLET=${triplet}
EOF_INFO

cp -R rules/. "${dest}/release/rules/"
cp scripts/scan.sh "${dest}/release/scripts/scan.sh"
cp scripts/scan-fixtures.sh "${dest}/release/scripts/scan-fixtures.sh"

printf "# Native build artifacts for %s (%s)\n" "${PIPELINE_NAME:-yara}" "${triplet}" > "${dest}/release/README.txt"
