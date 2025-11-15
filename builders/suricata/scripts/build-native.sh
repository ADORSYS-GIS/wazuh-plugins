#!/usr/bin/env bash
set -euo pipefail
triplet="${ARTIFACT_TRIPLET:-native}"
dest="${ARTIFACT_DEST:-$(pwd)/dist/${triplet}}"
version="${PIPELINE_VERSION:-dev}"

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
