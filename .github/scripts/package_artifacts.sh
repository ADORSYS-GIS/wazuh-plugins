#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: package_artifacts.sh <builder> <triplet>" >&2
  exit 1
fi

builder="$1"
triplet="$2"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

release_file="${repo_root}/builders/${builder}/release.txt"
version="$(< "${release_file}")"
artifact_dir="${repo_root}/builders/${builder}/dist/${triplet}"
artifacts_root="${repo_root}/artifacts"
stage_name="${builder}-${version}-${triplet}"
stage_dir="${artifacts_root}/${stage_name}"
stage_rel="artifacts/${stage_name}"
package_src="${artifact_dir}/artifacts"

rm -rf "${stage_dir}"
mkdir -p "${stage_dir}"

if [[ ! -d "${package_src}" ]]; then
  echo "Package artifacts directory not found: ${package_src}" >&2
  exit 1
fi

shopt -s nullglob
copied=0
patterns=(
  "*.tar.gz"
  "*.sha256.txt"
  "*.deb"
  "*.dmg"
)
for pattern in "${patterns[@]}"; do
  for file in "${package_src}"/${pattern}; do
    cp "${file}" "${stage_dir}/"
    copied=1
  done
done
shopt -u nullglob

if [[ "${copied}" -eq 0 ]]; then
  echo "No packaged artifacts found in ${package_src}" >&2
  exit 1
fi

manifest_file="$(mktemp)"
(
  cd "${repo_root}"
  find "${stage_rel}" -maxdepth 1 -type f | LC_ALL=C sort > "${manifest_file}"
)
{
  echo "version=${version}"
  echo "artifact_name=${stage_name}"
  echo "artifact_path=${stage_dir}"
  echo "files<<EOF"
  cat "${manifest_file}"
  echo "EOF"
} >> "${GITHUB_OUTPUT}"

rm -f "${manifest_file}"
