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

rm -rf "${stage_dir}"
mkdir -p "${stage_dir}"
rsync -a "${artifact_dir}/" "${stage_dir}/"

manifest_file="$(mktemp)"
python "${repo_root}/.github/scripts/list_artifacts.py" "${stage_dir}" "${builder}" "${version}" "${triplet}" > "${manifest_file}"

{
  echo "version=${version}"
  echo "artifact_name=${stage_name}"
  echo "artifact_path=${stage_dir}"
  echo "files<<EOF"
  cat "${manifest_file}"
  echo "EOF"
} >> "${GITHUB_OUTPUT}"

rm -f "${manifest_file}"
