#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: scan.sh <rule-file|rule-name> <path-to-scan>

Provide either an absolute/relative rule file path or the name of a rule
present inside the bundled rules directory.
USAGE
}

if [[ $# -lt 2 ]]; then
    usage >&2
    exit 1
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
release_root="$(cd "${script_dir}/.." && pwd)"
rules_root="${YARA_RULES_DIR:-${release_root}/rules}"
yara_bin="${YARA_BIN:-${release_root}/bin/yara}"

if [[ ! -x "${yara_bin}" ]]; then
    if command -v yara >/dev/null 2>&1; then
        yara_bin="$(command -v yara)"
    else
        echo "Unable to find a yara binary. Set YARA_BIN to override." >&2
        exit 1
    fi
fi

resolve_rule() {
    local rule_input="$1"
    if [[ -f "${rule_input}" ]]; then
        printf '%s\n' "${rule_input}"
        return
    fi
    local bundled="${rules_root}/${rule_input}"
    if [[ -f "${bundled}" ]]; then
        printf '%s\n' "${bundled}"
        return
    fi
    echo "Rule file '${rule_input}' was not found" >&2
    exit 1
}

resolve_target() {
    local target_input="$1"
    if [[ -e "${target_input}" ]]; then
        printf '%s\n' "${target_input}"
        return
    fi
    local relative="${release_root}/${target_input}"
    if [[ -e "${relative}" ]]; then
        printf '%s\n' "${relative}"
        return
    fi
    echo "Target '${target_input}' does not exist" >&2
    exit 1
}

rule_path="$(resolve_rule "$1")"
target_path="$(resolve_target "$2")"

exec "${yara_bin}" "${rule_path}" "${target_path}"
