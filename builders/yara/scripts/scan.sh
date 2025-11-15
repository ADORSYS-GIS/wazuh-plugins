#!/usr/bin/env bash
set -euo pipefail
echo "[yara] Pretending to scan $1 with YARA ${YARA_VERSION:-unknown}"
ls -1 /opt/yara/rules
