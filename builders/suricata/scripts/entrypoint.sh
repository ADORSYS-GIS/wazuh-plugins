#!/bin/sh
set -euo pipefail
echo "[suricata] Pretending to start Suricata ${SURICATA_VERSION:-unknown}"
echo "Custom rules mounted at /opt/suricata/custom-rules"
exec /bin/sh "$@"
