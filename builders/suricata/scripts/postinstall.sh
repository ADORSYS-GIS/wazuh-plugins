#!/bin/sh
set -e

COMP_PREFIX="${"$1":-"/opt/wazuh/suricata"}"
SERVICE_NAME="suricata-wazuh.service"

# 1) Ensure group/user wazuh exist
if command -v getent >/dev/null 2>&1; then
  getent group wazuh >/dev/null 2>&1 || \
    addgroup --system wazuh 2>/dev/null || groupadd -r wazuh || true

  getent passwd wazuh >/dev/null 2>&1 || \
    adduser --system --ingroup wazuh --home "$COMP_PREFIX" --shell /usr/sbin/nologin wazuh 2>/dev/null || \
    useradd -r -g wazuh -d "$COMP_PREFIX" -s /usr/sbin/nologin wazuh || true
else
  # very minimal fallback
  groupadd -r wazuh 2>/dev/null || true
  useradd -r -g wazuh -d "$COMP_PREFIX" -s /usr/sbin/nologin wazuh 2>/dev/null || true
fi

## 2) Permissions on install tree
#chown -R wazuh:wazuh "$COMP_PREFIX" 2>/dev/null || true
#
## Make sure runtime dirs exist and are owned correctly
#mkdir -p "$COMP_PREFIX/var/log/suricata" \
#         "$COMP_PREFIX/var/run/suricata" \
#         "$COMP_PREFIX/var/lib/suricata/rules"
#
#chown -R wazuh:wazuh "$COMP_PREFIX/var"
#chmod 750 "$COMP_PREFIX/var" "$COMP_PREFIX/var/log" "$COMP_PREFIX/var/log/suricata"
#
## 3) Seed rules if none present
#if [ -d "$COMP_PREFIX/share/suricata/rules" ] && \
#   [ ! -f "$COMP_PREFIX/var/lib/suricata/rules/suricata.rules" ]; then
#  cp "$COMP_PREFIX"/share/suricata/rules/* \
#     "$COMP_PREFIX/var/lib/suricata/rules/" 2>/dev/null || true
#  chown -R wazuh:wazuh "$COMP_PREFIX/var/lib/suricata"
#fi

# 4) systemd integration (if present)
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
  systemctl enable --now "$SERVICE_NAME" || true
fi

exit 0
