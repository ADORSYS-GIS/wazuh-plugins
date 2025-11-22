#!/bin/sh
set -e

COMP_PREFIX="${"$1":-"/opt/wazuh/yara"}"

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

exit 0