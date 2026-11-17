#!/bin/sh
set -e

COMP_PREFIX=${1:-/opt/wazuh/yara}

# Find a suitable nologin shell
if command -v nologin >/dev/null 2>&1; then
  NOLOGIN_SHELL="$(command -v nologin)"
elif [ -x /usr/sbin/nologin ]; then
  NOLOGIN_SHELL=/usr/sbin/nologin
elif [ -x /sbin/nologin ]; then
  NOLOGIN_SHELL=/sbin/nologin
else
  # Last resort
  NOLOGIN_SHELL=/bin/false
fi

# 1) Ensure group wazuh exists
if ! getent group wazuh >/dev/null 2>&1; then
  if command -v addgroup >/dev/null 2>&1; then
    # Debian/Ubuntu style
    if ! addgroup --system wazuh 2>/dev/null; then
      groupadd -r wazuh 2>/dev/null || :
    fi
  else
    # RHEL/CentOS style
    groupadd -r wazuh 2>/dev/null || :
  fi
fi

# 2) Ensure user wazuh exists
if ! getent passwd wazuh >/dev/null 2>&1; then
  if command -v adduser >/dev/null 2>&1; then
    # Debian/Ubuntu style
    if ! adduser --system \
        --ingroup wazuh \
        --home "$COMP_PREFIX" \
        --shell "$NOLOGIN_SHELL" \
        wazuh 2>/dev/null; then
      useradd -r -g wazuh -d "$COMP_PREFIX" -s "$NOLOGIN_SHELL" wazuh 2>/dev/null || :
    fi
  else
    # RHEL/CentOS style
    useradd -r -g wazuh -d "$COMP_PREFIX" -s "$NOLOGIN_SHELL" wazuh 2>/dev/null || :
  fi
fi

# 3) Change owner
chown -R wazuh:wazuh $COMP_PREFIX >/dev/null 2>&1 || true

exit 0