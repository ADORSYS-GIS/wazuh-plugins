#!/bin/bash
set -eu

args=()
for iface in /sys/class/net/*/; do
    name=$(basename "$iface")

    # Skip loopback
    [[ "$name" == "lo" ]] && continue

    # Resolve the symlink and skip anything under devices/virtual/
    real=$(readlink -f "$iface")
    [[ "$real" == */devices/virtual/* ]] && continue

    args+=( -i "$name" )
done

echo /opt/wazuh/suricata/bin/suricata "${args[@]}" "$@"
exec /opt/wazuh/suricata/bin/suricata "${args[@]}" "$@"