#!/bin/bash

set -eu

IFACES=($(ls /sys/class/net | grep -v lo))

args=()
for i in "${IFACES[@]}"; do
    args+=( -i "$i" )
done

echo /opt/wazuh/suricata/bin/suricata "${args[@]}" "$@"
exec /opt/wazuh/suricata/bin/suricata "${args[@]}" "$@"