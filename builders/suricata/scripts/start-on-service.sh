#!/bin/bash

set -ex

IFACES=($(ls /sys/class/net | grep -v lo))

args=()
for i in "${IFACES[@]}"; do
    args+=( -i "$i" )
done

exec /opt/wazuh/suricata/bin/suricata "${args[@]}" "$@"