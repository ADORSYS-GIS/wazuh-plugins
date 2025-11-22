#!/bin/bash

set -ex

IFACES=($(ls /sys/class/net | grep -i en))

args=()
for i in "${IFACES[@]}"; do
    args+=( -i "$i" )
done

exec /opt/wazuh/suricata/bin/suricata "${args[@]}" "$@"