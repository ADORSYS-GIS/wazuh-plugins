#!/bin/bash

set -eu

IFACES=$(ifconfig -l | tr ' ' '\n' | grep -i en)

args=()
for i in "${IFACES[@]}"; do
    args+=( -i "$i" )
done

echo /opt/wazuh/suricata/bin/suricata "${args[@]}" "$@"
exec /opt/wazuh/suricata/bin/suricata "${args[@]}" "$@"