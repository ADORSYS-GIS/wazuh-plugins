#!/bin/bash

set -ex

IFACES=$(ifconfig -l | tr ' ' '\n' | grep -i en)

args=()
for i in "${IFACES[@]}"; do
    args+=( -i "$i" )
done

exec /opt/wazuh/suricata/bin/suricata "${args[@]}" "$@"