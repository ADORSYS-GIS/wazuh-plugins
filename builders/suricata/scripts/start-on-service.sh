#!/bin/bash

set -ex

IFS=$'\n'
IFACES=($(ls /sys/class/net | grep -i en))

ARGS=""
for i in "${IFACES[@]}"; do
    ARGS="$ARGS -i $i"
done

exec /opt/wazuh/suricata/bin/suricata \
    $ARGS \
    "$@"
