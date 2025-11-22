#!/bin/bash

set -ex

IFACES=$(ifconfig -l | tr ' ' '\n' | grep -i en)

ARGS=""
for i in $IFACES; do
    ARGS="$ARGS -i $i"
done

exec /opt/wazuh/suricata/bin/suricata \
    $ARGS \
    "$@"
