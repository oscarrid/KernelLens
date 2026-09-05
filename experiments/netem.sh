#!/usr/bin/env bash
# Inject DELAY latency and LOSS packet loss on IFACE for DURATION seconds via
# a netem qdisc, then remove it. Needs root (tc qdisc add/del).
set -euo pipefail
IFACE=${IFACE:-lo}
DELAY=${DELAY:-200ms}
LOSS=${LOSS:-5%}
DURATION=${DURATION:-30}

trap 'tc qdisc del dev "$IFACE" root 2>/dev/null' EXIT

echo "netem: $IFACE +${DELAY} delay, ${LOSS} loss for ${DURATION}s"
tc qdisc add dev "$IFACE" root netem delay "$DELAY" loss "$LOSS"
sleep "$DURATION"
