#!/usr/bin/env bash
# Simulate a network partition: blackhole TARGET with an unreachable route
# for DURATION seconds, then remove it. Needs root (ip route add/del).
set -euo pipefail
TARGET=${TARGET:-8.8.8.8}
DURATION=${DURATION:-30}

trap 'ip route del unreachable "$TARGET" 2>/dev/null' EXIT

echo "iproute2: blackholing $TARGET for ${DURATION}s"
ip route add unreachable "$TARGET"
sleep "$DURATION"
