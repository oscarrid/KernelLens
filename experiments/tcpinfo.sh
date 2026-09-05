#!/usr/bin/env bash
# Stall a local TCP receiver mid-connection (SIGSTOP) so its receive window
# collapses, then poll the kernel's TCP_INFO for both ends (via `ss -i`, the
# same getsockopt(TCP_INFO) data `ss` always reads) for DURATION seconds.
# Needs nc.
set -euo pipefail
PORT=${PORT:-5201}
DURATION=${DURATION:-30}
send_pid=""

nc -l "$PORT" >/dev/null &
recv_pid=$!
trap 'kill -CONT "$recv_pid" 2>/dev/null; kill "$recv_pid" $send_pid 2>/dev/null || true' EXIT
sleep 0.2

yes | nc localhost "$PORT" >/dev/null &
send_pid=$!
sleep 0.2

kill -STOP "$recv_pid"  # stop reading: its receive buffer fills, window -> 0
echo "tcpinfo: receiver on :$PORT stalled, watching TCP_INFO for ${DURATION}s"

end=$((SECONDS + DURATION))
while ((SECONDS < end)); do
    ss -tin state established "( sport = :$PORT or dport = :$PORT )"
    sleep 2
done
