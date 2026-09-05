#!/usr/bin/env bash
# Confine a memory hog to a systemd transient scope with a hard MemoryMax,
# so the kernel's cgroup-aware OOM killer contains the fault to this scope
# instead of the whole machine. Needs root (systemd-run creates a system
# scope unit).
set -euo pipefail
LIMIT_MB=${LIMIT_MB:-64}
MB=${MB:-256}  # write more than LIMIT_MB so the cgroup limit actually bites
DIR=${DIR:-/dev/shm}

f=$(mktemp "$DIR/kl_systemd.XXXXXX")
trap 'rm -f "$f"' EXIT

echo "systemd: scope limited to ${LIMIT_MB}M, writing ${MB}M into $f"
systemd-run --scope --collect -p MemoryMax="${LIMIT_MB}M" -- \
    dd if=/dev/zero of="$f" bs=1M count="$MB" status=none || true
echo "systemd: scope exited (OOM-killed or write failed once the limit hit)"
