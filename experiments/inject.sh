#!/bin/sh
# inject one controlled fault on this node and capture low-level diagnostics around it
set -eu

FAULT=none
RUN=""
NODE="$(hostname)"
BASELINE=20
DURATION=45
RECOVERY=25
IFACE=""
DELAY=120
LOSS=5
WORKDIR=/var/tmp
MEM_MAX_MB=512
PERF_RECORD=0

while [ $# -gt 0 ]; do
  case "$1" in
    --fault) FAULT=$2; shift 2 ;;
    --run-dir) RUN=$2; shift 2 ;;
    --node) NODE=$2; shift 2 ;;
    --baseline) BASELINE=$2; shift 2 ;;
    --duration) DURATION=$2; shift 2 ;;
    --recovery) RECOVERY=$2; shift 2 ;;
    --iface) IFACE=$2; shift 2 ;;
    --delay) DELAY=$2; shift 2 ;;
    --loss) LOSS=$2; shift 2 ;;
    --dir) WORKDIR=$2; shift 2 ;;
    --mem-max-mb) MEM_MAX_MB=$2; shift 2 ;;
    --perf-record) PERF_RECORD=1; shift ;;
    *) echo "usage: $0 --fault <cpu|mem|disk|fs|net|none> [--run-dir DIR] [--baseline S]"; exit 2 ;;
  esac
done

[ "$(id -u)" = 0 ] || { echo "inject.sh must run as root"; exit 1; }
[ -n "$RUN" ] || RUN="./runs/${FAULT}-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$RUN"
RUN=$(cd "$RUN" && pwd)

have() { command -v "$1" >/dev/null 2>&1; }
TRACEFS=""
for d in /sys/kernel/tracing /sys/kernel/debug/tracing; do
  if [ -w "$d/tracing_on" ]; then TRACEFS=$d; break; fi
done

# nanoseconds since the epoch, with a fallback for date(1) without %N.
now_ns() {
  n=$(date +%s%N 2>/dev/null) || n=""
  case "$n" in *[!0-9]*|"") n="$(date +%s)000000000" ;; esac
  echo "$n"
}

mark() {
  printf '{"t":%s,"node":"%s","kind":"mark","phase":"%s","fault":"%s","target":"%s"}\n' \
    "$(now_ns)" "$NODE" "$1" "$FAULT" "$NODE" >> "$RUN/marks.jsonl"
}

snapshot() { # snapshot <tag>
  {
    echo "=== $1 $(date -Is 2>/dev/null || date) ==="
    for f in /proc/pressure/cpu /proc/pressure/io /proc/pressure/memory; do
      if [ -r "$f" ]; then echo "--- $f"; cat "$f"; fi
    done
    echo "--- /proc/meminfo (head)"; head -12 /proc/meminfo
    echo "--- vmstat"; grep -E 'pgmajfault|pgscan_direct|oom_kill|nr_dirty' /proc/vmstat || true
    if have ss; then echo "--- ss -ti (established)"; ss -tin state established | head -40; fi
    if have tc && [ -n "$IFACE" ]; then echo "--- tc -s qdisc"; tc -s qdisc show dev "$IFACE"; fi
    echo "--- dmesg tail"; dmesg 2>/dev/null | tail -20 || true
  } >> "$RUN/snapshots.txt" 2>&1
}

TRACE_EVENTS=""
trace_start() {
  [ -n "$TRACEFS" ] || return 0
  echo 0 > "$TRACEFS/tracing_on"
  : > "$TRACEFS/trace"
  echo 8192 > "$TRACEFS/buffer_size_kb" 2>/dev/null || true
  echo global > "$TRACEFS/trace_clock" 2>/dev/null || true
  for e in $TRACE_EVENTS; do echo 1 > "$TRACEFS/events/$e/enable" 2>/dev/null || true; done
  echo 1 > "$TRACEFS/tracing_on"
}
trace_stop() {
  [ -n "$TRACEFS" ] || return 0
  echo 0 > "$TRACEFS/tracing_on"
  cat "$TRACEFS/trace" > "$RUN/ftrace.txt" 2>/dev/null || true
  for e in $TRACE_EVENTS; do echo 0 > "$TRACEFS/events/$e/enable" 2>/dev/null || true; done
  : > "$TRACEFS/trace"
}

MNT=""
cleanup() {
  set +e
  systemctl stop kl-cpu.service kl-mem.service >/dev/null 2>&1
  rm -f /dev/shm/kl-mem
  [ -n "$IFACE" ] && tc qdisc del dev "$IFACE" root >/dev/null 2>&1
  [ -n "$MNT" ] && { umount "$MNT" >/dev/null 2>&1; rmdir "$MNT" >/dev/null 2>&1; }
  rm -f "$RUN/kl-fs.img"
}
trap cleanup EXIT INT TERM

fio_engine() {
  if have fio && fio --enghelp 2>/dev/null | grep -qw libaio; then echo libaio; else echo psync; fi
}

apply_fault() {
  case "$FAULT" in
    cpu)
      N=$(getconf _NPROCESSORS_ONLN)
      systemd-run --unit=kl-cpu --collect --quiet --property=CPUWeight=10000 \
        /bin/sh -c "i=0; while [ \$i -lt $N ]; do (while :; do :; done) & i=\$((i+1)); done; wait"
      ;;
    mem)
      # a cgroup with no swap headroom: the writer forces reclaim, then a cgroup oom.
      systemd-run --unit=kl-mem --collect --quiet \
        --property=MemoryMax=${MEM_MAX_MB}M --property=MemorySwapMax=0 \
        "$(command -v dd)" if=/dev/zero of=/dev/shm/kl-mem bs=1M count=$((MEM_MAX_MB * 2))
      ;;
    disk)
      have fio || { echo "fio not installed"; return 1; }
      fio --name=kl-disk --directory="$WORKDIR" --rw=randwrite --bs=4k --numjobs=4 \
          --size=256M --iodepth=32 --ioengine="$(fio_engine)" --direct=1 --time_based \
          --runtime="$DURATION" --group_reporting --output="$RUN/fio-disk.txt" &
      ;;
    fs)
      have fio || { echo "fio not installed"; return 1; }
      MNT=$(mktemp -d)
      if have mkfs.ext4 && truncate -s 128M "$RUN/kl-fs.img" 2>/dev/null &&
         mkfs.ext4 -q -F "$RUN/kl-fs.img" >/dev/null 2>&1 &&
         mount -o loop "$RUN/kl-fs.img" "$MNT" 2>/dev/null; then
        echo "fs fault on loop-backed ext4 at $MNT" >> "$RUN/snapshots.txt"
      else
        rm -f "$RUN/kl-fs.img"
        mount -t tmpfs -o size=64M kl-fs "$MNT"
        echo "fs fault on tmpfs at $MNT (no usable mkfs)" >> "$RUN/snapshots.txt"
      fi
      # write past the end of the filesystem and keep going, so ENOSPC is observed
      # rather than merely hit once.
      fio --name=kl-fsfill --directory="$MNT" --rw=write --bs=1M --size=512M \
          --ioengine=psync --fallocate=none --continue_on_error=all --time_based \
          --runtime="$DURATION" --output="$RUN/fio-fs.txt" &
      ;;
    net)
      have tc || { echo "iproute2 tc not installed"; return 1; }
      tc qdisc replace dev "$IFACE" root netem delay "${DELAY}ms" "$((DELAY / 4))ms" \
         distribution normal loss "${LOSS}%"
      # safety net: undo the qdisc even if this script is killed outright.
      (sleep $((DURATION + 30)); tc qdisc del dev "$IFACE" root >/dev/null 2>&1) &
      ;;
    none) ;;
    *) echo "unknown fault: $FAULT"; return 1 ;;
  esac
}

revert_fault() {
  case "$FAULT" in
    cpu)  systemctl stop kl-cpu.service >/dev/null 2>&1 || true ;;
    mem)  systemctl stop kl-mem.service >/dev/null 2>&1 || true; rm -f /dev/shm/kl-mem ;;
    disk) wait 2>/dev/null || true; rm -f "$WORKDIR"/kl-disk.* ;;
    fs)   wait 2>/dev/null || true; umount "$MNT" 2>/dev/null || true; rmdir "$MNT" 2>/dev/null || true
          rm -f "$RUN/kl-fs.img"; MNT="" ;;
    net)  tc qdisc del dev "$IFACE" root >/dev/null 2>&1 || true ;;
  esac
}

case "$FAULT" in
  cpu)  TRACE_EVENTS="sched/sched_process_exec sched/sched_process_exit" ;;
  mem)  TRACE_EVENTS="vmscan/mm_vmscan_direct_reclaim_begin vmscan/mm_vmscan_direct_reclaim_end oom/mark_victim" ;;
  disk) TRACE_EVENTS="block/block_rq_issue block/block_rq_complete" ;;
  fs)   TRACE_EVENTS="writeback/writeback_start writeback/writeback_written" ;;
  net)  TRACE_EVENTS="tcp/tcp_retransmit_skb sock/inet_sock_set_state" ;;
esac
if [ "$FAULT" = net ] && [ -z "$IFACE" ]; then
  IFACE=$(ip -o route show default 2>/dev/null | awk '{print $5; exit}')
  [ -n "$IFACE" ] || { echo "no default route; pass --iface"; exit 1; }
fi

echo "kernellens: fault=$FAULT node=$NODE run=$RUN" >&2
snapshot before
sleep "$BASELINE"

mark start
trace_start
if have perf; then
  perf stat -a -e cycles,instructions,context-switches,cpu-migrations,page-faults \
    -o "$RUN/perf-stat.txt" -- sleep "$DURATION" >/dev/null 2>&1 &
  if [ "$PERF_RECORD" = 1 ]; then
    perf record -a -F 99 -g -o "$RUN/perf.data" -- sleep "$DURATION" >/dev/null 2>&1 &
  fi
fi
apply_fault || true
snapshot fault-start

HALF=$((DURATION / 2))
if [ "$HALF" -gt 0 ]; then sleep "$HALF"; snapshot fault-mid; fi
sleep $((DURATION - HALF))

revert_fault
trace_stop
mark stop
snapshot fault-end

sleep "$RECOVERY"
snapshot after
echo "kernellens: diagnostics in $RUN" >&2
