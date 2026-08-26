#!/bin/sh
# run one experiment across 2-3 nodes: start the agent everywhere, inject a
# fault on one node, collect everything into a single run directory, report.
#
#   ./run.sh --nodes web1,web2,db1 --target db1 --fault net --duration 45
#
# each node needs kernellens-agent installed and the kernellens-agent@.service
# unit in place; the target also needs inject.sh. ssh must work without a
# prompt and the remote user must reach root via sudo.
set -eu

NODES=""
TARGET=""
FAULT=none
DURATION=45
OUT=""
SSH="ssh -o BatchMode=yes"
EXTRA=""

while [ $# -gt 0 ]; do
  case "$1" in
    --nodes) NODES=$2; shift 2 ;;
    --target) TARGET=$2; shift 2 ;;
    --fault) FAULT=$2; shift 2 ;;
    --duration) DURATION=$2; shift 2 ;;
    --out) OUT=$2; shift 2 ;;
    --) shift; EXTRA="$*"; break ;;
    *) echo "usage: $0 --nodes a,b,c --target a --fault <cpu|mem|disk|fs|net|none> [-- extra inject.sh args]"; exit 2 ;;
  esac
done
[ -n "$NODES" ] || { echo "--nodes is required"; exit 2; }
NODE_LIST=$(echo "$NODES" | tr ',' ' ')
[ -n "$TARGET" ] || TARGET=$(echo "$NODE_LIST" | awk '{print $1}')

RUNID="${FAULT}-$(date +%Y%m%d-%H%M%S)"
[ -n "$OUT" ] || OUT="./runs/$RUNID"
mkdir -p "$OUT"
REMOTE_DIAG="/var/log/kernellens/$RUNID-diag"

on() { node=$1; shift; $SSH "$node" "sudo sh -c '$*'"; }

stop_all() {
  for n in $NODE_LIST; do
    on "$n" "systemctl stop kernellens-agent@$RUNID.service" >/dev/null 2>&1 || true
  done
}
trap stop_all EXIT INT TERM

echo "== starting agents on: $NODE_LIST"
for n in $NODE_LIST; do
  on "$n" "systemctl start kernellens-agent@$RUNID.service"
done

echo "== injecting $FAULT on $TARGET"
on "$TARGET" "mkdir -p $REMOTE_DIAG"
$SSH "$TARGET" "sudo inject.sh --fault $FAULT --node $TARGET --duration $DURATION \
  --run-dir $REMOTE_DIAG $EXTRA"

echo "== stopping agents"
stop_all
trap - EXIT INT TERM

echo "== collecting into $OUT"
for n in $NODE_LIST; do
  on "$n" "chmod a+r /var/log/kernellens/$RUNID.jsonl" >/dev/null 2>&1 || true
  scp -q "$n:/var/log/kernellens/$RUNID.jsonl" "$OUT/$n.jsonl" || \
    echo "   warning: no samples from $n"
done
on "$TARGET" "chmod -R a+r $REMOTE_DIAG" >/dev/null 2>&1 || true
mkdir -p "$OUT/diag-$TARGET"
scp -q -r "$TARGET:$REMOTE_DIAG/." "$OUT/diag-$TARGET/" || echo "   warning: no diagnostics"
# the report only scans *.jsonl at the top level, so the markers move up a level.
if [ -f "$OUT/diag-$TARGET/marks.jsonl" ]; then
  cp "$OUT/diag-$TARGET/marks.jsonl" "$OUT/marks.jsonl"
else
  echo "   warning: no fault markers; the report will split the run at one third"
fi

echo "== report"
kernellens-report "$OUT" -o "$OUT/report.md"
echo "$OUT/report.md"
