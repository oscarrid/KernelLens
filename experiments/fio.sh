#!/usr/bin/env bash
# Sustained random-write I/O under DIR for DURATION seconds via fio, then
# clean up. Needs fio installed.
set -euo pipefail
DIR=${DIR:-.}
DURATION=${DURATION:-30}
BS=${BS:-4k}
IODEPTH=${IODEPTH:-16}

f=$(mktemp "$DIR/kl_fio.XXXXXX")
trap 'rm -f "$f"' EXIT

echo "fio: random ${BS} writes, iodepth ${IODEPTH}, to $f for ${DURATION}s"
fio --name=kl_fio --filename="$f" --rw=randwrite --bs="$BS" \
    --iodepth="$IODEPTH" --ioengine=libaio --direct=1 --size=256M \
    --runtime="$DURATION" --time_based --output-format=normal >/dev/null
