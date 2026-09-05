#!/usr/bin/env bash
# Build if needed, then run.
set -euo pipefail
cd "$(dirname "$0")"

[ -x build/kernellens ] || ./install.sh
exec ./build/kernellens
