#!/usr/bin/env bash
# Configure and build KernelLens into ./build.
set -euo pipefail
cd "$(dirname "$0")"

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"

echo "built: $(pwd)/build/kernellens"
