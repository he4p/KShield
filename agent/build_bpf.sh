#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SRC="$SCRIPT_DIR/bpf/kshield.bpf.c"
OUT="$SCRIPT_DIR/bpf/kshield.bpf.o"

clang \
  -O2 -g -Wall -Werror \
  -target bpf \
  -D__TARGET_ARCH_x86 \
  -I/usr/include \
  -c "$SRC" \
  -o "$OUT"

echo "built $OUT"
