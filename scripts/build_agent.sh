#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"

bash "$ROOT_DIR/agent/build_bpf.sh"
cargo build --release --manifest-path "$ROOT_DIR/agent/Cargo.toml"
