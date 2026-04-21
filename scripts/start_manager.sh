#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"

mkdir -p "$ROOT_DIR/manager/data"
exec python3 "$ROOT_DIR/manager/app.py" --host 0.0.0.0 --port 8080
