#!/bin/bash
# Ataree Bootstrap Launcher
# This script concurrently launches the Manager, Docs, and native eBPF agent.

set -e

cd "$(dirname "$0")"

echo "[+] Starting Ataree Manager..."
pushd manager > /dev/null
python3 app.py &
MANAGER_PID=$!
popd > /dev/null

echo "[+] Starting MkDocs Documentation Server..."
if command -v mkdocs &> /dev/null; then
    mkdocs serve -a 127.0.0.1:8000 &
    DOCS_PID=$!
else
    echo "[-] mkdocs not found. Skipping docs server."
    DOCS_PID=""
fi

echo "[+] Building Ataree Agent..."
bash scripts/build_agent.sh

echo "[+] Starting Ataree Agent (requires sudo)..."
sudo ./agent/target/debug/kshield-agent --manager-url http://127.0.0.1:8080 &
AGENT_PID=$!

echo "=========================================================="
echo "[+] All components launched successfully!"
echo " - Dashboard: http://127.0.0.1:8080 (Creds: admin:secret)"
if [ -n "$DOCS_PID" ]; then
    echo " - Docs API:  http://127.0.0.1:8000"
fi
echo " - Agent PID: $AGENT_PID"
echo "=========================================================="
echo "Press Ctrl+C to stop all services."

# Trap SIGINT and SIGTERM to kill all background jobs cleanly
cleanup() {
    echo -e "\n[*] Shutting down..."
    sudo kill $AGENT_PID 2>/dev/null || true
    kill $MANAGER_PID 2>/dev/null || true
    if [ -n "$DOCS_PID" ]; then
        kill $DOCS_PID 2>/dev/null || true
    fi
    exit 0
}

trap cleanup SIGINT SIGTERM
wait
