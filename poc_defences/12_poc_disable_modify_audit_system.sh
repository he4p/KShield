#!/bin/bash
# POC: Disable or Modify Audit System (T1562.012)
# Triggers: disable-modify-audit-system detector
# Description: Attempts to interact with Linux audit system components

set -e

echo "[*] POC: Disable or Modify Audit System (T1562.012)"
echo "[*] This script demonstrates audit system tampering detection"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "[!] This POC requires root privileges"
   exit 1
fi

# Attempt to list audit rules (triggers execve event on /usr/sbin/auditctl)
echo "[*] Attempting to list audit rules..."
if command -v auditctl &> /dev/null; then
    auditctl -l 2>/dev/null || true
else
    echo "[!] auditctl not found - skipping this test"
fi

# Attempt to read audit configuration
echo "[*] Attempting to read audit configuration..."
if [[ -d /etc/audit ]]; then
    ls -la /etc/audit/ 2>/dev/null || true
else
    echo "[!] Audit config directory not found"
fi

# Attempt to read audit logs
echo "[*] Attempting to read audit logs..."
if [[ -d /var/log/audit ]]; then
    ls -la /var/log/audit/ 2>/dev/null || true
else
    echo "[!] Audit log directory not found"
fi

echo ""
echo "[+] POC complete - detector should have fired"
