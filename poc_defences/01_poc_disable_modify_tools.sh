#!/bin/bash
# POC: Disable or Modify Security Tools (T1562.001)
# Triggers: disable-modify-tools detector
# Description: Attempts to interact with security and monitoring tools

set -e

echo "[*] POC: Disable or Modify Security Tools (T1562.001)"
echo "[*] This script demonstrates security tool tampering detection"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "[!] This POC requires root privileges"
   exit 1
fi

# Attempt to interact with audit tools
echo "[*] Attempting to interact with audit tools..."
if command -v auditctl &> /dev/null; then
    auditctl -l 2>/dev/null || true
fi

if command -v ausearch &> /dev/null; then
    ausearch --help 2>/dev/null || true
fi

if command -v aureport &> /dev/null; then
    aureport --help 2>/dev/null || true
fi

# Attempt to interact with firewall tools
echo "[*] Attempting to interact with firewall tools..."
if command -v iptables &> /dev/null; then
    iptables -L 2>/dev/null || true
fi

if command -v nft &> /dev/null; then
    nft list tables 2>/dev/null || true
fi

if command -v sysctl &> /dev/null; then
    sysctl -a 2>/dev/null | head -5 || true
fi

# Attempt to read security tool configuration
echo "[*] Attempting to read security tool configurations..."
for tool_path in /etc/audit /etc/iptables /etc/ufw /etc/firewalld /etc/sysctl.conf /etc/sysctl.d; do
    if [[ -e "$tool_path" ]]; then
        echo "[*] Accessing $tool_path"
        ls -la "$tool_path" 2>/dev/null || true
    fi
done

echo ""
echo "[+] POC complete - detector should have fired"
