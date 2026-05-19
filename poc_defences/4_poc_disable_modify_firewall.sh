#!/bin/bash
# POC: Disable or Modify Firewall (T1562.004)
# Triggers: disable-modify-firewall detector
# Description: Attempts to interact with firewall configuration and tools

set -e

echo "[*] POC: Disable or Modify Firewall (T1562.004)"
echo "[*] This script demonstrates firewall tampering detection"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "[!] This POC requires root privileges"
   exit 1
fi

# Attempt to list iptables rules
echo "[*] Attempting to list iptables rules..."
if command -v iptables &> /dev/null; then
    iptables -L 2>/dev/null || true
else
    echo "[!] iptables not found"
fi

# Attempt to list ip6tables rules
echo "[*] Attempting to list ip6tables rules..."
if command -v ip6tables &> /dev/null; then
    ip6tables -L 2>/dev/null || true
else
    echo "[!] ip6tables not found"
fi

# Attempt to list nftables rules
echo "[*] Attempting to list nftables rules..."
if command -v nft &> /dev/null; then
    nft list tables 2>/dev/null || true
else
    echo "[!] nft not found"
fi

# Attempt to check UFW status
echo "[*] Attempting to check UFW status..."
if command -v ufw &> /dev/null; then
    ufw status 2>/dev/null || true
else
    echo "[!] ufw not found"
fi

# Attempt to check firewalld status
echo "[*] Attempting to check firewall-cmd..."
if command -v firewall-cmd &> /dev/null; then
    firewall-cmd --list-all 2>/dev/null || true
else
    echo "[!] firewall-cmd not found"
fi

# Attempt to read firewall configuration directories
echo "[*] Attempting to read firewall configuration..."
for conf_dir in /etc/iptables /etc/ufw /etc/firewalld /etc/nftables.conf; do
    if [[ -e "$conf_dir" ]]; then
        echo "[*] Checking $conf_dir"
        ls -la "$conf_dir" 2>/dev/null || true
    fi
done

echo ""
echo "[+] POC complete - detector should have fired"
