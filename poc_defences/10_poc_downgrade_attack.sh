#!/bin/bash
# POC: Downgrade Attack (T1562.010)
# Triggers: downgrade-attack detector
# Description: Attempts package manager and crypto configuration access

set -e

echo "[*] POC: Downgrade Attack (T1562.010)"
echo "[*] This script demonstrates package downgrade and crypto tampering detection"
echo ""

# Detect package manager
if command -v apt-get &> /dev/null; then
    echo "[*] Detected apt-based system"
    echo "[*] Querying apt-get..."
    apt-get --version 2>/dev/null || true
elif command -v dnf &> /dev/null; then
    echo "[*] Detected dnf-based system"
    echo "[*] Querying dnf..."
    dnf --version 2>/dev/null || true
elif command -v yum &> /dev/null; then
    echo "[*] Detected yum-based system"
    echo "[*] Querying yum..."
    yum --version 2>/dev/null || true
elif command -v rpm &> /dev/null; then
    echo "[*] Detected rpm-based system"
    echo "[*] Querying rpm..."
    rpm --version 2>/dev/null || true
fi

# Attempt to access package manager files
echo "[*] Attempting to read package manager files..."
if command -v dpkg &> /dev/null; then
    dpkg --version 2>/dev/null || true
fi

# Attempt to read SSL/TLS configuration
echo "[*] Attempting to read SSL/TLS configuration..."
for ssl_path in /etc/ssl /etc/openssl; do
    if [[ -d "$ssl_path" ]]; then
        echo "[*] Accessing $ssl_path"
        ls -la "$ssl_path" 2>/dev/null | head -10 || true
    fi
done

# Attempt to read SSH configuration
echo "[*] Attempting to read SSH configuration..."
for ssh_conf in /etc/ssh/sshd_config /etc/ssh/ssh_config; do
    if [[ -f "$ssh_conf" ]]; then
        echo "[*] Accessing $ssh_conf"
        file "$ssh_conf" 2>/dev/null || true
    fi
done

# Attempt to read systemd default crypto policies
echo "[*] Attempting to read crypto policy configuration..."
for policy_path in /etc/crypto-policies /etc/ssh/ssh_config.d; do
    if [[ -e "$policy_path" ]]; then
        echo "[*] Accessing $policy_path"
        ls -la "$policy_path" 2>/dev/null || true
    fi
done

echo ""
echo "[+] POC complete - detector should have fired"
