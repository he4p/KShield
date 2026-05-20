#!/bin/bash
# POC: Indicator Blocking (T1562.006)
# Triggers: indicator-blocking detector
# Description: Attempts to access and modify hosts, DNS, and indicator configuration

echo "[*] POC: Indicator Blocking (T1562.006)"
echo "[*] This script demonstrates indicator blocking/DNS manipulation detection"
echo ""

# Attempt to access hosts file
echo "[*] Attempting to access /etc/hosts..."
if [[ -f /etc/hosts ]]; then
    echo "[*] Found /etc/hosts"
    file /etc/hosts 2>/dev/null || true
    wc -l /etc/hosts 2>/dev/null || true
else
    echo "[!] /etc/hosts not found"
fi

# Attempt to access DNS configuration
echo "[*] Attempting to access DNS configuration..."
for dns_conf in /etc/resolv.conf /etc/systemd/resolved.conf /etc/dnsmasq.conf; do
    if [[ -f "$dns_conf" ]]; then
        echo "[*] Found DNS config: $dns_conf"
        file "$dns_conf" 2>/dev/null || true
        wc -l "$dns_conf" 2>/dev/null || true
    fi
done

# Attempt to access syslog configuration
echo "[*] Attempting to access syslog configuration..."
for syslog_conf in /etc/rsyslog.conf /etc/rsyslog.d /etc/syslog-ng; do
    if [[ -e "$syslog_conf" ]]; then
        echo "[*] Found syslog config: $syslog_conf"
        ls -la "$syslog_conf" 2>/dev/null || true
    fi
done

# Demonstrate DNS query to show resolution capability
echo "[*] Checking current DNS resolution..."
if command -v nslookup &> /dev/null; then
    nslookup localhost 2>/dev/null | head -5 || true
elif command -v dig &> /dev/null; then
    dig localhost +short 2>/dev/null || true
fi

echo ""
echo "[+] POC complete - detector should have fired for indicator blocking surface access"
