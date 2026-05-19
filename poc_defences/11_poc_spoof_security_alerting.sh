#!/bin/bash
# POC: Spoof Security Alerting (T1562.011)
# Triggers: spoof-security-alerting detector
# Description: Attempts to access logging sockets, log files, and alerting configuration

echo "[*] POC: Spoof Security Alerting (T1562.011)"
echo "[*] This script demonstrates security alerting spoofing/suppression detection"
echo ""

# Attempt to access system logging socket
echo "[*] Attempting to access logging socket..."
if [[ -S /dev/log ]]; then
    echo "[*] Found /dev/log logging socket"
    file /dev/log 2>/dev/null || true
else
    echo "[!] /dev/log socket not found"
fi

# Attempt to access systemd journal socket
echo "[*] Attempting to access systemd journal socket..."
if [[ -S /run/systemd/journal/socket ]]; then
    echo "[*] Found systemd journal socket"
    file /run/systemd/journal/socket 2>/dev/null || true
else
    echo "[!] systemd journal socket not found"
fi

# Attempt to access system log files
echo "[*] Attempting to access system log files..."
for log_file in /var/log/syslog /var/log/messages /var/log/secure /var/log/auth.log /var/log/kern.log; do
    if [[ -f "$log_file" ]]; then
        echo "[*] Found log file: $log_file"
        file "$log_file" 2>/dev/null || true
        wc -l "$log_file" 2>/dev/null || true
    fi
done

# Attempt to access journal logs
echo "[*] Attempting to access systemd journal logs..."
if [[ -d /var/log/journal ]]; then
    echo "[*] Found systemd journal directory"
    ls -la /var/log/journal/ 2>/dev/null | head -10 || true
fi

# Attempt to access rsyslog configuration
echo "[*] Attempting to access rsyslog configuration..."
for rsyslog_conf in /etc/rsyslog.conf /etc/rsyslog.d; do
    if [[ -e "$rsyslog_conf" ]]; then
        echo "[*] Found rsyslog configuration: $rsyslog_conf"
        ls -la "$rsyslog_conf" 2>/dev/null || true
    fi
done

echo ""
echo "[+] POC complete - detector should have fired for alerting surface access"
