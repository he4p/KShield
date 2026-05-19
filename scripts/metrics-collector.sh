#!/usr/bin/env bash
# kshield-metrics-collector
# Posts agent CPU/RAM metrics to manager periodically.
# Usage: ./metrics-collector.sh <agent-id> <manager-url> [interval-secs]

set -euo pipefail

AGENT_ID="${1:?agent_id required}"
MANAGER_URL="${2:?manager_url required}"
INTERVAL="${3:-10}"

AGENT_URL="${MANAGER_URL}/api/v1/agent-metrics"

CLK_TCK=$(getconf CLK_TCK 2>/dev/null || echo 100)
PAGE_SIZE=$(getconf PAGE_SIZE 2>/dev/null || echo 4096)

prev_utime=0
prev_stime=0
prev_time=0

collect_and_post() {
    local pid
    pid=$(pgrep -f "kshield-agent" | head -1)
    if [[ -z "$pid" ]]; then
        return
    fi

    # Read /proc/[pid]/stat
    local stat
    stat=$(cat "/proc/$pid/stat" 2>/dev/null) || return

    # Parse fields (space-delimited, comm may contain spaces in parens)
    local after_paren="${stat#*)}"
    after_paren="${after_paren# }"   # trim leading space
    # Field mapping (original /proc/pid/stat with pid+comm stripped, leading space trimmed):
    #  1=state 2=ppid ... 12=utime 13=stime ... 20=starttime ... 22=rss
    read -r \
        _ _ _ _ _ _ _ _ _ _ _ \
        utime stime \
        _ _ _ _ _ _ _ \
        starttime \
        _ \
        rss \
        _ \
    <<< "$after_paren"

    utime=${utime:-0}
    stime=${stime:-0}
    starttime=${starttime:-0}
    rss=${rss:-0}

    # CPU percent
    local now
    now=$(awk '{print int($1 * 100)}' /proc/uptime 2>/dev/null || echo 0)
    local cpu_percent=0
    if [[ $prev_time -gt 0 ]] && [[ $now -gt $prev_time ]]; then
        local delta_proc=$(( (utime + stime) - (prev_utime + prev_stime) ))
        local delta_time=$(( now - prev_time ))
        cpu_percent=$(awk "BEGIN { printf \"%.2f\", ($delta_proc * 100) / ($CLK_TCK * $delta_time) }")
    fi

    # RSS in MB
    local rss_mb
    rss_mb=$(awk "BEGIN { printf \"%.2f\", ($rss * $PAGE_SIZE) / 1048576 }")

    # Uptime from /proc/uptime
    local uptime_secs
    uptime_secs=$(awk '{print int($1)}' /proc/uptime 2>/dev/null || echo 0)

    # Post
    curl -s -X POST "$AGENT_URL" \
        -H "Content-Type: application/json" \
        -d "{\"agent_id\":\"$AGENT_ID\",\"cpu_percent\":$cpu_percent,\"rss_mb\":$rss_mb,\"uptime_secs\":$uptime_secs,\"pid\":$pid}" \
        -o /dev/null 2>/dev/null || true

    prev_utime=$utime
    prev_stime=$stime
    prev_time=$now
}

# Main loop
echo "kshield-metrics-collector started (agent=$AGENT_ID, interval=${INTERVAL}s)"

# First collection (no delta yet)
collect_and_post

while true; do
    sleep "$INTERVAL"
    collect_and_post
done
