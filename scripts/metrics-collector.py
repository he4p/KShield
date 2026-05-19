#!/usr/bin/env python3
"""KShield metrics collector - posts CPU/RSS/uptime to manager."""

import os, sys, time, json, urllib.request

AGENT_ID = sys.argv[1]
MANAGER_URL = sys.argv[2].rstrip("/")
INTERVAL = int(sys.argv[3]) if len(sys.argv) > 3 else 10

URL = f"{MANAGER_URL}/api/v1/agent-metrics"
CLK_TCK = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
PAGE_SIZE = os.sysconf(os.sysconf_names["SC_PAGE_SIZE"])

prev_utime = 0
prev_stime = 0
prev_time = 0

def collect():
    global prev_utime, prev_stime, prev_time

    for line in os.popen("pgrep -f kshield-agent"):
        pid = int(line.strip())
        break
    else:
        return

    with open(f"/proc/{pid}/stat") as f:
        fields = f.read().split()
        # field 1=pid, 2=comm, 14=utime, 15=stime, 22=starttime, 24=rss
        after_comm = fields[2:]  # skip pid + comm
        utime = int(after_comm[11])   # field 14-2 = 12th after comm = index 11
        stime = int(after_comm[12])   # field 15-2 = 13th
        rss = int(after_comm[21])     # field 24-2 = 22nd = index 21

    cpu_pct = 0.0
    now = int(time.monotonic() * 100)
    if prev_time > 0 and now > prev_time:
        delta_proc = (utime + stime) - (prev_utime + prev_stime)
        delta_time = now - prev_time
        cpu_pct = round((delta_proc * 100) / (CLK_TCK * delta_time / 100), 2)  # in units of 0.01s

    rss_mb = round((rss * PAGE_SIZE) / 1048576, 1)

    with open("/proc/uptime") as f:
        uptime = int(float(f.read().split()[0]))

    data = json.dumps({
        "agent_id": AGENT_ID,
        "cpu_percent": cpu_pct,
        "rss_mb": rss_mb,
        "uptime_secs": uptime,
        "pid": pid,
    }).encode()

    req = urllib.request.Request(URL, data=data, headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass

    prev_utime = utime
    prev_stime = stime
    prev_time = now


print(f"kshield-metrics-collector started (agent={AGENT_ID}, interval={INTERVAL}s)", flush=True)
collect()

while True:
    time.sleep(INTERVAL)
    collect()
