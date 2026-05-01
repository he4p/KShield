from __future__ import annotations

import os
from dataclasses import dataclass


_CLK_TCK = os.sysconf(os.sysconf_names["SC_CLK_TCK"])


@dataclass(frozen=True)
class SystemCpuSample:
    ts_s: float
    total_jiffies: int
    idle_jiffies: int


@dataclass(frozen=True)
class ProcessCpuSample:
    ts_s: float
    pid: int
    cpu_jiffies: int


@dataclass(frozen=True)
class ProcessMemSample:
    ts_s: float
    pid: int
    rss_kb: int


@dataclass(frozen=True)
class SystemMemSample:
    ts_s: float
    mem_total_kb: int
    mem_available_kb: int


def read_system_cpu(ts_s: float) -> SystemCpuSample:
    # /proc/stat: cpu  user nice system idle iowait irq softirq steal guest guest_nice
    with open("/proc/stat", "r", encoding="utf-8") as f:
        for line in f:
            if not line.startswith("cpu "):
                continue
            parts = line.split()
            values = [int(v) for v in parts[1:]]
            total = sum(values)
            idle = values[3] + (values[4] if len(values) > 4 else 0)
            return SystemCpuSample(ts_s=ts_s, total_jiffies=total, idle_jiffies=idle)
    raise RuntimeError("missing cpu line in /proc/stat")


def read_process_cpu(ts_s: float, pid: int) -> ProcessCpuSample:
    # /proc/<pid>/stat fields: ... utime (14), stime (15)
    with open(f"/proc/{pid}/stat", "r", encoding="utf-8") as f:
        text = f.read().strip()
    parts = text.split()
    utime = int(parts[13])
    stime = int(parts[14])
    return ProcessCpuSample(ts_s=ts_s, pid=pid, cpu_jiffies=utime + stime)


def read_process_rss_kb(ts_s: float, pid: int) -> ProcessMemSample:
    rss_kb = 0
    with open(f"/proc/{pid}/status", "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                rss_kb = int(line.split()[1])
                break
    return ProcessMemSample(ts_s=ts_s, pid=pid, rss_kb=rss_kb)


def read_system_mem(ts_s: float) -> SystemMemSample:
    mem_total_kb = 0
    mem_available_kb = 0
    with open("/proc/meminfo", "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("MemTotal:"):
                mem_total_kb = int(line.split()[1])
            elif line.startswith("MemAvailable:"):
                mem_available_kb = int(line.split()[1])
    return SystemMemSample(ts_s=ts_s, mem_total_kb=mem_total_kb, mem_available_kb=mem_available_kb)


def cpu_utilization_percent(prev: SystemCpuSample, cur: SystemCpuSample) -> float:
    delta_total = cur.total_jiffies - prev.total_jiffies
    delta_idle = cur.idle_jiffies - prev.idle_jiffies
    if delta_total <= 0:
        return 0.0
    return max(0.0, min(100.0, (delta_total - delta_idle) * 100.0 / delta_total))


def process_cpu_percent(prev: ProcessCpuSample, cur: ProcessCpuSample) -> float:
    dt = cur.ts_s - prev.ts_s
    if dt <= 0:
        return 0.0
    delta_j = cur.cpu_jiffies - prev.cpu_jiffies
    cpu_s = delta_j / float(_CLK_TCK)
    # Percent of a single CPU core. (Can exceed 100% if multithreaded.)
    return max(0.0, (cpu_s * 100.0) / dt)

