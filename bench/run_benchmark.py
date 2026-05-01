#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from http_client import HttpError, request_json
from proc_metrics import (
    cpu_utilization_percent,
    process_cpu_percent,
    read_process_cpu,
    read_process_rss_kb,
    read_system_cpu,
    read_system_mem,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT_DIR = ROOT / "bench" / "out"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_iso8601(ts: str) -> datetime:
    normalized = ts.replace("Z", "+00:00")
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def ensure_fixture_files() -> None:
    # Used by policy tests. Must exist before enabling policies that would block their creation.
    shadow = Path("/tmp/shadow")
    if not shadow.exists():
        shadow.write_bytes(b"bench\n")
        os.chmod(shadow, 0o644)
    blocked_exec = Path("/tmp/ksbench_blocked_exec.sh")
    if not blocked_exec.exists():
        blocked_exec.write_text("#!/usr/bin/env sh\nexit 0\n", encoding="utf-8")
        os.chmod(blocked_exec, 0o755)


def find_agent_id(manager_url: str) -> str:
    payload = request_json("GET", f"{manager_url}/api/v1/agents")
    items = payload.get("items", []) if isinstance(payload, dict) else []
    if not items:
        raise RuntimeError("no agents registered (GET /api/v1/agents returned empty list)")
    # Pick most recently seen.
    return str(items[0]["id"])


def get_latest_ids(manager_url: str) -> tuple[int, int]:
    events = request_json("GET", f"{manager_url}/api/v1/events?limit=1").get("items", [])
    dets = request_json("GET", f"{manager_url}/api/v1/detections?limit=1").get("items", [])
    last_event_id = int(events[0]["id"]) if events else 0
    last_det_id = int(dets[0]["id"]) if dets else 0
    return last_event_id, last_det_id


def fetch_recent(manager_url: str, limit: int = 2000) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    ev = request_json("GET", f"{manager_url}/api/v1/events?limit={limit}").get("items", [])
    de = request_json("GET", f"{manager_url}/api/v1/detections?limit={limit}").get("items", [])
    return list(ev), list(de)


def snapshot_policy(manager_url: str) -> dict[str, Any]:
    payload = request_json("GET", f"{manager_url}/api/v1/policy")
    if not isinstance(payload, dict):
        return {}
    # Keep the full item lists so we can restore exact scopes.
    return {
        "blocked_ipv4_items": payload.get("blocked_ipv4_items", []),
        "blocked_bind_port_items": payload.get("blocked_bind_port_items", []),
        "blocked_exec_path_items": payload.get("blocked_exec_path_items", []),
        "protected_write_target_items": payload.get("protected_write_target_items", []),
        "ptrace_deny_items": payload.get("ptrace_deny_items", []),
    }


def _delete_all_policy(manager_url: str, snap: dict[str, Any]) -> None:
    for item in snap.get("blocked_ipv4_items", []):
        request_json(
            "DELETE",
            f"{manager_url}/api/v1/policy/blocked-ipv4",
            {"ip": item.get("ip", ""), "agent_id": item.get("agent_id", "")},
        )
    for item in snap.get("blocked_bind_port_items", []):
        request_json(
            "DELETE",
            f"{manager_url}/api/v1/policy/blocked-bind-port",
            {"port": int(item.get("port", 0)), "agent_id": item.get("agent_id", "")},
        )
    for item in snap.get("blocked_exec_path_items", []):
        request_json(
            "DELETE",
            f"{manager_url}/api/v1/policy/blocked-exec-path",
            {"path": item.get("path", ""), "agent_id": item.get("agent_id", "")},
        )
    for item in snap.get("protected_write_target_items", []):
        request_json(
            "DELETE",
            f"{manager_url}/api/v1/policy/protected-write-target",
            {"target": item.get("target", ""), "agent_id": item.get("agent_id", "")},
        )
    for item in snap.get("ptrace_deny_items", []):
        request_json(
            "DELETE",
            f"{manager_url}/api/v1/policy/deny-ptrace",
            {"agent_id": item.get("agent_id", "")},
        )


def restore_policy(manager_url: str, snapshot: dict[str, Any]) -> None:
    # Best-effort restore: delete everything we see now and re-apply snapshot.
    current = snapshot_policy(manager_url)
    _delete_all_policy(manager_url, current)

    for item in snapshot.get("blocked_ipv4_items", []):
        request_json(
            "POST",
            f"{manager_url}/api/v1/policy/blocked-ipv4",
            {"ip": item.get("ip", ""), "enabled": bool(item.get("enabled", True)), "agent_id": item.get("agent_id", "")},
        )
    for item in snapshot.get("blocked_bind_port_items", []):
        request_json(
            "POST",
            f"{manager_url}/api/v1/policy/blocked-bind-port",
            {"port": int(item.get("port", 0)), "enabled": bool(item.get("enabled", True)), "agent_id": item.get("agent_id", "")},
        )
    for item in snapshot.get("blocked_exec_path_items", []):
        request_json(
            "POST",
            f"{manager_url}/api/v1/policy/blocked-exec-path",
            {"path": item.get("path", ""), "enabled": bool(item.get("enabled", True)), "agent_id": item.get("agent_id", "")},
        )
    for item in snapshot.get("protected_write_target_items", []):
        request_json(
            "POST",
            f"{manager_url}/api/v1/policy/protected-write-target",
            {"target": item.get("target", ""), "enabled": bool(item.get("enabled", True)), "agent_id": item.get("agent_id", "")},
        )
    for item in snapshot.get("ptrace_deny_items", []):
        request_json(
            "POST",
            f"{manager_url}/api/v1/policy/deny-ptrace",
            {"enabled": bool(item.get("enabled", True)), "agent_id": item.get("agent_id", "")},
        )


def apply_policy_profile(manager_url: str, profile: dict[str, Any]) -> None:
    for ip in profile.get("blocked_ipv4", []):
        request_json("POST", f"{manager_url}/api/v1/policy/blocked-ipv4", {"ip": ip, "enabled": True})
    for port in profile.get("blocked_bind_ports", []):
        request_json("POST", f"{manager_url}/api/v1/policy/blocked-bind-port", {"port": int(port), "enabled": True})
    for path in profile.get("blocked_exec_paths", []):
        request_json("POST", f"{manager_url}/api/v1/policy/blocked-exec-path", {"path": path, "enabled": True})
    for target in profile.get("protected_write_targets", []):
        request_json("POST", f"{manager_url}/api/v1/policy/protected-write-target", {"target": target, "enabled": True})
    if bool(profile.get("deny_ptrace", False)):
        request_json("POST", f"{manager_url}/api/v1/policy/deny-ptrace", {"enabled": True})


def run_action(action: str, comm: str) -> int:
    cmd = [sys.executable, str(ROOT / "bench" / "ksbench_action.py"), action, "--comm", comm]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return int(proc.returncode)


@dataclass
class TestResult:
    id: str
    label: str
    action: str
    expected_detectors: list[str]
    observed_detectors: list[str]
    new_events: int
    new_detections: int
    ok: bool
    classification: str  # TP/TN/FP/FN
    latencies_ms: list[float]
    action_rc: int


def evaluate_test(
    manager_url: str,
    comm_filter: str,
    test: dict[str, Any],
    poll_timeout_s: float,
) -> TestResult:
    test_id = str(test.get("id", ""))
    label = str(test.get("label", test_id))
    action = str(test.get("action", ""))
    expected = [str(x) for x in (test.get("expected_detectors") or [])]

    start_event_id, start_det_id = get_latest_ids(manager_url)
    t0 = utc_now()
    rc = run_action(action, comm_filter)

    seen_det_ids: set[int] = set()
    observed_detector_ids: set[str] = set()
    latencies_ms: list[float] = []

    deadline = time.time() + poll_timeout_s
    while time.time() < deadline:
        events, dets = fetch_recent(manager_url, limit=2000)
        events_by_id = {int(e["id"]): e for e in events if int(e.get("id", 0)) > start_event_id}

        new_dets = [d for d in dets if int(d.get("id", 0)) > start_det_id]
        new_events = [e for e in events if int(e.get("id", 0)) > start_event_id]
        new_events_filtered = [e for e in new_events if str(e.get("comm", "")) == comm_filter]

        for det in new_dets:
            det_id = int(det.get("id", 0))
            if det_id in seen_det_ids:
                continue
            event_id = int(det.get("event_id", 0))
            evt = events_by_id.get(event_id)
            if not evt or str(evt.get("comm", "")) != comm_filter:
                continue
            seen_det_ids.add(det_id)
            observed_detector_ids.add(str(det.get("detector_id", "")))
            if expected and str(det.get("detector_id", "")) in expected:
                try:
                    evt_ts = parse_iso8601(str(evt.get("ts", "")))
                    latency = (utc_now() - evt_ts).total_seconds() * 1000.0
                    if latency >= 0:
                        latencies_ms.append(latency)
                except Exception:
                    pass

        # Stop early if we've seen all expected detectors (attack cases) or if any detection appeared (benign FP check).
        if expected:
            if all(det_id in observed_detector_ids for det_id in expected):
                break
        else:
            if observed_detector_ids:
                break
            # Or if we saw at least one relevant event (so “no detection” is meaningful).
            if new_events_filtered:
                break

        time.sleep(0.25)

    events, dets = fetch_recent(manager_url, limit=2000)
    new_events = [e for e in events if int(e.get("id", 0)) > start_event_id and str(e.get("comm", "")) == comm_filter]

    # Count detections referencing our events (comm-filtered via join).
    events_by_id_all = {int(e["id"]): e for e in new_events}
    new_dets = [d for d in dets if int(d.get("id", 0)) > start_det_id]
    new_dets_filtered = [
        d
        for d in new_dets
        if int(d.get("event_id", 0)) in events_by_id_all
    ]
    final_observed = sorted({str(d.get("detector_id", "")) for d in new_dets_filtered if d.get("detector_id")})

    is_attack = bool(expected)
    detected = any(d in final_observed for d in expected) if expected else bool(final_observed)
    if is_attack:
        classification = "TP" if detected else "FN"
        ok = detected
    else:
        classification = "FP" if detected else "TN"
        ok = not detected

    return TestResult(
        id=test_id,
        label=label,
        action=action,
        expected_detectors=expected,
        observed_detectors=final_observed,
        new_events=len(new_events),
        new_detections=len(new_dets_filtered),
        ok=ok,
        classification=classification,
        latencies_ms=latencies_ms,
        action_rc=rc,
    )


def load_suite(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def detect_pids() -> dict[str, int | None]:
    # Best-effort: parse `ps` output.
    try:
        out = subprocess.check_output(["ps", "-eo", "pid,args"], text=True)
    except Exception:
        return {"manager_pid": None, "agent_pid": None}

    manager_pid: int | None = None
    agent_pid: int | None = None
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("PID"):
            continue
        pid_s, _, args = line.partition(" ")
        try:
            pid = int(pid_s)
        except ValueError:
            continue
        if "manager/app.py" in args and manager_pid is None:
            manager_pid = pid
        if "kshield-agent" in args and agent_pid is None:
            agent_pid = pid
    return {"manager_pid": manager_pid, "agent_pid": agent_pid}


@dataclass
class PerfSample:
    ts_s: float
    system_cpu_percent: float
    manager_cpu_percent: float | None
    agent_cpu_percent: float | None
    system_mem_used_kb: int
    manager_rss_kb: int | None
    agent_rss_kb: int | None


def measure_load(
    seconds: int,
    manager_pid: int | None,
    agent_pid: int | None,
    interval_s: float = 1.0,
) -> list[PerfSample]:
    samples: list[PerfSample] = []
    t_start = time.time()

    prev_sys = read_system_cpu(t_start)
    prev_mgr = read_process_cpu(t_start, manager_pid) if manager_pid else None
    prev_agent = read_process_cpu(t_start, agent_pid) if agent_pid else None

    while True:
        now = time.time()
        if now - t_start >= seconds:
            break

        time.sleep(interval_s)
        now = time.time()

        sys_cpu = read_system_cpu(now)
        sys_pct = cpu_utilization_percent(prev_sys, sys_cpu)
        prev_sys = sys_cpu

        mgr_pct: float | None = None
        mgr_rss: int | None = None
        if manager_pid:
            try:
                mgr_cpu = read_process_cpu(now, manager_pid)
                mgr_pct = process_cpu_percent(prev_mgr, mgr_cpu) if prev_mgr else None
                prev_mgr = mgr_cpu
                mgr_rss = read_process_rss_kb(now, manager_pid).rss_kb
            except FileNotFoundError:
                manager_pid = None

        agent_pct: float | None = None
        agent_rss: int | None = None
        if agent_pid:
            try:
                agent_cpu = read_process_cpu(now, agent_pid)
                agent_pct = process_cpu_percent(prev_agent, agent_cpu) if prev_agent else None
                prev_agent = agent_cpu
                agent_rss = read_process_rss_kb(now, agent_pid).rss_kb
            except FileNotFoundError:
                agent_pid = None

        mem = read_system_mem(now)
        used_kb = max(0, mem.mem_total_kb - mem.mem_available_kb)

        samples.append(
            PerfSample(
                ts_s=now,
                system_cpu_percent=sys_pct,
                manager_cpu_percent=mgr_pct,
                agent_cpu_percent=agent_pct,
                system_mem_used_kb=used_kb,
                manager_rss_kb=mgr_rss,
                agent_rss_kb=agent_rss,
            )
        )

    return samples


def run_loadgen(load_secs: int, comm: str) -> None:
    # Lightweight open loop to generate file_open events without expected detections.
    # Uses /etc/hosts as target (should not match any default detectors).
    cmd = [
        sys.executable,
        str(ROOT / "bench" / "ksbench_action.py"),
        "open_hosts",
        "--comm",
        comm,
    ]
    deadline = time.time() + load_secs
    while time.time() < deadline:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def summarize_confusion(results: list[TestResult]) -> dict[str, Any]:
    tp = sum(1 for r in results if r.classification == "TP")
    tn = sum(1 for r in results if r.classification == "TN")
    fp = sum(1 for r in results if r.classification == "FP")
    fn = sum(1 for r in results if r.classification == "FN")
    denom_pos = tp + fn
    denom_all = tp + tn + fp + fn
    tpr = (tp / denom_pos) if denom_pos else 0.0
    fnr = (fn / denom_pos) if denom_pos else 0.0
    acc = ((tp + tn) / denom_all) if denom_all else 0.0
    return {"TP": tp, "TN": tn, "FP": fp, "FN": fn, "TPR": tpr, "FNR": fnr, "Accuracy": acc}


def avg(values: list[float]) -> float:
    return (sum(values) / len(values)) if values else 0.0


def main() -> int:
    parser = argparse.ArgumentParser(description="KShield benchmark runner")
    parser.add_argument("--manager-url", default="http://127.0.0.1:8080")
    parser.add_argument("--agent-id", default="")
    parser.add_argument("--suite", default=str(ROOT / "bench" / "suite.default.json"))
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT_DIR))
    parser.add_argument("--mode", choices=["monitored", "baseline"], default="monitored")
    parser.add_argument("--baseline", default="", help="baseline JSON file to compute CPU/mem overhead")
    parser.add_argument("--policy-wait-secs", type=int, default=14, help="wait after applying policy to allow agent sync")
    parser.add_argument("--poll-timeout-secs", type=float, default=6.0)
    parser.add_argument("--load-secs", type=int, default=20)
    parser.add_argument("--load-interval-secs", type=float, default=1.0)
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    suite = load_suite(Path(args.suite))
    comm = str(suite.get("comm_filter", "ksbench"))

    report: dict[str, Any] = {
        "ts": utc_now().isoformat(),
        "manager_url": args.manager_url,
        "mode": args.mode,
        "suite": suite.get("name", "unknown"),
    }

    if args.mode == "monitored":
        try:
            agent_id = args.agent_id.strip() or find_agent_id(args.manager_url)
        except Exception as exc:
            print(f"agent-id discovery failed: {exc}", file=sys.stderr)
            return 2
        report["agent_id"] = agent_id

        ensure_fixture_files()
        policy_snapshot = snapshot_policy(args.manager_url)
        report["policy_snapshot_taken"] = True

        results: list[TestResult] = []
        try:
            for test in suite.get("non_policy_tests", []):
                results.append(evaluate_test(args.manager_url, comm, test, args.poll_timeout_secs))

            policy_profile = suite.get("policy_profile", {})
            if policy_profile and suite.get("policy_tests"):
                apply_policy_profile(args.manager_url, policy_profile)
                time.sleep(max(0, int(args.policy_wait_secs)))
                for test in suite.get("policy_tests", []):
                    results.append(evaluate_test(args.manager_url, comm, test, args.poll_timeout_secs))
        finally:
            try:
                restore_policy(args.manager_url, policy_snapshot)
            except Exception as exc:
                print(f"policy restore failed (manual cleanup may be needed): {exc}", file=sys.stderr)

        report["tests"] = [asdict(r) for r in results]
        confusion = summarize_confusion(results)
        report["confusion"] = confusion
        lat_all = [v for r in results for v in r.latencies_ms]
        report["detection_latency_ms_avg"] = avg(lat_all)
        report["coverage"] = {
            "attacks_total": sum(1 for r in results if r.expected_detectors),
            "attacks_detected": sum(1 for r in results if r.classification == "TP"),
            "coverage": confusion["TPR"],
        }

        # Throughput (events/sec) during a simple load phase.
        before = request_json("GET", f"{args.manager_url}/api/v1/metrics/summary")
        start_total_events = int(before.get("total_events", 0)) if isinstance(before, dict) else 0
        start = time.time()

        pids = detect_pids()
        manager_pid = pids.get("manager_pid")
        agent_pid = pids.get("agent_pid")
        report["pids"] = pids

        # Run loadgen in-process while sampling perf.
        perf_samples: list[Any] = []
        load_deadline = time.time() + int(args.load_secs)
        t_last_sample = time.time()
        # prime samples
        prev = None
        prev_mgr = None
        prev_agent = None
        prev_sys = read_system_cpu(time.time())
        if isinstance(manager_pid, int):
            try:
                prev_mgr = read_process_cpu(time.time(), manager_pid)
            except FileNotFoundError:
                manager_pid = None
        if isinstance(agent_pid, int):
            try:
                prev_agent = read_process_cpu(time.time(), agent_pid)
            except FileNotFoundError:
                agent_pid = None

        cmd = [sys.executable, str(ROOT / "bench" / "ksbench_action.py"), "open_hosts", "--comm", comm]
        while time.time() < load_deadline:
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            now = time.time()
            if now - t_last_sample >= float(args.load_interval_secs):
                sys_cpu = read_system_cpu(now)
                sys_pct = cpu_utilization_percent(prev_sys, sys_cpu)
                prev_sys = sys_cpu

                mgr_pct = None
                mgr_rss = None
                if isinstance(manager_pid, int):
                    try:
                        cur_mgr = read_process_cpu(now, manager_pid)
                        mgr_pct = process_cpu_percent(prev_mgr, cur_mgr) if prev_mgr else None
                        prev_mgr = cur_mgr
                        mgr_rss = read_process_rss_kb(now, manager_pid).rss_kb
                    except FileNotFoundError:
                        manager_pid = None

                agent_pct = None
                agent_rss = None
                if isinstance(agent_pid, int):
                    try:
                        cur_agent = read_process_cpu(now, agent_pid)
                        agent_pct = process_cpu_percent(prev_agent, cur_agent) if prev_agent else None
                        prev_agent = cur_agent
                        agent_rss = read_process_rss_kb(now, agent_pid).rss_kb
                    except FileNotFoundError:
                        agent_pid = None

                mem = read_system_mem(now)
                used_kb = max(0, mem.mem_total_kb - mem.mem_available_kb)
                perf_samples.append(
                    {
                        "ts_s": now,
                        "system_cpu_percent": sys_pct,
                        "manager_cpu_percent": mgr_pct,
                        "agent_cpu_percent": agent_pct,
                        "system_mem_used_kb": used_kb,
                        "manager_rss_kb": mgr_rss,
                        "agent_rss_kb": agent_rss,
                    }
                )
                t_last_sample = now

        elapsed = max(0.001, time.time() - start)
        after = request_json("GET", f"{args.manager_url}/api/v1/metrics/summary")
        end_total_events = int(after.get("total_events", 0)) if isinstance(after, dict) else 0
        delta_events = max(0, end_total_events - start_total_events)
        report["throughput_events_per_sec"] = delta_events / elapsed
        report["perf_samples"] = perf_samples
        report["avg_manager_rss_kb"] = avg([float(s["manager_rss_kb"]) for s in perf_samples if s.get("manager_rss_kb") is not None])
        report["avg_agent_rss_kb"] = avg([float(s["agent_rss_kb"]) for s in perf_samples if s.get("agent_rss_kb") is not None])

        # Optional overhead vs baseline file.
        if args.baseline:
            baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
            base_cpu = float(baseline.get("avg_system_cpu_percent", 0.0))
            cur_cpu = avg([float(s["system_cpu_percent"]) for s in perf_samples if s.get("system_cpu_percent") is not None])
            report["avg_system_cpu_percent"] = cur_cpu
            report["cpu_overhead_percent"] = ((cur_cpu - base_cpu) / base_cpu * 100.0) if base_cpu > 0 else None

            base_mem = float(baseline.get("avg_system_mem_used_kb", 0.0))
            cur_mem = avg([float(s["system_mem_used_kb"]) for s in perf_samples if s.get("system_mem_used_kb") is not None])
            report["avg_system_mem_used_kb"] = cur_mem
            report["mem_overhead_kb"] = (cur_mem - base_mem) if base_mem > 0 else None
        else:
            report["avg_system_cpu_percent"] = avg([float(s["system_cpu_percent"]) for s in perf_samples if s.get("system_cpu_percent") is not None])
            report["avg_system_mem_used_kb"] = avg([float(s["system_mem_used_kb"]) for s in perf_samples if s.get("system_mem_used_kb") is not None])

    else:
        # Baseline mode: just measure system CPU/mem during the workload generator loop.
        comm = "ksbench"
        perf_samples = []
        load_deadline = time.time() + int(args.load_secs)
        t_last_sample = time.time()
        prev_sys = read_system_cpu(time.time())
        cmd = [sys.executable, str(ROOT / "bench" / "ksbench_action.py"), "open_hosts", "--comm", comm]
        while time.time() < load_deadline:
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            now = time.time()
            if now - t_last_sample >= float(args.load_interval_secs):
                sys_cpu = read_system_cpu(now)
                sys_pct = cpu_utilization_percent(prev_sys, sys_cpu)
                prev_sys = sys_cpu
                mem = read_system_mem(now)
                used_kb = max(0, mem.mem_total_kb - mem.mem_available_kb)
                perf_samples.append(
                    {
                        "ts_s": now,
                        "system_cpu_percent": sys_pct,
                        "system_mem_used_kb": used_kb,
                    }
                )
                t_last_sample = now
        report["perf_samples"] = perf_samples
        report["avg_system_cpu_percent"] = avg([float(s["system_cpu_percent"]) for s in perf_samples])
        report["avg_system_mem_used_kb"] = avg([float(s["system_mem_used_kb"]) for s in perf_samples])

    report_path = out_dir / ("baseline.json" if args.mode == "baseline" else "report.json")
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    # Human summary
    summary_lines: list[str] = []
    summary_lines.append(f"mode={args.mode} manager={args.manager_url}")
    if args.mode == "monitored":
        conf = report.get("confusion", {})
        summary_lines.append(
            f"TP={conf.get('TP')} TN={conf.get('TN')} FP={conf.get('FP')} FN={conf.get('FN')} "
            f"TPR={conf.get('TPR'):.3f} FNR={conf.get('FNR'):.3f} Accuracy={conf.get('Accuracy'):.3f}"
        )
        summary_lines.append(f"avg_detection_latency_ms={report.get('detection_latency_ms_avg'):.1f}")
        summary_lines.append(f"throughput_events_per_sec={report.get('throughput_events_per_sec'):.1f}")
        summary_lines.append(f"avg_system_cpu_percent={report.get('avg_system_cpu_percent'):.2f}")
        summary_lines.append(f"avg_system_mem_used_kb={report.get('avg_system_mem_used_kb'):.0f}")
        summary_lines.append(f"avg_manager_rss_kb={report.get('avg_manager_rss_kb'):.0f}")
        summary_lines.append(f"avg_agent_rss_kb={report.get('avg_agent_rss_kb'):.0f}")
        if report.get("cpu_overhead_percent") is not None:
            summary_lines.append(f"cpu_overhead_percent={report.get('cpu_overhead_percent'):.2f}")
        if report.get("mem_overhead_kb") is not None:
            summary_lines.append(f"mem_overhead_kb={report.get('mem_overhead_kb'):.0f}")
    else:
        summary_lines.append(f"avg_system_cpu_percent={report.get('avg_system_cpu_percent'):.2f}")
        summary_lines.append(f"avg_system_mem_used_kb={report.get('avg_system_mem_used_kb'):.0f}")

    (out_dir / ("baseline.txt" if args.mode == "baseline" else "report.txt")).write_text(
        "\n".join(summary_lines) + "\n",
        encoding="utf-8",
    )
    print("\n".join(summary_lines))
    print(f"wrote {report_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except HttpError as exc:
        print(f"http error: {exc}", file=sys.stderr)
        raise SystemExit(2)
