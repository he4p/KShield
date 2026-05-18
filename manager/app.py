#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import threading
import tomllib
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def as_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def as_list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list) else []


def stable_event_ts(value: Any) -> str:
    text = as_str(value).strip()
    return text or now_iso()


def parse_event_dt(value: Any) -> datetime:
    text = as_str(value).strip()
    if not text:
        return datetime.now(timezone.utc)
    try:
        normalized = text.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


class SafeFormatMap(dict[str, Any]):
    def __missing__(self, key: str) -> str:
        return ""


@dataclass
class Config:
    host: str
    port: int
    db_path: Path
    static_dir: Path
    detector_dir: Path


@dataclass
class Detector:
    id: str
    name: str
    description: str
    severity: str
    tags: list[str] = field(default_factory=list)
    event_types: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    comm_in: list[str] = field(default_factory=list)
    comm_prefixes: list[str] = field(default_factory=list)
    subject_prefixes: list[str] = field(default_factory=list)
    subject_contains: list[str] = field(default_factory=list)
    dst_ports: list[int] = field(default_factory=list)
    dst_ips: list[str] = field(default_factory=list)
    uids: list[int] = field(default_factory=list)
    arg0_in: list[int] = field(default_factory=list)
    arg1_in: list[int] = field(default_factory=list)
    threshold_count: int = 1
    threshold_window_secs: int = 0
    group_by: list[str] = field(default_factory=list)
    summary_template: str = ""
    source_file: str = ""

    @classmethod
    def from_toml(cls, path: Path, payload: dict[str, Any]) -> "Detector":
        match = payload.get("match", {}) if isinstance(payload.get("match"), dict) else {}
        detector_id = as_str(payload.get("id"), path.stem).strip() or path.stem
        name = as_str(payload.get("name"), detector_id).strip() or detector_id
        description = as_str(payload.get("description"), "").strip()
        severity = as_str(payload.get("severity"), "warning").strip().lower() or "warning"
        return cls(
            id=detector_id,
            name=name,
            description=description,
            severity=severity,
            tags=[as_str(v).strip() for v in as_list(payload.get("tags")) if as_str(v).strip()],
            event_types=[as_str(v).strip().lower() for v in as_list(match.get("event_types")) if as_str(v).strip()],
            actions=[as_str(v).strip().lower() for v in as_list(match.get("actions")) if as_str(v).strip()],
            comm_in=[as_str(v).strip().lower() for v in as_list(match.get("comm_in")) if as_str(v).strip()],
            comm_prefixes=[as_str(v).strip().lower() for v in as_list(match.get("comm_prefixes")) if as_str(v).strip()],
            subject_prefixes=[as_str(v).strip().lower() for v in as_list(match.get("subject_prefixes")) if as_str(v).strip()],
            subject_contains=[as_str(v).strip().lower() for v in as_list(match.get("subject_contains")) if as_str(v).strip()],
            dst_ports=[as_int(v) for v in as_list(match.get("dst_ports"))],
            dst_ips=[as_str(v).strip() for v in as_list(match.get("dst_ips")) if as_str(v).strip()],
            uids=[as_int(v) for v in as_list(match.get("uids"))],
            arg0_in=[as_int(v) for v in as_list(match.get("arg0_in"))],
            arg1_in=[as_int(v) for v in as_list(match.get("arg1_in"))],
            threshold_count=max(1, as_int(payload.get("threshold_count"), 1)),
            threshold_window_secs=max(0, as_int(payload.get("threshold_window_secs"), 0)),
            group_by=[as_str(v).strip() for v in as_list(payload.get("group_by")) if as_str(v).strip()],
            summary_template=as_str(payload.get("summary_template"), "").strip(),
            source_file=path.name,
        )

    def matches(self, event: dict[str, Any]) -> bool:
        event_type = as_str(event.get("event_type")).lower()
        action = as_str(event.get("action")).lower()
        comm = as_str(event.get("comm")).lower()
        subject = as_str(event.get("subject")).lower()
        dst_ip = as_str(event.get("dst_ip"))
        dst_port = as_int(event.get("dst_port"))
        uid = as_int(event.get("uid"))
        arg0 = as_int(event.get("arg0"))
        arg1 = as_int(event.get("arg1"))

        if self.event_types and event_type not in self.event_types:
            return False
        if self.actions and action not in self.actions:
            return False
        if self.comm_in and comm not in self.comm_in:
            return False
        if self.comm_prefixes and not any(comm.startswith(prefix) for prefix in self.comm_prefixes):
            return False
        if self.subject_prefixes and not any(subject.startswith(prefix) for prefix in self.subject_prefixes):
            return False
        if self.subject_contains and not any(fragment in subject for fragment in self.subject_contains):
            return False
        if self.dst_ports and dst_port not in self.dst_ports:
            return False
        if self.dst_ips and dst_ip not in self.dst_ips:
            return False
        if self.uids and uid not in self.uids:
            return False
        if self.arg0_in and arg0 not in self.arg0_in:
            return False
        if self.arg1_in and arg1 not in self.arg1_in:
            return False
        return True

    def summary_for(self, event: dict[str, Any]) -> str:
        if self.summary_template:
            return self.summary_template.format_map(
                SafeFormatMap({key: as_str(value) for key, value in event.items()})
            )
        if self.description:
            return self.description
        subject = as_str(event.get("subject")).strip()
        if subject:
            return f"{self.name}: {subject}"
        return self.name

    def correlation_key_for(self, event: dict[str, Any]) -> str:
        fields = self.group_by or ["agent_id"]
        return "|".join(as_str(event.get(field)).strip() for field in fields)


class DetectorCatalog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self._stamp: tuple[tuple[str, int, int], ...] = ()
        self._detectors: list[Detector] = []

    def _snapshot(self) -> tuple[tuple[str, int, int], ...]:
        files = []
        for entry in sorted(self.path.glob("*.toml")):
            stat = entry.stat()
            files.append((entry.name, stat.st_mtime_ns, stat.st_size))
        return tuple(files)

    def refresh(self) -> None:
        with self.lock:
            stamp = self._snapshot()
            if stamp == self._stamp:
                return

            detectors: list[Detector] = []
            for name, _, _ in stamp:
                path = self.path / name
                try:
                    data = tomllib.loads(path.read_text(encoding="utf-8"))
                    detector = Detector.from_toml(path, data)
                    detectors.append(detector)
                except Exception as exc:  # noqa: BLE001
                    print(f"detector load error for {path.name}: {exc}")

            self._detectors = detectors
            self._stamp = stamp

    def list(self) -> list[Detector]:
        self.refresh()
        with self.lock:
            return list(self._detectors)


class Storage:
    def __init__(self, path: Path, detectors: DetectorCatalog) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        self.detectors = detectors
        self.correlation_windows: dict[tuple[str, str], deque[datetime]] = defaultdict(deque)
        self._init_schema()

    def _ensure_column(self, table: str, column: str, definition: str) -> None:
        existing = {
            str(row["name"])
            for row in self.conn.execute(f"PRAGMA table_info({table})").fetchall()
        }
        if column not in existing:
            self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def _init_schema(self) -> None:
        with self.lock, self.conn:
            self.conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS agents (
                    id TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    kernel TEXT DEFAULT '',
                    version TEXT DEFAULT '',
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'online'
                );

                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    ts TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    action TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    pid INTEGER NOT NULL DEFAULT 0,
                    uid INTEGER NOT NULL DEFAULT 0,
                    comm TEXT NOT NULL DEFAULT '',
                    dst_ip TEXT NOT NULL DEFAULT '',
                    dst_port INTEGER NOT NULL DEFAULT 0,
                    subject TEXT NOT NULL DEFAULT '',
                    arg0 INTEGER NOT NULL DEFAULT 0,
                    arg1 INTEGER NOT NULL DEFAULT 0,
                    raw_json TEXT NOT NULL DEFAULT '{}',
                    FOREIGN KEY(agent_id) REFERENCES agents(id)
                );

                CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
                CREATE INDEX IF NOT EXISTS idx_events_agent ON events(agent_id);

                CREATE TABLE IF NOT EXISTS detections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    detector_id TEXT NOT NULL,
                    detector_name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    ts TEXT NOT NULL,
                    event_id INTEGER NOT NULL,
                    agent_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    action TEXT NOT NULL,
                    subject TEXT NOT NULL DEFAULT '',
                    match_count INTEGER NOT NULL DEFAULT 1,
                    correlation_key TEXT NOT NULL DEFAULT '',
                    summary TEXT NOT NULL DEFAULT '',
                    raw_json TEXT NOT NULL DEFAULT '{}',
                    FOREIGN KEY(event_id) REFERENCES events(id),
                    FOREIGN KEY(agent_id) REFERENCES agents(id)
                );

                CREATE INDEX IF NOT EXISTS idx_detections_ts ON detections(ts DESC);
                CREATE INDEX IF NOT EXISTS idx_detections_detector ON detections(detector_id);

                CREATE TABLE IF NOT EXISTS blocked_ipv4 (
                    ip TEXT PRIMARY KEY,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS blocked_bind_ports (
                    port INTEGER PRIMARY KEY,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS blocked_ipv4_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    agent_scope TEXT NOT NULL DEFAULT '',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    updated_at TEXT NOT NULL,
                    UNIQUE(ip, agent_scope)
                );

                CREATE INDEX IF NOT EXISTS idx_blocked_ipv4_rules_scope
                ON blocked_ipv4_rules(agent_scope, enabled);

                CREATE TABLE IF NOT EXISTS blocked_bind_port_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    port INTEGER NOT NULL,
                    agent_scope TEXT NOT NULL DEFAULT '',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    updated_at TEXT NOT NULL,
                    UNIQUE(port, agent_scope)
                );

                CREATE INDEX IF NOT EXISTS idx_blocked_bind_port_rules_scope
                ON blocked_bind_port_rules(agent_scope, enabled);

                CREATE TABLE IF NOT EXISTS blocked_exec_path_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    path TEXT NOT NULL,
                    agent_scope TEXT NOT NULL DEFAULT '',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    updated_at TEXT NOT NULL,
                    UNIQUE(path, agent_scope)
                );

                CREATE INDEX IF NOT EXISTS idx_blocked_exec_path_rules_scope
                ON blocked_exec_path_rules(agent_scope, enabled);

                CREATE TABLE IF NOT EXISTS protected_write_target_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    agent_scope TEXT NOT NULL DEFAULT '',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    updated_at TEXT NOT NULL,
                    UNIQUE(target, agent_scope)
                );

                CREATE INDEX IF NOT EXISTS idx_protected_write_target_rules_scope
                ON protected_write_target_rules(agent_scope, enabled);

                CREATE TABLE IF NOT EXISTS ptrace_deny_rules (
                    agent_scope TEXT PRIMARY KEY NOT NULL DEFAULT '',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    updated_at TEXT NOT NULL
                );
                """
            )

            self._ensure_column("events", "subject", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column("events", "arg0", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column("events", "arg1", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column("events", "ppid", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column("events", "ancestry", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column("events", "process_path", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column("events", "pid_ns", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column("events", "mount_ns", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column("events", "net_ns", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column("detections", "match_count", "INTEGER NOT NULL DEFAULT 1")
            self._ensure_column("detections", "correlation_key", "TEXT NOT NULL DEFAULT ''")

            if self.conn.execute("SELECT COUNT(*) FROM blocked_ipv4_rules").fetchone()[0] == 0:
                self.conn.execute(
                    """
                    INSERT OR IGNORE INTO blocked_ipv4_rules(ip, agent_scope, enabled, updated_at)
                    SELECT ip, '', enabled, updated_at FROM blocked_ipv4
                    """
                )

            if self.conn.execute("SELECT COUNT(*) FROM blocked_bind_port_rules").fetchone()[0] == 0:
                self.conn.execute(
                    """
                    INSERT OR IGNORE INTO blocked_bind_port_rules(port, agent_scope, enabled, updated_at)
                    SELECT port, '', enabled, updated_at FROM blocked_bind_ports
                    """
                )

    def register_agent(self, payload: dict[str, Any]) -> str:
        hostname = as_str(payload.get("hostname"), "unknown")
        ip = as_str(payload.get("ip"), "unknown")
        kernel = as_str(payload.get("kernel"))
        version = as_str(payload.get("version"))
        agent_id = as_str(payload.get("agent_id")).strip() or str(uuid.uuid4())
        ts = now_iso()

        with self.lock, self.conn:
            row = self.conn.execute(
                "SELECT id FROM agents WHERE hostname = ? AND ip = ?",
                (hostname, ip),
            ).fetchone()

            if row:
                agent_id = str(row["id"])
                self.conn.execute(
                    """
                    UPDATE agents
                    SET kernel = ?, version = ?, last_seen = ?, status = 'online'
                    WHERE id = ?
                    """,
                    (kernel, version, ts, agent_id),
                )
            else:
                self.conn.execute(
                    """
                    INSERT INTO agents(id, hostname, ip, kernel, version, first_seen, last_seen, status)
                    VALUES(?, ?, ?, ?, ?, ?, ?, 'online')
                    """,
                    (agent_id, hostname, ip, kernel, version, ts, ts),
                )
        return agent_id

    def heartbeat(self, agent_id: str) -> None:
        with self.lock, self.conn:
            self.conn.execute(
                "UPDATE agents SET last_seen = ?, status = 'online' WHERE id = ?",
                (now_iso(), agent_id),
            )

    def list_agents(self) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                """
                SELECT id, hostname, ip, kernel, version, first_seen, last_seen, status
                FROM agents
                ORDER BY last_seen DESC
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def _threshold_state(self, detector: Detector, event: dict[str, Any]) -> tuple[bool, int, str]:
        if detector.threshold_count <= 1 or detector.threshold_window_secs <= 0:
            return True, 1, ""

        current_dt = parse_event_dt(event.get("ts"))
        cutoff = current_dt - timedelta(seconds=detector.threshold_window_secs)
        correlation_key = detector.correlation_key_for(event)
        window = self.correlation_windows[(detector.id, correlation_key)]

        while window and window[0] < cutoff:
            window.popleft()
        window.append(current_dt)

        match_count = len(window)
        return match_count == detector.threshold_count, match_count, correlation_key

    def insert_events(self, events: list[dict[str, Any]]) -> int:
        if not events:
            return 0

        loaded_detectors = self.detectors.list()
        written = 0
        with self.lock, self.conn:
            for evt in events:
                agent_id = as_str(evt.get("agent_id")).strip()
                if not agent_id:
                    continue

                normalized = {
                    "agent_id": agent_id,
                    "ts": stable_event_ts(evt.get("ts")),
                    "event_type": as_str(evt.get("event_type"), "unknown"),
                    "action": as_str(evt.get("action"), "observe"),
                    "severity": as_str(evt.get("severity"), "info"),
                    "pid": as_int(evt.get("pid")),
                    "uid": as_int(evt.get("uid")),
                    "comm": as_str(evt.get("comm")),
                    "dst_ip": as_str(evt.get("dst_ip")),
                    "dst_port": as_int(evt.get("dst_port")),
                    "subject": as_str(evt.get("subject")),
                    "arg0": as_int(evt.get("arg0")),
                    "arg1": as_int(evt.get("arg1")),
                    "ppid": as_int(evt.get("ppid")),
                    "ancestry": as_str(evt.get("ancestry")),
                    "process_path": as_str(evt.get("process_path")),
                    "pid_ns": as_str(evt.get("pid_ns")),
                    "mount_ns": as_str(evt.get("mount_ns")),
                    "net_ns": as_str(evt.get("net_ns")),
                }

                cursor = self.conn.execute(
                    """
                    INSERT INTO events(agent_id, ts, event_type, action, severity, pid, uid, comm, dst_ip, dst_port, subject, arg0, arg1, ppid, ancestry, process_path, pid_ns, mount_ns, net_ns, raw_json)
                    VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        normalized["agent_id"],
                        normalized["ts"],
                        normalized["event_type"],
                        normalized["action"],
                        normalized["severity"],
                        normalized["pid"],
                        normalized["uid"],
                        normalized["comm"],
                        normalized["dst_ip"],
                        normalized["dst_port"],
                        normalized["subject"],
                        normalized["arg0"],
                        normalized["arg1"],
                        normalized["ppid"],
                        normalized["ancestry"],
                        normalized["process_path"],
                        normalized["pid_ns"],
                        normalized["mount_ns"],
                        normalized["net_ns"],
                        json.dumps(evt, ensure_ascii=True),
                    ),
                )
                event_id = int(cursor.lastrowid)
                self.conn.execute(
                    "UPDATE agents SET last_seen = ?, status = 'online' WHERE id = ?",
                    (now_iso(), agent_id),
                )

                for detector in loaded_detectors:
                    if not detector.matches(normalized):
                        continue
                    should_emit, match_count, correlation_key = self._threshold_state(detector, normalized)
                    if not should_emit:
                        continue
                    detection = {
                        "detector_id": detector.id,
                        "detector_name": detector.name,
                        "severity": detector.severity,
                        "ts": normalized["ts"],
                        "event_id": event_id,
                        "agent_id": normalized["agent_id"],
                        "event_type": normalized["event_type"],
                        "action": normalized["action"],
                        "subject": normalized["subject"],
                        "match_count": match_count,
                        "correlation_key": correlation_key,
                        "summary": detector.summary_for(
                            {
                                **normalized,
                                "match_count": match_count,
                                "correlation_key": correlation_key,
                            }
                        ),
                    }
                    self.conn.execute(
                        """
                        INSERT INTO detections(detector_id, detector_name, severity, ts, event_id, agent_id, event_type, action, subject, match_count, correlation_key, summary, raw_json)
                        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            detection["detector_id"],
                            detection["detector_name"],
                            detection["severity"],
                            detection["ts"],
                            detection["event_id"],
                            detection["agent_id"],
                            detection["event_type"],
                            detection["action"],
                            detection["subject"],
                            detection["match_count"],
                            detection["correlation_key"],
                            detection["summary"],
                            json.dumps({**normalized, **detection}, ensure_ascii=True),
                        ),
                    )

                written += 1
        return written

    def list_events(self, limit: int = 200) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 2000))
        with self.lock:
            rows = self.conn.execute(
                """
                SELECT id, agent_id, ts, event_type, action, severity, pid, uid, comm, dst_ip, dst_port, subject, arg0, arg1, ppid, ancestry, process_path, pid_ns, mount_ns, net_ns
                FROM events
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_detections(self, limit: int = 200) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 2000))
        with self.lock:
            rows = self.conn.execute(
                """
                SELECT id, detector_id, detector_name, severity, ts, event_id, agent_id, event_type, action, subject, match_count, correlation_key, summary
                FROM detections
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_detectors(self) -> list[dict[str, Any]]:
        detectors = self.detectors.list()
        with self.lock:
            counts = {
                str(row["detector_id"]): as_int(row["count"])
                for row in self.conn.execute(
                    "SELECT detector_id, COUNT(*) AS count FROM detections GROUP BY detector_id"
                ).fetchall()
            }
        return [
            {
                "id": detector.id,
                "name": detector.name,
                "description": detector.description,
                "severity": detector.severity,
                "tags": detector.tags,
                "source_file": detector.source_file,
                "threshold_count": detector.threshold_count,
                "threshold_window_secs": detector.threshold_window_secs,
                "group_by": detector.group_by,
                "hit_count": counts.get(detector.id, 0),
            }
            for detector in detectors
        ]

    def summary(self) -> dict[str, Any]:
        loaded_detectors = self.detectors.list()
        with self.lock:
            total_events = as_int(self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])
            total_agents = as_int(self.conn.execute("SELECT COUNT(*) FROM agents").fetchone()[0])
            blocked_events = as_int(
                self.conn.execute(
                    "SELECT COUNT(*) FROM events WHERE action = 'block'"
                ).fetchone()[0]
            )
            total_detections = as_int(
                self.conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
            )
            by_severity = {
                str(row["severity"]): as_int(row["count"])
                for row in self.conn.execute(
                    "SELECT severity, COUNT(*) AS count FROM events GROUP BY severity"
                ).fetchall()
            }
            policy_ipv4_count = as_int(
                self.conn.execute(
                    "SELECT COUNT(*) FROM blocked_ipv4_rules WHERE enabled = 1"
                ).fetchone()[0]
            )
            bind_port_count = as_int(
                self.conn.execute(
                    "SELECT COUNT(*) FROM blocked_bind_port_rules WHERE enabled = 1"
                ).fetchone()[0]
            )
            exec_path_count = as_int(
                self.conn.execute(
                    "SELECT COUNT(*) FROM blocked_exec_path_rules WHERE enabled = 1"
                ).fetchone()[0]
            )
            protected_write_count = as_int(
                self.conn.execute(
                    "SELECT COUNT(*) FROM protected_write_target_rules WHERE enabled = 1"
                ).fetchone()[0]
            )
            ptrace_deny_count = as_int(
                self.conn.execute(
                    "SELECT COUNT(*) FROM ptrace_deny_rules WHERE enabled = 1"
                ).fetchone()[0]
            )
        return {
            "total_events": total_events,
            "total_agents": total_agents,
            "blocked_events": blocked_events,
            "total_detections": total_detections,
            "loaded_detectors": len(loaded_detectors),
            "severity": by_severity,
            "blocked_ipv4_count": policy_ipv4_count,
            "blocked_bind_port_count": bind_port_count,
            "blocked_exec_path_count": exec_path_count,
            "protected_write_target_count": protected_write_count,
            "ptrace_deny_count": ptrace_deny_count,
        }

    def list_blocked_ipv4(self, enabled_only: bool = True, agent_scope: str = "") -> list[str]:
        scope = as_str(agent_scope).strip()
        query = "SELECT DISTINCT ip FROM blocked_ipv4_rules"
        clauses: list[str] = []
        params: list[Any] = []
        if enabled_only:
            clauses.append("enabled = 1")
        if scope:
            clauses.append("(agent_scope = '' OR agent_scope = ?)")
            params.append(scope)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY ip ASC"
        with self.lock:
            rows = self.conn.execute(query, params).fetchall()
        return [str(row["ip"]) for row in rows]

    def list_blocked_ipv4_entries(self) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                """
                SELECT ip, agent_scope, enabled, updated_at
                FROM blocked_ipv4_rules
                ORDER BY updated_at DESC, ip ASC
                """
            ).fetchall()
        return [
            {
                "ip": str(row["ip"]),
                "agent_id": as_str(row["agent_scope"]),
                "enabled": bool(row["enabled"]),
                "updated_at": str(row["updated_at"]),
            }
            for row in rows
        ]

    def set_blocked_ipv4(self, ip: str, enabled: bool, agent_scope: str = "") -> None:
        scope = as_str(agent_scope).strip()
        with self.lock, self.conn:
            self.conn.execute(
                """
                INSERT INTO blocked_ipv4_rules(ip, agent_scope, enabled, updated_at)
                VALUES(?, ?, ?, ?)
                ON CONFLICT(ip, agent_scope) DO UPDATE SET enabled = excluded.enabled, updated_at = excluded.updated_at
                """,
                (ip, scope, int(enabled), now_iso()),
            )

    def delete_blocked_ipv4(self, ip: str, agent_scope: str = "") -> None:
        scope = as_str(agent_scope).strip()
        with self.lock, self.conn:
            self.conn.execute(
                "DELETE FROM blocked_ipv4_rules WHERE ip = ? AND agent_scope = ?",
                (ip, scope),
            )

    def list_blocked_bind_ports(self, enabled_only: bool = True, agent_scope: str = "") -> list[int]:
        scope = as_str(agent_scope).strip()
        query = "SELECT DISTINCT port FROM blocked_bind_port_rules"
        clauses: list[str] = []
        params: list[Any] = []
        if enabled_only:
            clauses.append("enabled = 1")
        if scope:
            clauses.append("(agent_scope = '' OR agent_scope = ?)")
            params.append(scope)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY port ASC"
        with self.lock:
            rows = self.conn.execute(query, params).fetchall()
        return [as_int(row["port"]) for row in rows]

    def list_blocked_bind_port_entries(self) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                """
                SELECT port, agent_scope, enabled, updated_at
                FROM blocked_bind_port_rules
                ORDER BY updated_at DESC, port ASC
                """
            ).fetchall()
        return [
            {
                "port": as_int(row["port"]),
                "agent_id": as_str(row["agent_scope"]),
                "enabled": bool(row["enabled"]),
                "updated_at": str(row["updated_at"]),
            }
            for row in rows
        ]

    def set_blocked_bind_port(self, port: int, enabled: bool, agent_scope: str = "") -> None:
        scope = as_str(agent_scope).strip()
        with self.lock, self.conn:
            self.conn.execute(
                """
                INSERT INTO blocked_bind_port_rules(port, agent_scope, enabled, updated_at)
                VALUES(?, ?, ?, ?)
                ON CONFLICT(port, agent_scope) DO UPDATE SET enabled = excluded.enabled, updated_at = excluded.updated_at
                """,
                (port, scope, int(enabled), now_iso()),
            )

    def delete_blocked_bind_port(self, port: int, agent_scope: str = "") -> None:
        scope = as_str(agent_scope).strip()
        with self.lock, self.conn:
            self.conn.execute(
                "DELETE FROM blocked_bind_port_rules WHERE port = ? AND agent_scope = ?",
                (port, scope),
            )

    def list_blocked_exec_paths(self, enabled_only: bool = True, agent_scope: str = "") -> list[str]:
        scope = as_str(agent_scope).strip()
        query = "SELECT DISTINCT path FROM blocked_exec_path_rules"
        clauses: list[str] = []
        params: list[Any] = []
        if enabled_only:
            clauses.append("enabled = 1")
        if scope:
            clauses.append("(agent_scope = '' OR agent_scope = ?)")
            params.append(scope)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY path ASC"
        with self.lock:
            rows = self.conn.execute(query, params).fetchall()
        return [str(row["path"]) for row in rows]

    def list_blocked_exec_path_entries(self) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                """
                SELECT path, agent_scope, enabled, updated_at
                FROM blocked_exec_path_rules
                ORDER BY updated_at DESC, path ASC
                """
            ).fetchall()
        return [
            {
                "path": str(row["path"]),
                "agent_id": as_str(row["agent_scope"]),
                "enabled": bool(row["enabled"]),
                "updated_at": str(row["updated_at"]),
            }
            for row in rows
        ]

    def set_blocked_exec_path(self, path: str, enabled: bool, agent_scope: str = "") -> None:
        scope = as_str(agent_scope).strip()
        with self.lock, self.conn:
            self.conn.execute(
                """
                INSERT INTO blocked_exec_path_rules(path, agent_scope, enabled, updated_at)
                VALUES(?, ?, ?, ?)
                ON CONFLICT(path, agent_scope) DO UPDATE SET enabled = excluded.enabled, updated_at = excluded.updated_at
                """,
                (path, scope, int(enabled), now_iso()),
            )

    def delete_blocked_exec_path(self, path: str, agent_scope: str = "") -> None:
        scope = as_str(agent_scope).strip()
        with self.lock, self.conn:
            self.conn.execute(
                "DELETE FROM blocked_exec_path_rules WHERE path = ? AND agent_scope = ?",
                (path, scope),
            )

    def list_protected_write_targets(self, enabled_only: bool = True, agent_scope: str = "") -> list[str]:
        scope = as_str(agent_scope).strip()
        query = "SELECT DISTINCT target FROM protected_write_target_rules"
        clauses: list[str] = []
        params: list[Any] = []
        if enabled_only:
            clauses.append("enabled = 1")
        if scope:
            clauses.append("(agent_scope = '' OR agent_scope = ?)")
            params.append(scope)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY target ASC"
        with self.lock:
            rows = self.conn.execute(query, params).fetchall()
        return [str(row["target"]) for row in rows]

    def list_protected_write_target_entries(self) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                """
                SELECT target, agent_scope, enabled, updated_at
                FROM protected_write_target_rules
                ORDER BY updated_at DESC, target ASC
                """
            ).fetchall()
        return [
            {
                "target": str(row["target"]),
                "agent_id": as_str(row["agent_scope"]),
                "enabled": bool(row["enabled"]),
                "updated_at": str(row["updated_at"]),
            }
            for row in rows
        ]

    def set_protected_write_target(self, target: str, enabled: bool, agent_scope: str = "") -> None:
        scope = as_str(agent_scope).strip()
        with self.lock, self.conn:
            self.conn.execute(
                """
                INSERT INTO protected_write_target_rules(target, agent_scope, enabled, updated_at)
                VALUES(?, ?, ?, ?)
                ON CONFLICT(target, agent_scope) DO UPDATE SET enabled = excluded.enabled, updated_at = excluded.updated_at
                """,
                (target, scope, int(enabled), now_iso()),
            )

    def delete_protected_write_target(self, target: str, agent_scope: str = "") -> None:
        scope = as_str(agent_scope).strip()
        with self.lock, self.conn:
            self.conn.execute(
                "DELETE FROM protected_write_target_rules WHERE target = ? AND agent_scope = ?",
                (target, scope),
            )

    def ptrace_denied(self, agent_scope: str = "") -> bool:
        scope = as_str(agent_scope).strip()
        query = "SELECT COUNT(*) FROM ptrace_deny_rules WHERE enabled = 1"
        params: list[Any] = []
        if scope:
            query += " AND (agent_scope = '' OR agent_scope = ?)"
            params.append(scope)
        with self.lock:
            count = as_int(self.conn.execute(query, params).fetchone()[0])
        return count > 0

    def list_ptrace_deny_entries(self) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                """
                SELECT agent_scope, enabled, updated_at
                FROM ptrace_deny_rules
                ORDER BY updated_at DESC, agent_scope ASC
                """
            ).fetchall()
        return [
            {
                "agent_id": as_str(row["agent_scope"]),
                "enabled": bool(row["enabled"]),
                "updated_at": str(row["updated_at"]),
            }
            for row in rows
        ]

    def set_ptrace_deny(self, enabled: bool, agent_scope: str = "") -> None:
        scope = as_str(agent_scope).strip()
        with self.lock, self.conn:
            self.conn.execute(
                """
                INSERT INTO ptrace_deny_rules(agent_scope, enabled, updated_at)
                VALUES(?, ?, ?)
                ON CONFLICT(agent_scope) DO UPDATE SET enabled = excluded.enabled, updated_at = excluded.updated_at
                """,
                (scope, int(enabled), now_iso()),
            )

    def delete_ptrace_deny(self, agent_scope: str = "") -> None:
        scope = as_str(agent_scope).strip()
        with self.lock, self.conn:
            self.conn.execute(
                "DELETE FROM ptrace_deny_rules WHERE agent_scope = ?",
                (scope,),
            )


class AppHandler(BaseHTTPRequestHandler):
    server_version = "kshield-manager/0.2"

    @property
    def app(self) -> "AppServer":
        return self.server  # type: ignore[return-value]

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[{now_iso()}] {self.address_string()} {fmt % args}")

    def _read_json(self) -> dict[str, Any]:
        length = as_int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        body = self.rfile.read(length)
        if not body:
            return {}
        try:
            data = json.loads(body.decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except json.JSONDecodeError:
            return {}

    def _json(self, code: int, payload: Any) -> None:
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_file(self, path: Path, content_type: str) -> None:
        if not path.exists() or not path.is_file():
            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        content = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _check_auth(self, path: str) -> bool:
        if path == "/healthz":
            return True
        if path == "/login":
            return True
        if path == "/auth.js":
            return True
        if path == "/api/v1/agents/register":  # ADD THIS LINE
            return True

        auth = self.headers.get("Authorization")
        if auth and auth.startswith("Basic "):
            try:
                import base64
                decoded = base64.b64decode(auth[6:]).decode('utf-8')
                username, password = decoded.split(':', 1)
                if username == "admin" and password == "secret":
                    return True
            except Exception:
                pass

        if path.startswith("/api/"):
            self.send_response(HTTPStatus.UNAUTHORIZED)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "unauthorized"}')
            return False

        self.send_response(HTTPStatus.FOUND)
        self.send_header("Location", "/login")
        self.end_headers()
        return False

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        if not self._check_auth(path):
            return
        query = parse_qs(parsed.query)

        if path == "/healthz":
            self._json(HTTPStatus.OK, {"status": "ok", "ts": now_iso()})
            return
        if path == "/login":
            self._serve_file(self.app.config.static_dir / "login.html", "text/html; charset=utf-8")
            return
        if path == "/":
            self._serve_file(self.app.config.static_dir / "index.html", "text/html; charset=utf-8")
            return
        if path == "/style.css":
            self._serve_file(self.app.config.static_dir / "style.css", "text/css; charset=utf-8")
            return
        if path == "/app.js":
            self._serve_file(self.app.config.static_dir / "app.js", "application/javascript; charset=utf-8")
            return
        if path == "/auth.js":
            self._serve_file(self.app.config.static_dir / "auth.js", "application/javascript; charset=utf-8")
            return

        if path == "/api/v1/agents":
            self._json(HTTPStatus.OK, {"items": self.app.storage.list_agents()})
            return
        if path == "/api/v1/events":
            limit = as_int(query.get("limit", ["200"])[0], 200)
            self._json(HTTPStatus.OK, {"items": self.app.storage.list_events(limit=limit)})
            return
        if path == "/api/v1/detections":
            limit = as_int(query.get("limit", ["200"])[0], 200)
            self._json(HTTPStatus.OK, {"items": self.app.storage.list_detections(limit=limit)})
            return
        if path == "/api/v1/detectors":
            self._json(HTTPStatus.OK, {"items": self.app.storage.list_detectors()})
            return
        if path == "/api/v1/metrics/summary":
            self._json(HTTPStatus.OK, self.app.storage.summary())
            return
        if path == "/api/v1/policy":
            self._json(
                HTTPStatus.OK,
                {
                    "blocked_ipv4": self.app.storage.list_blocked_ipv4(enabled_only=True),
                    "blocked_ipv4_items": self.app.storage.list_blocked_ipv4_entries(),
                    "blocked_bind_ports": self.app.storage.list_blocked_bind_ports(enabled_only=True),
                    "blocked_bind_port_items": self.app.storage.list_blocked_bind_port_entries(),
                    "blocked_exec_paths": self.app.storage.list_blocked_exec_paths(enabled_only=True),
                    "blocked_exec_path_items": self.app.storage.list_blocked_exec_path_entries(),
                    "protected_write_targets": self.app.storage.list_protected_write_targets(enabled_only=True),
                    "protected_write_target_items": self.app.storage.list_protected_write_target_entries(),
                    "deny_ptrace": self.app.storage.ptrace_denied(),
                    "ptrace_deny_items": self.app.storage.list_ptrace_deny_entries(),
                },
            )
            return
        if path.startswith("/api/v1/policy/"):
            agent_id = path.rsplit("/", 1)[-1]
            self.app.storage.heartbeat(agent_id)
            self._json(
                HTTPStatus.OK,
                {
                    "blocked_ipv4": self.app.storage.list_blocked_ipv4(enabled_only=True, agent_scope=agent_id),
                    "blocked_bind_ports": self.app.storage.list_blocked_bind_ports(enabled_only=True, agent_scope=agent_id),
                    "blocked_exec_paths": self.app.storage.list_blocked_exec_paths(enabled_only=True, agent_scope=agent_id),
                    "protected_write_targets": self.app.storage.list_protected_write_targets(enabled_only=True, agent_scope=agent_id),
                    "deny_ptrace": self.app.storage.ptrace_denied(agent_scope=agent_id),
                },
            )
            return

        self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if not self._check_auth(path):
            return
        payload = self._read_json()

        if path == "/api/v1/agents/register":
            agent_id = self.app.storage.register_agent(payload)
            self._json(HTTPStatus.OK, {"agent_id": agent_id})
            return

        if path == "/api/v1/events":
            events: list[dict[str, Any]]
            raw_payload: Any = payload
            if isinstance(raw_payload, dict) and isinstance(raw_payload.get("events"), list):
                events = [item for item in raw_payload["events"] if isinstance(item, dict)]
            elif isinstance(raw_payload, dict):
                events = [raw_payload]
            else:
                events = []
            written = self.app.storage.insert_events(events)
            self._json(HTTPStatus.OK, {"written": written})
            return

        if path == "/api/v1/policy/blocked-ipv4":
            ip = as_str(payload.get("ip")).strip()
            enabled = bool(payload.get("enabled", True))
            agent_scope = as_str(payload.get("agent_id")).strip()
            if not ip:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "ip_required"})
                return
            self.app.storage.set_blocked_ipv4(ip, enabled, agent_scope)
            self._json(
                HTTPStatus.OK,
                {
                    "blocked_ipv4": self.app.storage.list_blocked_ipv4(enabled_only=True),
                    "blocked_ipv4_items": self.app.storage.list_blocked_ipv4_entries(),
                },
            )
            return

        if path == "/api/v1/policy/blocked-bind-port":
            port = as_int(payload.get("port"))
            enabled = bool(payload.get("enabled", True))
            agent_scope = as_str(payload.get("agent_id")).strip()
            if port <= 0 or port > 65535:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "valid_port_required"})
                return
            self.app.storage.set_blocked_bind_port(port, enabled, agent_scope)
            self._json(
                HTTPStatus.OK,
                {
                    "blocked_bind_ports": self.app.storage.list_blocked_bind_ports(enabled_only=True),
                    "blocked_bind_port_items": self.app.storage.list_blocked_bind_port_entries(),
                },
            )
            return

        if path == "/api/v1/policy/blocked-exec-path":
            exec_path = as_str(payload.get("path")).strip()
            enabled = bool(payload.get("enabled", True))
            agent_scope = as_str(payload.get("agent_id")).strip()
            if not exec_path:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "path_required"})
                return
            self.app.storage.set_blocked_exec_path(exec_path, enabled, agent_scope)
            self._json(
                HTTPStatus.OK,
                {
                    "blocked_exec_paths": self.app.storage.list_blocked_exec_paths(enabled_only=True),
                    "blocked_exec_path_items": self.app.storage.list_blocked_exec_path_entries(),
                },
            )
            return

        if path == "/api/v1/policy/protected-write-target":
            target = as_str(payload.get("target")).strip()
            enabled = bool(payload.get("enabled", True))
            agent_scope = as_str(payload.get("agent_id")).strip()
            if not target:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "target_required"})
                return
            self.app.storage.set_protected_write_target(target, enabled, agent_scope)
            self._json(
                HTTPStatus.OK,
                {
                    "protected_write_targets": self.app.storage.list_protected_write_targets(enabled_only=True),
                    "protected_write_target_items": self.app.storage.list_protected_write_target_entries(),
                },
            )
            return

        if path == "/api/v1/policy/deny-ptrace":
            enabled = bool(payload.get("enabled", True))
            agent_scope = as_str(payload.get("agent_id")).strip()
            self.app.storage.set_ptrace_deny(enabled, agent_scope)
            self._json(
                HTTPStatus.OK,
                {
                    "deny_ptrace": self.app.storage.ptrace_denied(),
                    "ptrace_deny_items": self.app.storage.list_ptrace_deny_entries(),
                },
            )
            return

        self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_DELETE(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if not self._check_auth(path):
            return
        payload = self._read_json()

        if path == "/api/v1/policy/blocked-ipv4":
            ip = as_str(payload.get("ip")).strip()
            agent_scope = as_str(payload.get("agent_id")).strip()
            if not ip:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "ip_required"})
                return
            self.app.storage.delete_blocked_ipv4(ip, agent_scope)
            self._json(
                HTTPStatus.OK,
                {
                    "blocked_ipv4": self.app.storage.list_blocked_ipv4(enabled_only=True),
                    "blocked_ipv4_items": self.app.storage.list_blocked_ipv4_entries(),
                },
            )
            return

        if path == "/api/v1/policy/blocked-bind-port":
            port = as_int(payload.get("port"))
            agent_scope = as_str(payload.get("agent_id")).strip()
            if port <= 0 or port > 65535:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "valid_port_required"})
                return
            self.app.storage.delete_blocked_bind_port(port, agent_scope)
            self._json(
                HTTPStatus.OK,
                {
                    "blocked_bind_ports": self.app.storage.list_blocked_bind_ports(enabled_only=True),
                    "blocked_bind_port_items": self.app.storage.list_blocked_bind_port_entries(),
                },
            )
            return

        if path == "/api/v1/policy/blocked-exec-path":
            exec_path = as_str(payload.get("path")).strip()
            agent_scope = as_str(payload.get("agent_id")).strip()
            if not exec_path:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "path_required"})
                return
            self.app.storage.delete_blocked_exec_path(exec_path, agent_scope)
            self._json(
                HTTPStatus.OK,
                {
                    "blocked_exec_paths": self.app.storage.list_blocked_exec_paths(enabled_only=True),
                    "blocked_exec_path_items": self.app.storage.list_blocked_exec_path_entries(),
                },
            )
            return

        if path == "/api/v1/policy/protected-write-target":
            target = as_str(payload.get("target")).strip()
            agent_scope = as_str(payload.get("agent_id")).strip()
            if not target:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "target_required"})
                return
            self.app.storage.delete_protected_write_target(target, agent_scope)
            self._json(
                HTTPStatus.OK,
                {
                    "protected_write_targets": self.app.storage.list_protected_write_targets(enabled_only=True),
                    "protected_write_target_items": self.app.storage.list_protected_write_target_entries(),
                },
            )
            return

        if path == "/api/v1/policy/deny-ptrace":
            agent_scope = as_str(payload.get("agent_id")).strip()
            self.app.storage.delete_ptrace_deny(agent_scope)
            self._json(
                HTTPStatus.OK,
                {
                    "deny_ptrace": self.app.storage.ptrace_denied(),
                    "ptrace_deny_items": self.app.storage.list_ptrace_deny_entries(),
                },
            )
            return

        self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})


class AppServer(ThreadingHTTPServer):
    def __init__(self, config: Config, storage: Storage) -> None:
        super().__init__((config.host, config.port), AppHandler)
        self.config = config
        self.storage = storage


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Kernel Threat Detection Manager")
    parser.add_argument("--host", default=os.getenv("MANAGER_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=as_int(os.getenv("MANAGER_PORT", "8080"), 8080))
    parser.add_argument(
        "--db",
        default=os.getenv("MANAGER_DB", str(Path(__file__).resolve().parent / "data" / "siem.db")),
    )
    parser.add_argument(
        "--static-dir",
        default=os.getenv("MANAGER_STATIC", str(Path(__file__).resolve().parent / "static")),
    )
    parser.add_argument(
        "--detector-dir",
        default=os.getenv("MANAGER_DETECTORS", str(Path(__file__).resolve().parent / "detectors")),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = Config(
        host=args.host,
        port=args.port,
        db_path=Path(args.db).resolve(),
        static_dir=Path(args.static_dir).resolve(),
        detector_dir=Path(args.detector_dir).resolve(),
    )
    detectors = DetectorCatalog(config.detector_dir)
    storage = Storage(config.db_path, detectors)
    srv = AppServer(config, storage)
    print(f"manager listening on http://{config.host}:{config.port}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
