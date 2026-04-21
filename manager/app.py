#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Config:
    host: str
    port: int
    db_path: Path
    static_dir: Path


class Storage:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        self._init_schema()

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
                    raw_json TEXT NOT NULL DEFAULT '{}',
                    FOREIGN KEY(agent_id) REFERENCES agents(id)
                );

                CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
                CREATE INDEX IF NOT EXISTS idx_events_agent ON events(agent_id);

                CREATE TABLE IF NOT EXISTS blocked_ipv4 (
                    ip TEXT PRIMARY KEY,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    updated_at TEXT NOT NULL
                );
                """
            )

    def register_agent(self, payload: dict[str, Any]) -> str:
        hostname = str(payload.get("hostname", "unknown"))
        ip = str(payload.get("ip", "unknown"))
        kernel = str(payload.get("kernel", ""))
        version = str(payload.get("version", ""))
        agent_id = str(payload.get("agent_id", "")).strip() or str(uuid.uuid4())
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

    def insert_events(self, events: list[dict[str, Any]]) -> int:
        if not events:
            return 0
        with self.lock, self.conn:
            for evt in events:
                agent_id = str(evt.get("agent_id", ""))
                if not agent_id:
                    continue
                self.conn.execute(
                    """
                    INSERT INTO events(agent_id, ts, event_type, action, severity, pid, uid, comm, dst_ip, dst_port, raw_json)
                    VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        agent_id,
                        str(evt.get("ts", now_iso())),
                        str(evt.get("event_type", "unknown")),
                        str(evt.get("action", "observe")),
                        str(evt.get("severity", "info")),
                        int(evt.get("pid", 0)),
                        int(evt.get("uid", 0)),
                        str(evt.get("comm", "")),
                        str(evt.get("dst_ip", "")),
                        int(evt.get("dst_port", 0)),
                        json.dumps(evt, ensure_ascii=True),
                    ),
                )
                self.conn.execute(
                    "UPDATE agents SET last_seen = ?, status = 'online' WHERE id = ?",
                    (now_iso(), agent_id),
                )
        return len(events)

    def list_events(self, limit: int = 200) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 2000))
        with self.lock:
            rows = self.conn.execute(
                """
                SELECT id, agent_id, ts, event_type, action, severity, pid, uid, comm, dst_ip, dst_port
                FROM events
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def summary(self) -> dict[str, Any]:
        with self.lock:
            total_events = int(
                self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            )
            total_agents = int(
                self.conn.execute("SELECT COUNT(*) FROM agents").fetchone()[0]
            )
            blocked = int(
                self.conn.execute(
                    "SELECT COUNT(*) FROM events WHERE action = 'block'"
                ).fetchone()[0]
            )
            by_severity = {
                row["severity"]: int(row["c"])
                for row in self.conn.execute(
                    "SELECT severity, COUNT(*) AS c FROM events GROUP BY severity"
                ).fetchall()
            }
            policy_count = int(
                self.conn.execute(
                    "SELECT COUNT(*) FROM blocked_ipv4 WHERE enabled = 1"
                ).fetchone()[0]
            )
        return {
            "total_events": total_events,
            "total_agents": total_agents,
            "blocked_events": blocked,
            "severity": by_severity,
            "blocked_ipv4_count": policy_count,
        }

    def list_blocked_ipv4(self, enabled_only: bool = True) -> list[str]:
        query = "SELECT ip FROM blocked_ipv4"
        if enabled_only:
            query += " WHERE enabled = 1"
        query += " ORDER BY ip ASC"
        with self.lock:
            rows = self.conn.execute(query).fetchall()
        return [str(row["ip"]) for row in rows]

    def set_blocked_ipv4(self, ip: str, enabled: bool) -> None:
        with self.lock, self.conn:
            self.conn.execute(
                """
                INSERT INTO blocked_ipv4(ip, enabled, updated_at)
                VALUES(?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET enabled = excluded.enabled, updated_at = excluded.updated_at
                """,
                (ip, int(enabled), now_iso()),
            )


class AppHandler(BaseHTTPRequestHandler):
    server_version = "kshield-manager/0.1"

    @property
    def app(self) -> "AppServer":
        return self.server  # type: ignore[return-value]

    def log_message(self, fmt: str, *args: Any) -> None:
        # Keep logs compact and useful in terminal.
        print(f"[{now_iso()}] {self.address_string()} {fmt % args}")

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        body = self.rfile.read(length)
        if not body:
            return {}
        try:
            return json.loads(body.decode("utf-8"))
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

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/healthz":
            self._json(HTTPStatus.OK, {"status": "ok", "ts": now_iso()})
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

        if path == "/api/v1/agents":
            self._json(HTTPStatus.OK, {"items": self.app.storage.list_agents()})
            return
        if path == "/api/v1/events":
            limit = int(query.get("limit", ["200"])[0])
            self._json(HTTPStatus.OK, {"items": self.app.storage.list_events(limit=limit)})
            return
        if path == "/api/v1/metrics/summary":
            self._json(HTTPStatus.OK, self.app.storage.summary())
            return
        if path == "/api/v1/policy":
            self._json(
                HTTPStatus.OK,
                {"blocked_ipv4": self.app.storage.list_blocked_ipv4(enabled_only=True)},
            )
            return
        if path.startswith("/api/v1/policy/"):
            agent_id = path.rsplit("/", 1)[-1]
            self.app.storage.heartbeat(agent_id)
            self._json(
                HTTPStatus.OK,
                {"blocked_ipv4": self.app.storage.list_blocked_ipv4(enabled_only=True)},
            )
            return

        self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        payload = self._read_json()

        if path == "/api/v1/agents/register":
            agent_id = self.app.storage.register_agent(payload)
            self._json(HTTPStatus.OK, {"agent_id": agent_id})
            return

        if path == "/api/v1/events":
            if isinstance(payload, dict) and "events" in payload and isinstance(payload["events"], list):
                events = payload["events"]
            elif isinstance(payload, list):
                events = payload
            elif isinstance(payload, dict):
                events = [payload]
            else:
                events = []
            written = self.app.storage.insert_events(events)  # type: ignore[arg-type]
            self._json(HTTPStatus.OK, {"written": written})
            return

        if path == "/api/v1/policy/blocked-ipv4":
            ip = str(payload.get("ip", "")).strip()
            enabled = bool(payload.get("enabled", True))
            if not ip:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "ip_required"})
                return
            self.app.storage.set_blocked_ipv4(ip, enabled)
            self._json(
                HTTPStatus.OK,
                {"blocked_ipv4": self.app.storage.list_blocked_ipv4(enabled_only=True)},
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
    parser.add_argument("--port", type=int, default=int(os.getenv("MANAGER_PORT", "8080")))
    parser.add_argument(
        "--db",
        default=os.getenv("MANAGER_DB", str(Path(__file__).resolve().parent / "data" / "siem.db")),
    )
    parser.add_argument(
        "--static-dir",
        default=os.getenv(
            "MANAGER_STATIC",
            str(Path(__file__).resolve().parent / "static"),
        ),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = Config(
        host=args.host,
        port=args.port,
        db_path=Path(args.db).resolve(),
        static_dir=Path(args.static_dir).resolve(),
    )
    storage = Storage(config.db_path)
    srv = AppServer(config, storage)
    print(f"manager listening on http://{config.host}:{config.port}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
