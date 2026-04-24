#!/usr/bin/env python3
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from manager.app import DetectorCatalog, Storage


ROOT = Path(__file__).resolve().parents[1]


class ReplayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="kshield-test-")
        self.root = Path(self.temp_dir.name)
        self.detector_dir = self.root / "detectors"
        shutil.copytree(ROOT / "manager" / "detectors", self.detector_dir)
        self.storage = Storage(self.root / "test.db", DetectorCatalog(self.detector_dir))

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_replay_stream_generates_threshold_detection(self) -> None:
        fixture_path = ROOT / "tests" / "fixtures" / "replay-events.json"
        events = json.loads(fixture_path.read_text(encoding="utf-8"))

        written = self.storage.insert_events(events)
        detections = self.storage.list_detections(limit=50)
        detector_ids = [item["detector_id"] for item in detections]

        self.assertEqual(written, 4)
        self.assertIn("interactive-shell-exec", detector_ids)
        self.assertIn("repeated-bind-denials", detector_ids)
        self.assertEqual(detector_ids.count("blocked-bind-port"), 3)

        repeated = next(item for item in detections if item["detector_id"] == "repeated-bind-denials")
        self.assertEqual(repeated["match_count"], 3)
        self.assertEqual(repeated["correlation_key"], "agent-a|python3|4444")

    def test_scoped_policy_merges_global_and_agent_rules(self) -> None:
        self.storage.set_blocked_ipv4("1.1.1.1", True)
        self.storage.set_blocked_ipv4("9.9.9.9", True, "agent-a")
        self.storage.set_blocked_bind_port(4444, True)
        self.storage.set_blocked_bind_port(5555, True, "agent-a")
        self.storage.set_blocked_exec_path("/usr/bin/nc", True)
        self.storage.set_blocked_exec_path("/usr/bin/python3", True, "agent-a")
        self.storage.set_protected_write_target("shadow", True)
        self.storage.set_protected_write_target("sudoers", True, "agent-a")
        self.storage.set_ptrace_deny(True)
        self.storage.set_ptrace_deny(True, "agent-a")

        self.assertEqual(self.storage.list_blocked_ipv4(enabled_only=True, agent_scope="agent-a"), ["1.1.1.1", "9.9.9.9"])
        self.assertEqual(self.storage.list_blocked_bind_ports(enabled_only=True, agent_scope="agent-a"), [4444, 5555])
        self.assertEqual(self.storage.list_blocked_exec_paths(enabled_only=True, agent_scope="agent-a"), ["/usr/bin/nc", "/usr/bin/python3"])
        self.assertEqual(self.storage.list_protected_write_targets(enabled_only=True, agent_scope="agent-a"), ["shadow", "sudoers"])
        self.assertTrue(self.storage.ptrace_denied(agent_scope="agent-a"))
        self.assertEqual(self.storage.list_blocked_ipv4(enabled_only=True, agent_scope="agent-b"), ["1.1.1.1"])
        self.assertEqual(self.storage.list_blocked_bind_ports(enabled_only=True, agent_scope="agent-b"), [4444])
        self.assertEqual(self.storage.list_blocked_exec_paths(enabled_only=True, agent_scope="agent-b"), ["/usr/bin/nc"])
        self.assertEqual(self.storage.list_protected_write_targets(enabled_only=True, agent_scope="agent-b"), ["shadow"])
        self.assertTrue(self.storage.ptrace_denied(agent_scope="agent-b"))

    def test_file_path_detectors_fire_from_subject_paths(self) -> None:
        events = [
            {
                "agent_id": "agent-a",
                "ts": "2026-04-24T12:00:00Z",
                "event_type": "file_open",
                "action": "observe",
                "severity": "warning",
                "pid": 111,
                "uid": 1000,
                "comm": "cat",
                "subject": "/etc/shadow",
            },
            {
                "agent_id": "agent-a",
                "ts": "2026-04-24T12:00:01Z",
                "event_type": "file_open",
                "action": "observe",
                "severity": "warning",
                "pid": 112,
                "uid": 1000,
                "comm": "strings",
                "subject": "/proc/kcore",
            },
        ]

        self.storage.insert_events(events)
        detector_ids = [item["detector_id"] for item in self.storage.list_detections(limit=20)]

        self.assertIn("sensitive-shadow-access", detector_ids)
        self.assertIn("proc-kcore-read", detector_ids)


if __name__ == "__main__":
    unittest.main()
