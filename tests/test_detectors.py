#!/usr/bin/env python3
"""Comprehensive detector tests covering all 23 detectors."""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from manager.app import DetectorCatalog, Storage


ROOT = Path(__file__).resolve().parents[1]


class DetectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="kshield-test-")
        self.root = Path(self.temp_dir.name)
        self.detector_dir = self.root / "detectors"
        shutil.copytree(ROOT / "manager" / "detectors", self.detector_dir)
        self.storage = Storage(self.root / "test.db", DetectorCatalog(self.detector_dir))

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def assert_detector_fires(self, events: list, detector_id: str, count: int = 1) -> None:
        """Helper: insert events and assert detector fires."""
        self.storage.insert_events(events)
        detections = self.storage.list_detections(limit=100)
        detector_ids = [item["detector_id"] for item in detections]
        self.assertIn(detector_id, detector_ids, f"Detector '{detector_id}' did not fire")
        self.assertEqual(
            detector_ids.count(detector_id),
            count,
            f"Expected {count} hits for '{detector_id}', got {detector_ids.count(detector_id)}"
        )

    # T1562 Impair Defenses
    def test_disable_modify_audit_system(self) -> None:
        """T1562.012: Audit system tampering."""
        events = [{
            "agent_id": "test-agent",
            "ts": "2026-04-24T12:00:00Z",
            "event_type": "execve",
            "action": "observe",
            "severity": "warning",
            "pid": 100,
            "uid": 0,
            "comm": "auditctl",
            "subject": "/usr/sbin/auditctl",
        }]
        self.assert_detector_fires(events, "disable-modify-audit-system")

    def test_disable_modify_firewall(self) -> None:
        """T1562.004: Firewall modification."""
        events = [{
            "agent_id": "test-agent",
            "ts": "2026-04-24T12:00:00Z",
            "event_type": "execve",
            "action": "observe",
            "severity": "warning",
            "pid": 100,
            "uid": 0,
            "comm": "iptables",
            "subject": "/usr/sbin/iptables",
        }]
        self.assert_detector_fires(events, "disable-modify-firewall")

    def test_disable_modify_tools(self) -> None:
        """T1562.001: Security tool tampering."""
        events = [{
            "agent_id": "test-agent",
            "ts": "2026-04-24T12:00:00Z",
            "event_type": "file_open",
            "action": "observe",
            "severity": "warning",
            "pid": 100,
            "uid": 0,
            "comm": "bash",
            "subject": "/usr/sbin/auditctl",
        }]
        self.assert_detector_fires(events, "disable-modify-tools")

    def test_downgrade_attack(self) -> None:
        """T1562.010: Package downgrade attempts."""
        events = [{
            "agent_id": "test-agent",
            "ts": "2026-04-24T12:00:00Z",
            "event_type": "execve",
            "action": "observe",
            "severity": "warning",
            "pid": 100,
            "uid": 1000,
            "comm": "apt-get",
            "subject": "/usr/bin/apt-get",
        }]
        self.assert_detector_fires(events, "downgrade-attack")

    def test_impair_command_history(self) -> None:
        """T1562.003: Command history tampering."""
        events = [{
            "agent_id": "test-agent",
            "ts": "2026-04-24T12:00:00Z",
            "event_type": "file_write",
            "action": "observe",
            "severity": "warning",
            "pid": 100,
            "uid": 1000,
            "comm": "bash",
            "subject": "/root/.bash_history",
        }]
        self.assert_detector_fires(events, "impair-command-history")

    def test_spoof_security_alerting(self) -> None:
        """T1562.011: Syslog spoofing."""
        events = [{
            "agent_id": "test-agent",
            "ts": "2026-04-24T12:00:00Z",
            "event_type": "file_open",
            "action": "observe",
            "severity": "warning",
            "pid": 100,
            "uid": 1000,
            "comm": "logger",
            "subject": "/dev/log",
        }]
        self.assert_detector_fires(events, "spoof-security-alerting")

    def test_indicator_blocking(self) -> None:
        """T1562.006: Indicator blocking / DNS/hosts manipulation."""
        events = [{
            "agent_id": "test-agent",
            "ts": "2026-04-24T12:00:00Z",
            "event_type": "file_write",
            "action": "observe",
            "severity": "warning",
            "pid": 100,
            "uid": 0,
            "comm": "bash",
            "subject": "/etc/hosts",
        }]
        self.assert_detector_fires(events, "indicator-blocking")

    # Execution & Access Control
    def test_blocked_exec_path(self) -> None:
        """Execution of blocked paths."""
        self.storage.set_blocked_exec_path("/usr/bin/nc", True)
        events = [{
            "agent_id": "test-agent",
            "ts": "2026-04-24T12:00:00Z",
            "event_type": "execve",
            "action": "block",
            "severity": "critical",
            "pid": 100,
            "uid": 1000,
            "comm": "nc",
            "subject": "/usr/bin/nc",
        }]
        self.assert_detector_fires(events, "blocked-exec-path")

    def test_interactive_shell_exec(self) -> None:
        """Interactive shell execution detection."""
        events = [{
            "agent_id": "test-agent",
            "ts": "2026-04-24T12:00:00Z",
            "event_type": "execve",
            "action": "observe",
            "severity": "warning",
            "pid": 100,
            "uid": 1000,
            "comm": "bash",
            "subject": "/bin/bash",
        }]
        self.assert_detector_fires(events, "interactive-shell-exec")

    def test_blocked_ptrace(self) -> None:
        """Ptrace activity blocked by policy."""
        events = [{
            "agent_id": "test-agent",
            "ts": "2026-04-24T12:00:00Z",
            "event_type": "ptrace",
            "action": "block",
            "severity": "critical",
            "pid": 100,
            "uid": 1000,
            "comm": "gdb",
            "arg0": "PTRACE_ATTACH",
            "arg1": 1234,
        }]
        self.assert_detector_fires(events, "blocked-ptrace")

    def test_ptrace_attach(self) -> None:
        """Ptrace attachment detection."""
        events = [{
            "agent_id": "test-agent",
            "ts": "2026-04-24T12:00:00Z",
            "event_type": "ptrace",
            "action": "observe",
            "severity": "warning",
            "pid": 100,
            "uid": 1000,
            "comm": "gdb",
            "arg0": "PTRACE_ATTACH",
            "arg1": 1234,
        }]
        self.assert_detector_fires(events, "ptrace-attach")

    # Sensitive File Access
    def test_sensitive_shadow_access(self) -> None:
        """Shadow file access detection."""
        events = [{
            "agent_id": "test-agent",
            "ts": "2026-04-24T12:00:00Z",
            "event_type": "file_open",
            "action": "observe",
            "severity": "warning",
            "pid": 100,
            "uid": 1000,
            "comm": "cat",
            "subject": "/etc/shadow",
        }]
        self.assert_detector_fires(events, "sensitive-shadow-access")

    def test_blocked_sensitive_write(self) -> None:
        """Protected file write detection."""
        self.storage.set_protected_write_target("shadow", True)
        events = [{
            "agent_id": "test-agent",
            "ts": "2026-04-24T12:00:00Z",
            "event_type": "file_write",
            "action": "block",
            "severity": "warning",
            "pid": 100,
            "uid": 0,
            "comm": "bash",
            "subject": "/etc/shadow",
        }]
        self.assert_detector_fires(events, "blocked-sensitive-write")

    def test_proc_kcore_read(self) -> None:
        """/proc/kcore kernel memory read."""
        events = [{
            "agent_id": "test-agent",
            "ts": "2026-04-24T12:00:00Z",
            "event_type": "file_open",
            "action": "observe",
            "severity": "warning",
            "pid": 100,
            "uid": 1000,
            "comm": "strings",
            "subject": "/proc/kcore",
        }]
        self.assert_detector_fires(events, "proc-kcore-read")

    # Network & Kernel
    def test_blocked_egress_connection(self) -> None:
        """Blocked outbound connection detection."""
        events = [{
            "agent_id": "test-agent",
            "ts": "2026-04-24T12:00:00Z",
            "event_type": "socket_connect",
            "action": "block",
            "severity": "warning",
            "pid": 100,
            "uid": 1000,
            "comm": "curl",
            "dst_ip": "1.1.1.1",
            "dst_port": 443,
        }]
        self.assert_detector_fires(events, "blocked-egress-connection")

    def test_blocked_bind_port(self) -> None:
        """Blocked bind port detection (threshold)."""
        self.storage.set_blocked_bind_port(4444, True)
        events = [
            {
                "agent_id": "test-agent",
                "ts": "2026-04-24T12:00:00Z",
                "event_type": "socket_bind",
                "action": "block",
                "severity": "warning",
                "pid": 100,
                "uid": 1000,
                "comm": "python3",
                "dst_port": 4444,
            },
            {
                "agent_id": "test-agent",
                "ts": "2026-04-24T12:00:01Z",
                "event_type": "socket_bind",
                "action": "block",
                "severity": "warning",
                "pid": 100,
                "uid": 1000,
                "comm": "python3",
                "dst_port": 4444,
            },
            {
                "agent_id": "test-agent",
                "ts": "2026-04-24T12:00:02Z",
                "event_type": "socket_bind",
                "action": "block",
                "severity": "warning",
                "pid": 100,
                "uid": 1000,
                "comm": "python3",
                "dst_port": 4444,
            },
        ]
        self.assert_detector_fires(events, "blocked-bind-port", count=3)

    def test_repeated_bind_denials(self) -> None:
        """Threshold-based repeated bind denial detection."""
        events = [
            {
                "agent_id": "test-agent",
                "ts": "2026-04-24T12:00:00Z",
                "event_type": "socket_bind",
                "action": "block",
                "severity": "warning",
                "pid": 100,
                "uid": 1000,
                "comm": "ssh",
                "dst_port": 22,
            },
            {
                "agent_id": "test-agent",
                "ts": "2026-04-24T12:00:01Z",
                "event_type": "socket_bind",
                "action": "block",
                "severity": "warning",
                "pid": 100,
                "uid": 1000,
                "comm": "ssh",
                "dst_port": 22,
            },
            {
                "agent_id": "test-agent",
                "ts": "2026-04-24T12:00:02Z",
                "event_type": "socket_bind",
                "action": "block",
                "severity": "warning",
                "pid": 100,
                "uid": 1000,
                "comm": "ssh",
                "dst_port": 22,
            },
        ]
        self.storage.insert_events(events)
        detections = self.storage.list_detections(limit=100)
        detector_ids = [item["detector_id"] for item in detections]
        self.assertIn("repeated-bind-denials", detector_ids)

    def test_kernel_module_load(self) -> None:
        """Kernel module loading detection."""
        events = [{
            "agent_id": "test-agent",
            "ts": "2026-04-24T12:00:00Z",
            "event_type": "module_load",
            "action": "observe",
            "severity": "warning",
            "pid": 100,
            "uid": 0,
            "comm": "insmod",
            "subject": "rootkit",
        }]
        self.assert_detector_fires(events, "kernel-module-load")

    def test_bpf_syscall_use(self) -> None:
        """BPF syscall usage detection."""
        events = [{
            "agent_id": "test-agent",
            "ts": "2026-04-24T12:00:00Z",
            "event_type": "bpf",
            "action": "observe",
            "severity": "warning",
            "pid": 100,
            "uid": 1000,
            "comm": "kshield-agent",
            "arg0": "BPF_PROG_LOAD",
        }]
        self.assert_detector_fires(events, "bpf-syscall-use")

    def test_mount_activity(self) -> None:
        """Mount operation detection."""
        events = [{
            "agent_id": "test-agent",
            "ts": "2026-04-24T12:00:00Z",
            "event_type": "mount",
            "action": "observe",
            "severity": "warning",
            "pid": 100,
            "uid": 0,
            "comm": "mount",
            "subject": "/mnt/usb",
        }]
        self.assert_detector_fires(events, "mount-activity")

    def test_setuid_root_change(self) -> None:
        """Setuid to root privilege escalation detection."""
        events = [{
            "agent_id": "test-agent",
            "ts": "2026-04-24T12:00:00Z",
            "event_type": "setuid",
            "action": "observe",
            "severity": "warning",
            "pid": 100,
            "uid": 1000,
            "comm": "sudo",
            "arg0": 0,
        }]
        self.assert_detector_fires(events, "setuid-root-change")

    def test_cve_2026_43284(self) -> None:
        """CVE-2026-43284 ESP-in-UDP detection."""
        events = [{
            "agent_id": "test-agent",
            "ts": "2026-04-24T12:00:00Z",
            "event_type": "esp_input",
            "action": "observe",
            "severity": "critical",
            "pid": 100,
            "uid": 0,
            "comm": "kernel",
        }]
        self.assert_detector_fires(events, "cve-2026-43284")

    def test_cve_2026_46333(self) -> None:
        """CVE-2026-46333 pidfd_getfd detection."""
        events = [{
            "agent_id": "test-agent",
            "ts": "2026-04-24T12:00:00Z",
            "event_type": "pidfd_getfd",
            "action": "observe",
            "severity": "critical",
            "pid": 100,
            "uid": 1000,
            "comm": "ssh-keysign",
            "arg1": 42,
        }]
        self.assert_detector_fires(events, "cve-2026-46333")


if __name__ == "__main__":
    unittest.main()
