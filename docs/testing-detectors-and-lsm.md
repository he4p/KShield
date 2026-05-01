# Testing Detectors and LSM Hooks

This guide explains how to manually test every detector and LSM hook embedded within the KShield runtime. 

To easily synthesize the attack surfaces without needing to compile malicious C payloads, KShield provides a utility named `ksbench_action.py`. This script invokes specific syscall combinations crafted to trip active detectors.

> **Note**: You must be running the manager (`http://127.0.0.1:8080`) and the `kshield-agent` locally to observe the detections taking place.

## 1. General Detectors (Passive)

These detectors track telemetry asynchronously. Generating the activity will result in a standard detection payload in the manager (`GET /api/v1/detections`).

| Detector ID | Action | Testing Command | How it works |
| --- | --- | --- | --- |
| `sensitive-shadow-access` | `open_shadow` | `python3 bench/ksbench_action.py open_shadow` | Triggers a file open read (`O_RDONLY`) directly against `/etc/shadow`. |
| `proc-kcore-read` | `open_kcore` | `python3 bench/ksbench_action.py open_kcore` | Triggers a file open read against kernel memory maps via `/proc/kcore`. |
| `ptrace-attach` | `ptrace_attach_child` | `python3 bench/ksbench_action.py ptrace_attach_child` | Forks a child task and executes `ptrace(PTRACE_ATTACH, ...)`. |
| `setuid-root-change` | `setuid0` | `python3 bench/ksbench_action.py setuid0` | Directly invokes the `setuid(0)` standard library wrapper syscall. |
| `mount-activity` | `mount_attempt` | `python3 bench/ksbench_action.py mount_attempt` | Executes `mount("tmpfs", "/tmp/ksbench_mnt", ...)` to flag file system mounts. |
| `bpf-syscall-use` | `bpf_syscall` | `python3 bench/ksbench_action.py bpf_syscall` | Attempts raw `bpf(2)` syscalls with blank arguments. |
| `kernel-module-load` | `init_module_attempt` | `python3 bench/ksbench_action.py init_module_attempt` | Calls `init_module` natively mapping to the x86_64 sys-hook. |

---

## 2. LSM Hooks (Active Prevention)

LSM policies block specific behaviors contextually. To test these, the relevant blocking profile must be applied.

### Setting Up the Policy Profile
You can force the manager to adopt the blocking test profile with `curl`:
```bash
curl -X POST -H "Content-Type: application/json" -d '{"ip": "203.0.113.1", "enabled": true}' http://127.0.0.1:8080/api/v1/policy/blocked-ipv4
curl -X POST -H "Content-Type: application/json" -d '{"port": 4444, "enabled": true}' http://127.0.0.1:8080/api/v1/policy/blocked-bind-port
curl -X POST -H "Content-Type: application/json" -d '{"path": "/tmp/ksbench_blocked_exec.sh", "enabled": true}' http://127.0.0.1:8080/api/v1/policy/blocked-exec-path
curl -X POST -H "Content-Type: application/json" -d '{"target": "shadow", "enabled": true}' http://127.0.0.1:8080/api/v1/policy/protected-write-target
curl -X POST -H "Content-Type: application/json" -d '{"enabled": true}' http://127.0.0.1:8080/api/v1/policy/deny-ptrace
```
*(Wait 10-15 seconds for the eBPF maps backing the LSM agent to synchronize).*

### Triggering the LSM Hooks

| LSM Hook / Detector ID | Action | Testing Command | How it works |
| --- | --- | --- | --- |
| `blocked-egress-connection` | `connect_blocked_ip` | `python3 bench/ksbench_action.py connect_blocked_ip` | Evaluates network Egress restrictions. Creates an `AF_INET` socket connecting to `203.0.113.1`. The operation should return an error. |
| `blocked-bind-port` | `bind_blocked_port` | `python3 bench/ksbench_action.py bind_blocked_port` | Targets port `4444` directly over `socket.bind()`. Kernel denies binding rights. |
| `blocked-exec-path` | `exec_blocked_path` | `python3 bench/ksbench_action.py exec_blocked_path` | Generates a shell script file at `/tmp/ksbench_blocked_exec.sh` and executes it. Action returns error code 127/128 due to execve halt. |
| `blocked-sensitive-write` | `write_protected_shadow` | `python3 bench/ksbench_action.py write_protected_shadow` | Targets a file with basename `shadow` (in `/tmp/shadow`) using `O_WRONLY \| O_APPEND`. Kernel intercepts and denies write. |
| `blocked-ptrace` | `ptrace_attach_child` | `python3 bench/ksbench_action.py ptrace_attach_child` | Runs the `ptrace` attack payload while the policy restricts attach capabilities. |

---

## 3. Threshold Detectors

Threshold detectors aggregate multiple alerts before firing.

| Detector ID | Action | Testing Command | How it works |
| --- | --- | --- | --- |
| `repeated-bind-denials` | `bind_blocked_port_repeat3` | `python3 bench/ksbench_action.py bind_blocked_port_repeat3` | Re-attempts binding to the blocked port (4444) three consecutive times in rapid succession, thereby bypassing the correlation window thresholds to generate an aggregate detection alert. |

### Further Validation
Once tested, ensure successful evaluation by polling the detection log:
```bash
curl -s http://127.0.0.1:8080/api/v1/detections | grep "detector_id"
```
